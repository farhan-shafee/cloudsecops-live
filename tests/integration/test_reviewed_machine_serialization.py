"""Native machine SQL must serialize with human closure and audit invalidation."""

from __future__ import annotations

import gzip
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from cloudsecops_live.database import Database
from cloudsecops_live.pipeline_roles import load_pipeline_config, provision_pipeline
from cloudsecops_live.storage import ingest, verify_store
from cloudsecops_live.worker import work_once
from cloudsecops_live.workspace_config import write_private_json
from tests.helpers import archive, event
from tests.integration.support import current, one, rows
from tests.integration.test_backup import snapshot
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def machine_roles(flow):
    return {
        kind: Database(provision_pipeline(flow.db, kind)["dsn"]) for kind in ("collector", "worker")
    }


def close_arguments(flow):
    rec = flow.recommend()
    review = flow.review(rec)
    receipt = flow.verify(rec)
    store, token, nonce, version = flow.prepare("close", "reviewer", rec["version"])
    return store, (
        token,
        nonce,
        flow.cid,
        version,
        rec["recommendation_id"],
        rec["version"],
        rec["recommendation_hash"],
        review["review_id"],
        receipt["verification_id"],
        "Close the reviewed synthetic exercise",
    )


def original_copy(db):
    original = one(db, "SELECT * FROM csl.raw_objects ORDER BY raw_id LIMIT 1")
    before = bytes(original["archive_bytes"])
    changed = bytearray(before)
    # Gzip MTIME is an unsigned header value. Changing it creates a different
    # compressed original with exactly the same valid expanded content.
    changed[4] ^= 1
    after = bytes(changed)
    assert gzip.decompress(before) == gzip.decompress(after)
    assert before != after
    new_id = sha256(after).hexdigest()
    return original, (
        new_id,
        "synthetic/serialized-copy.json.gz",
        after,
        new_id,
        original["content_hash"],
        original["expanded_size"],
        original["record_count"],
    )


RAW_INSERT = (
    "INSERT INTO csl.raw_objects(raw_id,source_ref,archive_bytes,archive_hash,"
    "content_hash,expanded_size,record_count) VALUES(%s,%s,%s,%s,%s,%s,%s)"
)


def batch_insert(conn, flow, *, batch_id, checkpoint, raw_values):
    request = [(raw_values[1], raw_values[0])]
    generation = one(flow.db, "SELECT generation FROM csl.pipeline")["generation"]
    conn.execute(
        "INSERT INTO csl.batches(batch_id,checkpoint,request_hash,status,generation,"
        "accepted_count,duplicate_count,conflicting_count,source_count) "
        "VALUES(%s,%s,%s,'committed',%s,0,%s,0,1)",
        (
            batch_id,
            checkpoint,
            sha256(json.dumps(request, separators=(",", ":")).encode()).hexdigest(),
            generation,
            raw_values[-1],
        ),
    )


def append_complete_duplicate(flow, collector, raw_values, references):
    batch_id, checkpoint = str(uuid4()), "serialized-duplicate"
    with collector.connect() as conn, conn.transaction():
        # Releasing a savepoint must preserve the current TOP transaction's batch
        # authorization. A subtransaction's xmin is not a sufficient authority.
        with conn.transaction():
            batch_insert(
                conn, flow, batch_id=batch_id, checkpoint=checkpoint, raw_values=raw_values
            )
        conn.execute(RAW_INSERT, raw_values)
        conn.execute(
            "INSERT INTO csl.raw_deliveries(batch_id,raw_id,source_ref) VALUES(%s,%s,%s)",
            (batch_id, raw_values[0], raw_values[1]),
        )
        for reference in references:
            conn.execute(
                "INSERT INTO csl.source_references(batch_id,raw_id,source_ref,record_index,"
                "event_key,record_hash) VALUES(%s,%s,%s,%s,%s,%s)",
                (
                    batch_id,
                    raw_values[0],
                    raw_values[1],
                    reference["record_index"],
                    reference["event_key"],
                    reference["record_hash"],
                ),
            )
        generation = one(flow.db, "SELECT generation FROM csl.pipeline")["generation"]
        conn.execute(
            "INSERT INTO csl.checkpoints(checkpoint,batch_id,generation) VALUES(%s,%s,%s)",
            (checkpoint, batch_id, generation),
        )
        conn.execute(
            "SELECT csl.pi_audit('ingestion_committed',%s)",
            (Jsonb({"batch_id": batch_id, "generation": generation}),),
        )


def waiting_backend(control, db, role, future, *, advisory=False):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        control.execute("SELECT pg_stat_clear_snapshot()")
        waiting = control.execute(
            "SELECT pid,wait_event FROM pg_stat_activity WHERE datname=%s AND usename=%s "
            "AND backend_type='client backend' AND wait_event_type='Lock' "
            "AND pid<>pg_backend_pid()",
            (db._values["dbname"], role),
        ).fetchall()
        assert len(waiting) <= 1, "Only the declared test account's operation may be observed"
        if waiting and (not advisory or str(waiting[0]["wait_event"]).lower() == "advisory"):
            return True
        if future.done():
            return False
        time.sleep(0.02)
    return False


@contextmanager
def paused_closure(flow, store, arguments):
    key = secrets.randbits(63)
    with flow.db.connect() as control, ThreadPoolExecutor(max_workers=2) as pool:
        control.autocommit = True
        control.execute("SELECT pg_advisory_lock(%s)", (key,))
        control.execute(
            sql.SQL("""CREATE FUNCTION public.machine_close_wait() RETURNS trigger
          LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='workflow_close' THEN
            IF NOT EXISTS(SELECT FROM csl.ws_closures WHERE case_id={}) THEN
              RAISE EXCEPTION 'closure must precede audit';
            END IF;
            PERFORM pg_advisory_xact_lock({});
          END IF; RETURN NEW; END $$""").format(sql.Literal(flow.cid), sql.Literal(key))
        )
        control.execute(
            "CREATE TRIGGER machine_close_wait BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION public.machine_close_wait()"
        )
        released = False

        def release():
            nonlocal released
            if not released:
                control.execute("SELECT pg_advisory_unlock(%s)", (key,))
                released = True

        try:
            closing = pool.submit(store.close, *arguments)
            assert waiting_backend(
                control, flow.db, store.data_db._values["user"], closing, advisory=True
            ), "Closure did not reach its final audit barrier"
            yield control, pool, closing, release
        finally:
            release()
            pool.shutdown(wait=True, cancel_futures=True)
            control.execute("DROP TRIGGER machine_close_wait ON csl.audit")
            control.execute("DROP FUNCTION public.machine_close_wait()")


def test_orphan_collector_statements_require_a_batch_in_the_current_top_transaction(workflow):  # noqa: F811
    collector = machine_roles(workflow)["collector"]
    store, args = close_arguments(workflow)
    store.close(*args)
    original, raw_values = original_copy(workflow.db)
    variant = one(workflow.db, "SELECT * FROM csl.record_variants ORDER BY event_key LIMIT 1")
    changed = json.loads(bytes(variant["canonical_bytes"]))
    changed["untrustedExtra"] = "orphan-variant"
    canonical = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
    prior = one(
        workflow.db, "SELECT batch_id,generation FROM csl.batches ORDER BY batch_id LIMIT 1"
    )
    mutations = (
        ("original", RAW_INSERT, raw_values),
        (
            "variant",
            "INSERT INTO csl.record_variants(event_key,record_hash,canonical_bytes,normalized) "
            "VALUES(%s,%s,%s,%s)",
            (
                variant["event_key"],
                sha256(canonical).hexdigest(),
                canonical,
                Jsonb(variant["normalized"]),
            ),
        ),
        (
            "checkpoint",
            "INSERT INTO csl.checkpoints(checkpoint,batch_id,generation) VALUES(%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            ("orphan-checkpoint", prior["batch_id"], prior["generation"]),
        ),
        (
            "job",
            "INSERT INTO csl.jobs(job_id,generation) VALUES(%s,%s)",
            (
                str(uuid4()),
                one(workflow.db, "SELECT generation FROM csl.pipeline")["generation"] + 1,
            ),
        ),
        ("finding-status", "UPDATE csl.findings SET status='pending' WHERE status='current'", ()),
        ("case-status", "UPDATE csl.cases SET status='pending' WHERE status='current'", ()),
        ("pipeline", "UPDATE csl.pipeline SET generation=generation+1", ()),
    )
    before, accepted = snapshot(workflow.db), []
    for label, statement, parameters in mutations:
        with collector.connect() as conn, conn.transaction(force_rollback=True):
            try:
                conn.execute(statement, parameters)
            except psycopg.Error as denied:
                assert denied.sqlstate == "P0001"
                assert denied.diag.message_primary == "PIPE_BATCH_REQUIRED"
            else:
                accepted.append(label)
    assert snapshot(workflow.db) == before
    assert store.view(args[0], workflow.cid)["state"] == "closed"
    assert not accepted, (
        "Machine SQL accepted source mutations without this transaction's batch: "
        + ",".join(accepted)
    )
    # A batch rolled back to a savepoint cannot leave authority for a later raw write.
    with collector.connect() as conn, conn.transaction(force_rollback=True):
        with conn.transaction(force_rollback=True):
            batch_insert(
                conn,
                workflow,
                batch_id=str(uuid4()),
                checkpoint="rolled-back-batch",
                raw_values=raw_values,
            )
        with pytest.raises(psycopg.Error) as denied:
            conn.execute(RAW_INSERT, raw_values)
        assert denied.value.diag.message_primary == "PIPE_BATCH_REQUIRED"
    assert snapshot(workflow.db) == before
    with collector.connect() as conn, conn.transaction(force_rollback=True):
        identity = conn.execute("SELECT csl.pi_identity() AS value").fetchone()["value"]
        caller_claims = {
            "csl.pipeline_batch_authorized": "true",
            "csl.pipeline_id": identity["pipeline_id"],
            "csl.batch_id": prior["batch_id"],
            "csl.transaction_id": conn.execute(
                "SELECT pg_current_xact_id()::text AS xid"
            ).fetchone()["xid"],
        }
        for key, value in caller_claims.items():
            conn.execute("SELECT pg_catalog.set_config(%s,%s,true)", (key, value))
        with pytest.raises(psycopg.Error) as denied:
            conn.execute(RAW_INSERT, raw_values)
        assert denied.value.diag.message_primary == "PIPE_BATCH_REQUIRED"
    assert snapshot(workflow.db) == before
    assert original["raw_id"] != raw_values[0]


def test_batch_and_original_commit_wait_for_closure_then_invalidate_with_atomic_audit(workflow):  # noqa: F811
    collector = machine_roles(workflow)["collector"]
    store, args = close_arguments(workflow)
    original, raw_values = original_copy(workflow.db)
    references = rows(
        workflow.db,
        "SELECT DISTINCT ON(record_index) record_index,event_key,record_hash "
        "FROM csl.source_references WHERE raw_id=%s ORDER BY record_index",
        (original["raw_id"],),
    )
    with paused_closure(workflow, store, args) as (control, pool, closing, release):
        source = pool.submit(append_complete_duplicate, workflow, collector, raw_values, references)
        serialized = waiting_backend(control, workflow.db, collector._values["user"], source)
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
        assert (
            one(
                workflow.db,
                "SELECT count(*) AS n FROM csl.raw_objects WHERE raw_id=%s",
                (raw_values[0],),
            )["n"]
            == 0
        )
        release()
        assert closing.result(timeout=8)["case_id"] == workflow.cid
        source.result(timeout=8)
    assert serialized, "The source transaction must wait for the closure serialization lock"
    view = store.view(args[0], workflow.cid)
    assert view["state"] == "reopen_required"
    assert view["current_recommendation"]["effective"] is False
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
    assert (
        one(workflow.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_close'")["n"]
        == 1
    )
    assert (
        one(
            workflow.db,
            "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_evidence_invalidated'",
        )["n"]
        == 1
    )
    assert verify_store(workflow.db)["verified"] is True
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_pipeline_batches")["n"] == 1
    for statement in (
        "UPDATE csl.ws_pipeline_batches SET created_at=clock_timestamp()",
        "DELETE FROM csl.ws_pipeline_batches",
    ):
        with pytest.raises(psycopg.Error), workflow.db.connect() as conn:
            conn.execute(statement)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_pipeline_batches")["n"] == 1


def test_raw_worker_finding_write_waits_then_reopens_and_failed_audit_rolls_everything_back(
    workflow,  # noqa: F811
):
    worker = machine_roles(workflow)["worker"]
    store, args = close_arguments(workflow)

    def change_finding():
        with worker.connect() as conn:
            conn.execute("UPDATE csl.findings SET status='pending' WHERE status='current'")

    with paused_closure(workflow, store, args) as (control, pool, closing, release):
        changing = pool.submit(change_finding)
        serialized = waiting_backend(control, workflow.db, worker._values["user"], changing)
        release()
        assert closing.result(timeout=8)["case_id"] == workflow.cid
        changing.result(timeout=8)
    assert serialized, "A native worker write bypassed the closure's pipeline lock"
    view = store.view(args[0], workflow.cid)
    assert view["state"] == "reopen_required"
    assert view["current_recommendation"]["effective"] is False
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
    assert (
        one(
            workflow.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_machine_changed'"
        )["n"]
        == 1
    )
    with worker.connect() as conn:
        conn.execute("UPDATE csl.findings SET status='current' WHERE status='pending'")
    workflow.reopen()
    store, args = close_arguments(workflow)
    store.close(*args)
    before = snapshot(workflow.db)
    with workflow.db.connect() as control:
        control.execute(
            "CREATE FUNCTION public.machine_audit_fault() RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN IF NEW.kind='workflow_machine_changed' THEN "
            "RAISE EXCEPTION 'controlled_machine_audit_failure'; END IF; RETURN NEW; END $$"
        )
        control.execute(
            "CREATE TRIGGER machine_audit_fault BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION public.machine_audit_fault()"
        )
    try:
        with pytest.raises(psycopg.Error):
            change_finding()
        assert snapshot(workflow.db) == before
        assert store.view(args[0], workflow.cid)["state"] == "closed"
    finally:
        with workflow.db.connect() as control:
            control.execute("DROP TRIGGER machine_audit_fault ON csl.audit")
            control.execute("DROP FUNCTION public.machine_audit_fault()")
    change_finding()
    assert store.view(args[0], workflow.cid)["state"] == "reopen_required"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 2
    assert (
        one(
            workflow.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_machine_changed'"
        )["n"]
        == 2
    )


def test_scoped_normal_ingestion_publication_and_nul_quarantine_remain_supported(
    workflow,  # noqa: F811
    tmp_path,
):
    runtime = {}
    for kind in ("collector", "worker"):
        path = tmp_path / f"{kind}.json"
        write_private_json(path, provision_pipeline(workflow.db, kind))
        runtime[kind] = load_pipeline_config(path, kind)
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    assert (
        ingest(
            runtime["collector"],
            [("synthetic/normal.json.gz", archive([event("machine-late", base + 10)]))],
            checkpoint="machine-normal",
        )["accepted"]
        == 1
    )
    assert work_once(runtime["worker"])["status"] == "succeeded"
    assert len(current(workflow.db)) == 2
    assert verify_store(runtime["worker"])["verified"] is True
    before = snapshot(workflow.db)
    rejected = event("machine-nul", base + 15)
    rejected["futureField"] = "rejected\x00synthetic"
    from cloudsecops_live.errors import EvidenceError

    with pytest.raises(EvidenceError, match="NUL_CHARACTER"):
        ingest(
            runtime["collector"],
            [("synthetic/nul.json.gz", archive([rejected]))],
            checkpoint="machine-nul",
        )
    after = snapshot(workflow.db)
    assert {key: value for key, value in after.items() if key != "ingestion_errors"} == {
        key: value for key, value in before.items() if key != "ingestion_errors"
    }
    assert len(after["ingestion_errors"]) == len(before["ingestion_errors"]) + 1


def test_marker_and_internal_guards_are_private_and_missing_or_disabled_mapping_cannot_write(
    workflow,  # noqa: F811
):
    actors = machine_roles(workflow)
    credentials = [
        *actors.values(),
        workflow.workspace.config.gate_db,
        Database(workflow.verifier_account["dsn"]),
    ]
    for account in workflow.workspace.accounts.values():
        credentials.extend((Database(account["auth_dsn"]), Database(account["data_dsn"])))
    statements = (
        "SELECT * FROM csl.ws_pipeline_batches",
        "INSERT INTO csl.ws_pipeline_batches DEFAULT VALUES",
        "UPDATE csl.ws_pipeline_batches SET created_at=clock_timestamp()",
        "DELETE FROM csl.ws_pipeline_batches",
        "SELECT csl.pi_actor()",
        "SELECT csl.pi_write_guard()",
    )
    before = snapshot(workflow.db)
    for credential in credentials:
        for statement in statements:
            with credential.connect() as conn, conn.transaction(force_rollback=True):
                with pytest.raises(psycopg.Error) as denied:
                    conn.execute(statement)
                assert denied.value.sqlstate == "42501"
    assert snapshot(workflow.db) == before
    original, raw_values = original_copy(workflow.db)
    assert original["raw_id"] != raw_values[0]
    for kind, actor in actors.items():
        mapping = one(
            workflow.db,
            "SELECT * FROM csl.ws_pipeline_identities WHERE login_role=%s",
            (actor._values["user"],),
        )
        for state in ("disabled", "missing"):
            with workflow.db.connect() as conn:
                if state == "disabled":
                    conn.execute(
                        "UPDATE csl.ws_pipeline_identities SET enabled=false WHERE pipeline_id=%s",
                        (mapping["pipeline_id"],),
                    )
                else:
                    conn.execute(
                        "DELETE FROM csl.ws_pipeline_identities WHERE pipeline_id=%s",
                        (mapping["pipeline_id"],),
                    )
            try:
                # Retain LOGIN and the DB-specific capability deliberately. Only
                # the server-side mapping has changed, so Python validation and
                # connection denial cannot hide a missing native DML guard.
                with actor.connect() as conn, conn.transaction(force_rollback=True):
                    assert conn.execute("SELECT 1 AS n").fetchone()["n"] == 1
                    authority = one(
                        workflow.db,
                        "SELECT r.rolcanlogin,(SELECT count(*) FROM pg_catalog.pg_auth_members m "
                        "WHERE m.member=r.oid) AS memberships FROM pg_catalog.pg_roles r "
                        "WHERE r.rolname=%s",
                        (actor._values["user"],),
                    )
                    assert authority == {"rolcanlogin": True, "memberships": 1}
                    with pytest.raises(psycopg.Error) as denied:
                        if kind == "collector":
                            batch_insert(
                                conn,
                                workflow,
                                batch_id=str(uuid4()),
                                checkpoint="unmapped-collector",
                                raw_values=raw_values,
                            )
                        else:
                            conn.execute(
                                "UPDATE csl.findings SET status='pending' WHERE status='current'"
                            )
                    assert denied.value.sqlstate == "P0001"
                    assert denied.value.diag.message_primary == "PIPE_DENIED"
            finally:
                with workflow.db.connect() as conn:
                    if state == "disabled":
                        conn.execute(
                            "UPDATE csl.ws_pipeline_identities SET enabled=true "
                            "WHERE pipeline_id=%s",
                            (mapping["pipeline_id"],),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO csl.ws_pipeline_identities"
                            "(pipeline_id,login_role,kind,enabled) "
                            "VALUES(%s,%s,%s,%s)",
                            (
                                mapping["pipeline_id"],
                                mapping["login_role"],
                                mapping["kind"],
                                mapping["enabled"],
                            ),
                        )
            assert snapshot(workflow.db) == before


def test_stale_server_marker_cannot_authorize_matching_current_xid_and_actual_actor(workflow):  # noqa: F811
    collector = machine_roles(workflow)["collector"]
    role = collector._values["user"]
    identity = one(
        workflow.db,
        "SELECT pipeline_id FROM csl.ws_pipeline_identities WHERE login_role=%s",
        (role,),
    )
    _, raw_values = original_copy(workflow.db)
    prior = one(workflow.db, "SELECT batch_id FROM csl.batches ORDER BY batch_id LIMIT 1")
    before = snapshot(workflow.db)
    fresh_batch = str(uuid4())
    with workflow.db.connect() as conn, conn.transaction(force_rollback=True):
        initial_user = conn.execute("SELECT session_user AS name").fetchone()["name"]
        top_xid = conn.execute("SELECT pg_current_xact_id()::text AS xid").fetchone()["xid"]
        # Maintenance injects only this stale control-plane fixture. All attempted
        # source writes below execute as the actual collector SESSION_USER.
        conn.execute(
            "INSERT INTO csl.ws_pipeline_batches"
            "(transaction_id,batch_id,pipeline_id,server_started_at) "
            "VALUES(%s::xid8,%s,%s,pg_postmaster_start_time()-interval '1 day')",
            (top_xid, prior["batch_id"], identity["pipeline_id"]),
        )
        try:
            with pytest.raises(psycopg.Error) as denied:
                with conn.transaction():
                    conn.execute(
                        sql.SQL("SET SESSION AUTHORIZATION {}").format(sql.Identifier(role))
                    )
                    actual = conn.execute("SELECT current_user,session_user").fetchone()
                    assert actual == {"current_user": role, "session_user": role}
                    assert (
                        conn.execute("SELECT pg_current_xact_id()::text AS xid").fetchone()["xid"]
                        == top_xid
                    )
                    conn.execute(RAW_INSERT, raw_values)
            assert denied.value.sqlstate == "P0001"
            assert denied.value.diag.message_primary == "PIPE_BATCH_REQUIRED"
        finally:
            conn.execute("RESET SESSION AUTHORIZATION")
        assert conn.execute("SELECT session_user AS name").fetchone()["name"] == initial_user
        # The rejected statement's savepoint has rolled back; the deliberately
        # stale marker still exists in this top transaction and must be ignored.
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM csl.ws_pipeline_batches "
                "WHERE transaction_id=%s::xid8 AND pipeline_id=%s",
                (top_xid, identity["pipeline_id"]),
            ).fetchone()["n"]
            == 1
        )
        try:
            with conn.transaction():
                conn.execute(sql.SQL("SET SESSION AUTHORIZATION {}").format(sql.Identifier(role)))
                batch_insert(
                    conn,
                    workflow,
                    batch_id=fresh_batch,
                    checkpoint="fresh-server-batch",
                    raw_values=raw_values,
                )
            actual = conn.execute("SELECT current_user,session_user").fetchone()
            assert actual == {"current_user": role, "session_user": role}
            assert conn.execute(RAW_INSERT, raw_values).rowcount == 1
            assert (
                conn.execute("SELECT pg_current_xact_id()::text AS xid").fetchone()["xid"]
                == top_xid
            )
        finally:
            conn.execute("RESET SESSION AUTHORIZATION")
        fresh = conn.execute(
            "SELECT transaction_id::text AS xid,pipeline_id,"
            "server_started_at=pg_postmaster_start_time() AS current_server "
            "FROM csl.ws_pipeline_batches WHERE batch_id=%s",
            (fresh_batch,),
        ).fetchone()
        assert fresh == {
            "xid": top_xid,
            "pipeline_id": identity["pipeline_id"],
            "current_server": True,
        }
        assert conn.execute("SELECT session_user AS name").fetchone()["name"] == initial_user
    assert snapshot(workflow.db) == before
