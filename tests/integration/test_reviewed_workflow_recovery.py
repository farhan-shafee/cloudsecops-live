"""Real workflow transaction interruption, source races and bounded authority expiry."""

from __future__ import annotations

import secrets
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Barrier

import psycopg
import pytest
from psycopg import sql

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.worker import work_once
from tests.integration.support import add, one
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def mutation(workflow, action):  # noqa: F811
    """Prepare all credentials and computation before injecting a catalog fault."""
    if action == "reopen":
        base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
        add(workflow.db, [base, base + 20, base + 40], "audit-reopen-changed-provenance")
        assert workflow.view()["state"] == "reopen_required"
        store, token, nonce, version = workflow.prepare("reopen", "reviewer")

        def invoke():
            return store.reopen(
                token, nonce, workflow.cid, version, "Reopen this synthetic exercise"
            )

        return invoke, store.data_db, nonce, "ws_transitions"
    if action == "recommend":
        store, token, nonce, version = workflow.prepare("recommend")

        def invoke():
            return store.recommend(
                token,
                nonce,
                workflow.cid,
                workflow.case["current_revision"],
                workflow.case["fingerprint"],
                version,
                "Synthetic exercise",
                "Benign inventory",
                "No authentic AWS activity",
            )

        return invoke, store.data_db, nonce, "ws_recommendations"
    rec = workflow.recommend()
    if action == "review":
        store, token, nonce, version = workflow.prepare("review", "reviewer", rec["version"])

        def invoke():
            return store.review(
                token,
                nonce,
                workflow.cid,
                version,
                rec["recommendation_id"],
                rec["version"],
                rec["recommendation_hash"],
                "approve",
                "Exact evidence reviewed",
            )

        return invoke, store.data_db, nonce, "ws_reviews"
    review = workflow.review(rec)
    if action == "verification":
        from cloudsecops_live.independent_verifier import verify_snapshot

        verifier = workflow.verifier()
        request = verifier.begin(rec["recommendation_id"], rec["version"])
        report = verify_snapshot(
            request, lambda raw_id: verifier.original(request["request_id"], raw_id)
        )
        assert report["result"] == "verified"
        return (
            lambda: verifier.finish(request["request_id"], report),
            verifier.db,
            None,
            "ws_verifications",
        )
    receipt = workflow.verify(rec)
    store, token, nonce, version = workflow.prepare("close", "reviewer", rec["version"])

    def invoke():
        return store.close(
            token,
            nonce,
            workflow.cid,
            version,
            rec["recommendation_id"],
            rec["version"],
            rec["recommendation_hash"],
            review["review_id"],
            receipt["verification_id"],
            "No-action synthetic exercise closure",
        )

    return invoke, store.data_db, nonce, "ws_closures"


def observed(workflow, table, action, nonce):  # noqa: F811
    result = {
        "records": one(workflow.db, f"SELECT count(*) AS n FROM csl.{table}")["n"],
        "audit": one(
            workflow.db,
            "SELECT count(*) AS n FROM csl.audit WHERE kind=%s",
            ("workflow_" + action,),
        )["n"],
    }
    if nonce:
        result["used"] = one(
            workflow.db,
            "SELECT used FROM csl.ws_workflow_csrf WHERE nonce_hash=%s",
            (sha256(nonce.encode()).hexdigest(),),
        )["used"]
    if action == "verification":
        result["consumed"] = one(
            workflow.db, "SELECT count(*) AS n FROM csl.ws_verification_requests WHERE consumed"
        )["n"]
    return result


def test_real_audit_rejection_rolls_back_each_workflow_transition_and_retries(workflow):  # noqa: F811
    # A missing audit must never leave successful domain state or consumed authority.
    for action in ("recommend", "review", "verification", "close", "reopen"):
        invoke, _, nonce, table = mutation(workflow, action)
        before = observed(workflow, table, action, nonce)
        with workflow.db.connect() as conn:
            conn.execute(
                "CREATE FUNCTION public.workflow_audit_fault() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind="
                "'workflow_" + action + "' THEN RAISE EXCEPTION 'controlled_workflow_audit_fault';"
                " END IF; RETURN NEW; END $$"
            )
            conn.execute(
                "CREATE TRIGGER workflow_audit_fault BEFORE INSERT ON csl.audit "
                "FOR EACH ROW EXECUTE FUNCTION public.workflow_audit_fault()"
            )
        try:
            with pytest.raises(EvidenceError):
                invoke()
            assert observed(workflow, table, action, nonce) == before
        finally:
            with workflow.db.connect() as conn:
                conn.execute("DROP TRIGGER workflow_audit_fault ON csl.audit")
                conn.execute("DROP FUNCTION public.workflow_audit_fault()")
        invoke()
        after = observed(workflow, table, action, nonce)
        assert after["records"] == before["records"] + 1
        assert after["audit"] == before["audit"] + 1
        if nonce:
            assert after["used"] is True
        if action == "verification":
            assert after["consumed"] == before["consumed"] + 1
    rec = workflow.recommend()
    review = workflow.review(rec)
    workflow.close(rec, review, workflow.verify(rec))
    store, token = workflow.store(), workflow.token()
    batches_before = one(workflow.db, "SELECT count(*) AS n FROM csl.batches")["n"]
    invalidations_before = one(
        workflow.db,
        "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_evidence_invalidated'",
    )["n"]
    with workflow.db.connect() as conn:
        conn.execute(
            "CREATE FUNCTION public.workflow_source_audit_fault() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='workflow_evidence_invalidated' "
            "THEN RAISE EXCEPTION 'controlled_source_audit_fault'; "
            "END IF; RETURN NEW; END $$"
        )
        conn.execute(
            "CREATE TRIGGER workflow_source_audit_fault BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION public.workflow_source_audit_fault()"
        )
    try:
        # Exercise the real batch invalidation trigger inside its maintenance
        # transaction; a rejected source batch must not invalidate human state.
        with pytest.raises(psycopg.Error), workflow.db.connect() as conn:
            conn.execute("SELECT * FROM csl.pipeline FOR UPDATE")
            conn.execute(
                "INSERT INTO csl.batches(batch_id,checkpoint,request_hash,status,generation,"
                "accepted_count,duplicate_count,conflicting_count,source_count) "
                "SELECT %s,%s,request_hash,'committed',generation,0,0,0,0 "
                "FROM csl.batches ORDER BY batch_id LIMIT 1",
                (secrets.token_hex(32), secrets.token_hex(32)),
            )
        assert store.view(token, workflow.cid)["state"] == "closed"
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.batches")["n"] == batches_before
        assert (
            one(
                workflow.db,
                "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_evidence_invalidated'",
            )["n"]
            == invalidations_before
        )
    finally:
        with workflow.db.connect() as conn:
            conn.execute("DROP TRIGGER workflow_source_audit_fault ON csl.audit")
            conn.execute("DROP FUNCTION public.workflow_source_audit_fault()")
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    add(workflow.db, [base, base + 20, base + 40], "invalidating-audit-retry")
    assert workflow.view()["state"] == "reopen_required"
    assert (
        one(
            workflow.db,
            "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_evidence_invalidated'",
        )["n"]
        == invalidations_before + 1
    )


@pytest.mark.parametrize("action", ("review", "verification", "close"))
def test_actual_restricted_backend_kill_before_audit_rolls_back_then_retries(workflow, action):  # noqa: F811
    invoke, restricted, nonce, table = mutation(workflow, action)
    before = observed(workflow, table, action, nonce)
    lock_key = secrets.randbits(63)
    role = restricted._values["user"]
    with workflow.db.connect() as control:
        control.autocommit = True
        control.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
        control.execute(
            sql.SQL("""CREATE FUNCTION public.workflow_interruption_wait()
          RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.kind={} THEN
            IF NOT EXISTS (SELECT FROM csl.{} WHERE recommendation_id={}) THEN
              RAISE EXCEPTION 'domain row must precede audit';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock({});
          END IF; RETURN NEW; END $$""").format(
                sql.Literal("workflow_" + action),
                sql.Identifier(table),
                sql.Literal(workflow.cid),
                sql.Literal(lock_key),
            )
        )
        control.execute(
            "CREATE TRIGGER workflow_interruption_wait BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION public.workflow_interruption_wait()"
        )
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(invoke)
            deadline, victim_pid = time.monotonic() + 8, None
            while time.monotonic() < deadline:
                waiting = control.execute(
                    "SELECT pid FROM pg_stat_activity WHERE datname=%s AND usename=%s "
                    "AND backend_type='client backend' AND wait_event_type='Lock' "
                    "AND lower(wait_event)='advisory' AND pid<>pg_backend_pid()",
                    (workflow.db._values["dbname"], role),
                ).fetchall()
                assert len(waiting) <= 1, "Only the declared restricted operation may be targeted"
                if waiting:
                    victim_pid = waiting[0]["pid"]
                    break
                assert not future.done(), "Operation ended before its domain-write/audit barrier"
                time.sleep(0.02)
            assert victim_pid is not None
            assert (
                control.execute(
                    "SELECT pg_terminate_backend(%s) AS stopped", (victim_pid,)
                ).fetchone()["stopped"]
                is True
            )
            with pytest.raises(EvidenceError) as failed:
                future.result(timeout=5)
            assert failed.value.code == "WS_DATABASE"
            assert observed(workflow, table, action, nonce) == before
        finally:
            control.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))
            executor.shutdown(wait=True, cancel_futures=True)
            control.execute("DROP TRIGGER workflow_interruption_wait ON csl.audit")
            control.execute("DROP FUNCTION public.workflow_interruption_wait()")
    first = invoke()
    after = observed(workflow, table, action, nonce)
    assert after["records"] == before["records"] + 1
    assert after["audit"] == before["audit"] + 1
    if action == "verification":
        assert after["consumed"] == before["consumed"] + 1
        assert invoke() == first
        assert observed(workflow, table, action, nonce) == after
    else:
        with pytest.raises(EvidenceError):
            invoke()


def test_verifier_finish_expiry_disable_and_conflicting_replay_fail_closed(workflow):  # noqa: F811
    from cloudsecops_live.independent_verifier import verify_snapshot
    from cloudsecops_live.workspace_roles import disable_verifier

    rec = workflow.recommend()
    review = workflow.review(rec)
    verifier = workflow.verifier()
    request = verifier.begin(rec["recommendation_id"], rec["version"])
    report = verify_snapshot(
        request, lambda raw_id: verifier.original(request["request_id"], raw_id)
    )
    with workflow.db.connect() as conn:
        conn.execute("ALTER TABLE csl.ws_verification_requests DISABLE TRIGGER USER")
        conn.execute(
            "UPDATE csl.ws_verification_requests "
            "SET expires_at=clock_timestamp()-interval '1 second'"
        )
        conn.execute("ALTER TABLE csl.ws_verification_requests ENABLE TRIGGER USER")
    with pytest.raises(EvidenceError, match="WS_STALE"):
        verifier.finish(request["request_id"], report)
    assert (
        one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verification_requests WHERE consumed")[
            "n"
        ]
        == 0
    )
    request = verifier.begin(rec["recommendation_id"], rec["version"], secrets.token_hex(16))
    report = verify_snapshot(
        request, lambda raw_id: verifier.original(request["request_id"], raw_id)
    )
    receipt = verifier.finish(request["request_id"], report)
    assert verifier.finish(request["request_id"], report) == receipt
    altered = {**report, "result": "contradicted"}
    with pytest.raises(EvidenceError):
        verifier.finish(request["request_id"], altered)
    disable_verifier(workflow.db, workflow.verifier_account["verifier_id"])
    with pytest.raises(EvidenceError):
        workflow.verify(rec)
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 1
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0


def test_recommendation_and_receipt_expiry_are_database_enforced(workflow):  # noqa: F811
    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    # Maintenance-only time fixture models elapsed database time without sleeps.
    with workflow.db.connect() as conn:
        conn.execute("ALTER TABLE csl.ws_verifications DISABLE TRIGGER USER")
        conn.execute(
            "UPDATE csl.ws_verifications "
            "SET created_at=transaction_timestamp()-interval '11 minutes',"
            "expires_at=transaction_timestamp()-interval '1 minute'"
        )
        conn.execute("ALTER TABLE csl.ws_verifications ENABLE TRIGGER USER")
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    rec = workflow.recommend()
    with workflow.db.connect() as conn:
        conn.execute("ALTER TABLE csl.ws_recommendations DISABLE TRIGGER USER")
        conn.execute(
            "UPDATE csl.ws_recommendations "
            "SET created_at=transaction_timestamp()-interval '31 minutes',"
            "expires_at=transaction_timestamp()-interval '1 minute'"
        )
        conn.execute("ALTER TABLE csl.ws_recommendations ENABLE TRIGGER USER")
    with pytest.raises(EvidenceError):
        workflow.review(rec)
    with pytest.raises(EvidenceError):
        workflow.verify(rec)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0


def test_closure_racing_new_ingestion_never_leaves_current_closed_authority(workflow):  # noqa: F811
    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    barrier = Barrier(2)

    def close():
        barrier.wait(timeout=10)
        try:
            workflow.close(rec, review, receipt)
            return "committed"
        except EvidenceError as exc:
            return exc.code

    def ingest():
        barrier.wait(timeout=10)
        return add(workflow.db, [base + 10], "racing-source")

    with ThreadPoolExecutor(max_workers=2) as pool:
        closing, ingestion = pool.submit(close), pool.submit(ingest)
        assert closing.result(timeout=20) in ("committed", "WS_STALE")
        assert ingestion.result(timeout=20)["accepted"] == 1
    view = workflow.view()
    assert view["state"] in ("open", "reopen_required")
    assert view["current_recommendation"]["effective"] is False
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] <= 1
    work_once(workflow.db)
    assert workflow.view()["state"] != "closed"


def test_actual_verifier_process_death_before_and_after_commit_recovers_same_run(
    workflow,  # noqa: F811
    tmp_path,
):
    from cloudsecops_live.workspace_config import write_private_json

    rec = workflow.recommend()
    workflow.review(rec)
    config = tmp_path / "verifier-process.json"
    write_private_json(config, workflow.verifier_account)
    # The wrapper controls process lifetime only. Every proof and database write
    # still goes through the installed independent checker and restricted store.
    child_code = """
import sys
from pathlib import Path
from cloudsecops_live.workflow_store import VerifierStore
from cloudsecops_live.verifier_runtime import load_config, run_verification
phase=sys.argv[5]
if phase=='before':
    original_init=VerifierStore.__init__
    def ready(self,*args,**kwargs):
        original_init(self,*args,**kwargs)
        print('validated',flush=True)
        sys.stdin.readline()
    VerifierStore.__init__=ready
else:
    original_finish=VerifierStore.finish
    def committed(self,*args,**kwargs):
        receipt=original_finish(self,*args,**kwargs)
        print('committed',flush=True)
        sys.stdin.readline()
        return receipt
    VerifierStore.finish=committed
run_verification(load_config(Path(sys.argv[1])),sys.argv[2],int(sys.argv[3]),sys.argv[4])
"""
    role = workflow.verifier().db._values["user"]
    for index, phase in enumerate(("before", "after")):
        run_id = secrets.token_hex(16)
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                child_code,
                str(config),
                rec["recommendation_id"],
                str(rec["version"]),
                run_id,
                phase,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert process.stdout is not None and process.stdin is not None
        reader = ThreadPoolExecutor(max_workers=1)
        lock_key = secrets.randbits(63)
        with workflow.db.connect() as control:
            control.autocommit = True
            injected = False
            try:
                marker = reader.submit(process.stdout.readline).result(timeout=20).strip()
                assert marker == ("validated" if phase == "before" else "committed")
                if phase == "before":
                    control.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
                    control.execute(
                        sql.SQL("""CREATE FUNCTION public.verifier_process_wait()
                      RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                      IF NEW.kind='workflow_verification' THEN
                        IF NOT EXISTS(SELECT FROM csl.ws_verifications WHERE request_id={}) THEN
                          RAISE EXCEPTION 'receipt must precede audit';
                        END IF;
                        PERFORM pg_advisory_xact_lock({});
                      END IF; RETURN NEW; END $$""").format(
                            sql.Literal(run_id), sql.Literal(lock_key)
                        )
                    )
                    control.execute(
                        "CREATE TRIGGER verifier_process_wait BEFORE INSERT ON csl.audit "
                        "FOR EACH ROW EXECUTE FUNCTION public.verifier_process_wait()"
                    )
                    injected = True
                    process.stdin.write("continue\n")
                    process.stdin.flush()
                    deadline, reached = time.monotonic() + 15, False
                    while time.monotonic() < deadline:
                        waiting = control.execute(
                            "SELECT pid FROM pg_stat_activity WHERE datname=%s AND usename=%s "
                            "AND wait_event_type='Lock' AND lower(wait_event)='advisory'",
                            (workflow.db._values["dbname"], role),
                        ).fetchall()
                        assert len(waiting) <= 1
                        if waiting:
                            reached = True
                            break
                        assert process.poll() is None, (
                            "Verifier exited before its receipt/audit barrier"
                        )
                        time.sleep(0.02)
                    assert reached, "Verifier never reached its uncommitted receipt/audit barrier"
                process.kill()
                process.wait(timeout=10)
                assert process.returncode != 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                process.stdin.close()
                process.stdout.close()
                reader.shutdown(wait=True, cancel_futures=True)
                if injected:
                    control.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))
                    control.execute("DROP TRIGGER verifier_process_wait ON csl.audit")
                    control.execute("DROP FUNCTION public.verifier_process_wait()")
        persisted = one(
            workflow.db,
            "SELECT count(*) AS n FROM csl.ws_verifications WHERE request_id=%s",
            (run_id,),
        )["n"]
        assert persisted == (0 if phase == "before" else 1)
        state = one(
            workflow.db,
            "SELECT consumed FROM csl.ws_verification_requests WHERE request_id=%s",
            (run_id,),
        )
        assert state["consumed"] is (phase == "after")
        receipt = workflow.verify(rec, run_id=run_id)
        assert receipt["result"] == "verified"
        assert workflow.verify(rec, run_id=run_id) == receipt
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == index + 1
        assert (
            one(
                workflow.db,
                "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_verification'",
            )["n"]
            == index + 1
        )
