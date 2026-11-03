"""Independent least-privilege observations for normal collection and publication."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.outbox import deliver_once
from cloudsecops_live.storage import ingest, verify_store
from cloudsecops_live.worker import work_once
from tests.helpers import archive, event
from tests.integration.support import current, one
from tests.integration.test_backup import pg_command, snapshot


@dataclass
class Pipeline:
    db: Database = field(repr=False)
    records: dict[str, dict[str, str]] = field(repr=False)
    runtime: dict[str, Any] = field(repr=False)
    paths: dict[str, Any] = field(repr=False)

    def __iter__(self):
        return iter((self.db, self.records, self.runtime, self.paths))


@pytest.fixture
def pipeline(db, tmp_path):
    from cloudsecops_live.pipeline_roles import load_pipeline_config, provision_pipeline
    from cloudsecops_live.workspace_config import write_private_json

    records = {kind: provision_pipeline(db, kind) for kind in ("collector", "worker")}
    runtime = {}
    paths = {}
    for kind, account in records.items():
        path = tmp_path / f"{kind}.json"
        write_private_json(path, account)
        paths[kind] = path
        runtime[kind] = load_pipeline_config(path, kind)
    return Pipeline(db, records, runtime, paths)


def batch():
    return archive([event("p0"), event("p20", 20), event("p40", 40)])


def denied(db, statement, parameters=(), *, sqlstate="42501"):
    # Unexpected success is rolled back as well; no denial probe may corrupt a
    # retained fixture merely because the privilege boundary was broken.
    with db.connect() as conn, conn.transaction(force_rollback=True):
        with pytest.raises(psycopg.Error) as rejected:
            conn.execute(statement, parameters)
        assert rejected.value.sqlstate == sqlstate


def publish(pipeline):  # noqa: F811
    _, _, runtime, _ = pipeline
    result = ingest(
        runtime["collector"], [("synthetic/pipeline.gz", batch())], checkpoint="pipeline"
    )
    assert result["accepted"] == 3
    assert work_once(runtime["worker"])["status"] == "succeeded"


def test_actual_collector_worker_ingest_publish_and_machine_audits_without_human_authority(
    pipeline,
):
    db, records, runtime, _ = pipeline
    assert records["collector"]["pipeline_id"] != records["worker"]["pipeline_id"]
    assert (
        Database(records["collector"]["dsn"])._values["user"]
        != Database(records["worker"]["dsn"])._values["user"]
    )
    before = {
        name: values
        for name, values in snapshot(db).items()
        if name.startswith("ws_") and name != "ws_pipeline_batches"
    }
    publish(pipeline)
    cases = current(db)
    assert len(cases) == 1
    assert cases[0]["payload"]["evidence_event_ids"] == ["p0", "p20", "p40"]
    assert cases[0]["payload"]["unreviewed"] is True
    assert cases[0]["payload"]["source_kind"] == "synthetic"
    assert cases[0]["payload"]["authenticated"] is False
    original = one(db, "SELECT archive_bytes,archive_hash FROM csl.raw_objects")
    assert bytes(original["archive_bytes"]) == batch()
    assert original["archive_hash"] == sha256(batch()).hexdigest()
    assert one(db, "SELECT generation,published_generation FROM csl.pipeline") == {
        "generation": 1,
        "published_generation": 1,
    }
    assert {
        name: values
        for name, values in snapshot(db).items()
        if name.startswith("ws_") and name != "ws_pipeline_batches"
    } == before
    # The sole excluded ws_* table is machine protocol metadata, not human state.
    # Its actor/batch binding and server-assigned full transaction type are explicit.
    assert one(db, "SELECT count(*) AS n FROM csl.ws_pipeline_batches")["n"] == 1
    marker = one(
        db,
        "SELECT m.pipeline_id,b.checkpoint,pg_typeof(m.transaction_id)::text AS xid_type,"
        "mod(m.transaction_id::text::numeric,4294967296)=b.xmin::text::numeric AS server_xid "
        "FROM csl.ws_pipeline_batches m JOIN csl.batches b ON b.batch_id=m.batch_id",
    )
    assert marker == {
        "pipeline_id": records["collector"]["pipeline_id"],
        "checkpoint": "pipeline",
        "xid_type": "xid8",
        "server_xid": True,
    }
    with db.connect() as conn:
        kinds = {row["kind"] for row in conn.execute("SELECT kind FROM csl.audit").fetchall()}
    assert kinds == {"ingestion_committed", "job_claim", "case_revision", "job_completed"}
    assert verify_store(db)["verified"] is True
    assert verify_store(runtime["worker"])["verified"] is True
    assert deliver_once(runtime["worker"])["status"] == "locally_acknowledged"
    for kind in ("collector", "worker"):
        with runtime[kind].connect() as conn:
            role = conn.execute("SELECT current_user,session_user").fetchone()
            assert role["current_user"] == role["session_user"]


def test_actual_pipeline_credentials_cannot_read_humans_or_forge_human_audit(pipeline):
    db, records, runtime, _ = pipeline
    publish(pipeline)
    before = snapshot(db)
    forbidden = (
        "SELECT password_hash FROM csl.ws_users",
        "SELECT token_hash FROM csl.ws_sessions",
        "SELECT * FROM csl.ws_recommendations",
        "SELECT * FROM csl.ws_reviews",
        "SELECT * FROM csl.ws_verifications",
        "SELECT * FROM csl.ws_closures",
        "SELECT * FROM csl.ws_pipeline_identities",
        "UPDATE csl.ws_pipeline_identities SET enabled=true",
        "SELECT * FROM csl.audit",
        "INSERT INTO csl.audit(kind,payload) VALUES('workflow_review','{}')",
        "INSERT INTO csl.ws_recommendations DEFAULT VALUES",
        "INSERT INTO csl.ws_reviews DEFAULT VALUES",
        "INSERT INTO csl.ws_verifications DEFAULT VALUES",
        "INSERT INTO csl.ws_closures DEFAULT VALUES",
        "UPDATE csl.raw_objects SET source_ref='rewritten'",
        "DELETE FROM csl.record_variants",
        "UPDATE csl.schema_migrations SET checksum=repeat('0',64)",
        "ALTER TABLE csl.raw_objects ADD COLUMN authority_escalation integer",
        "CREATE TABLE public.pipeline_escalation(id integer)",
        "CREATE ROLE pipeline_escalation",
        "SET ROLE csl_ws_owner",
        "SET ROLE csl_vf_owner",
        "SET ROLE csl_ws_verifier",
        "SELECT csl.ws_password_hash()",
        "SELECT csl.wf_manifest()",
    )
    for kind in runtime:
        # Native SQL probes deliberately bypass the Python identity wrapper.
        restricted = Database(records[kind]["dsn"])
        for statement in forbidden:
            denied(restricted, statement)
        with restricted.connect() as conn, conn.transaction(force_rollback=True):
            with pytest.raises(psycopg.Error) as rejected:
                conn.execute("SELECT csl.pi_audit('workflow_review','{}'::jsonb)")
            assert rejected.value.sqlstate == "P0001"
            assert rejected.value.diag.message_primary == "PIPE_DENIED"
        wrong_machine_kind = "job_completed" if kind == "collector" else "ingestion_committed"
        with restricted.connect() as conn, conn.transaction(force_rollback=True):
            with pytest.raises(psycopg.Error) as rejected:
                conn.execute("SELECT csl.pi_audit(%s,'{}'::jsonb)", (wrong_machine_kind,))
            assert rejected.value.diag.message_primary == "PIPE_DENIED"
        other = records["worker" if kind == "collector" else "collector"]
        other_login = Database(other["dsn"])._values["user"]
        with db.connect() as conn:
            foreign = conn.execute(
                "SELECT r.rolname FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles r ON r.oid=m.roleid "
                "WHERE m.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s)",
                (other_login,),
            ).fetchone()["rolname"]
        denied(restricted, sql.SQL("SET ROLE {}").format(sql.Identifier(foreign)))
    assert snapshot(db) == before


def test_pipeline_column_grants_do_not_allow_server_defaults_or_foreign_machine_authority(pipeline):
    _, records, _, _ = pipeline
    publish(pipeline)
    collector, worker = (Database(records[kind]["dsn"]) for kind in ("collector", "worker"))
    collector_denials = (
        "UPDATE csl.findings SET payload='{}'::jsonb",
        "UPDATE csl.jobs SET status='succeeded'",
        "UPDATE csl.pipeline SET published_generation=generation",
        "UPDATE csl.cases SET current_revision=current_revision+1",
        "INSERT INTO csl.findings DEFAULT VALUES",
        "INSERT INTO csl.case_revisions DEFAULT VALUES",
        "INSERT INTO csl.jobs(job_id,generation,status) VALUES('forged-job',2,'succeeded')",
        "INSERT INTO csl.jobs(job_id,generation,lease_until) "
        "VALUES('forged-job',2,clock_timestamp())",
        "INSERT INTO csl.raw_objects(source_kind) VALUES('synthetic')",
        "INSERT INTO csl.raw_objects(authenticated) VALUES(false)",
        "INSERT INTO csl.raw_objects(parser_version) VALUES('1.0.0')",
    )
    worker_denials = (
        "INSERT INTO csl.raw_objects DEFAULT VALUES",
        "INSERT INTO csl.events DEFAULT VALUES",
        "INSERT INTO csl.batches DEFAULT VALUES",
        "INSERT INTO csl.ingestion_errors DEFAULT VALUES",
        "UPDATE csl.pipeline SET generation=generation+1",
        "UPDATE csl.findings SET payload='{}'::jsonb",
        "UPDATE csl.case_revisions SET payload='{}'::jsonb",
        "INSERT INTO csl.outbox(acknowledged_at) VALUES(clock_timestamp())",
        "INSERT INTO csl.outbox(claim_token) VALUES('forged-claim')",
        "INSERT INTO csl.case_revisions(created_at) VALUES(clock_timestamp())",
    )
    for statement in collector_denials:
        denied(collector, statement)
    for statement in worker_denials:
        denied(worker, statement)


def test_restricted_collector_persists_nul_quarantine_without_batch_or_checkpoint(pipeline):
    db, _, runtime, _ = pipeline
    before = snapshot(db)
    record = event("nul-rejected")
    record["futureField"] = "private\x00synthetic"
    with pytest.raises(EvidenceError, match="NUL_CHARACTER"):
        ingest(
            runtime["collector"],
            [("synthetic/nul.gz", archive([record]))],
            checkpoint="nul-private",
        )
    after = snapshot(db)
    assert {k: v for k, v in after.items() if k != "ingestion_errors"} == {
        k: v for k, v in before.items() if k != "ingestion_errors"
    }
    assert one(db, "SELECT code,checkpoint,status FROM csl.ingestion_errors") == {
        "code": "NUL_CHARACTER",
        "checkpoint": sha256(b"nul-private").hexdigest(),
        "status": "quarantined",
    }
    assert work_once(runtime["worker"])["status"] == "idle"


def test_private_config_kind_label_cannot_promote_owner_or_another_pipeline_identity(
    pipeline, tmp_path
):
    from cloudsecops_live.pipeline_roles import load_pipeline_config
    from cloudsecops_live.workspace_config import write_private_json

    db, records, _, _ = pipeline
    for index, forged in enumerate(
        (
            {**records["collector"], "kind": "worker"},
            {**records["worker"], "kind": "collector"},
            {**records["collector"], "dsn": make_conninfo(**db._values)},
            {**records["collector"], "pipeline_id": records["worker"]["pipeline_id"]},
        )
    ):
        path = tmp_path / f"forged-{index}.json"
        write_private_json(path, forged)
        with pytest.raises(EvidenceError):
            rejected = load_pipeline_config(path, forged["kind"])
            with rejected.connect() as conn:
                conn.execute("SELECT 1")


def test_pipeline_revalidates_live_disable_foreign_membership_and_catalog_privileges(pipeline):
    from cloudsecops_live.pipeline_roles import disable_pipeline

    db, records, runtime, _ = pipeline
    collector = runtime["collector"]
    role = sql.Identifier(Database(records["collector"]["dsn"])._values["user"])
    with db.connect() as conn:
        conn.execute(sql.SQL("GRANT csl_ws_reviews TO {} WITH ADMIN FALSE").format(role))
    try:
        with pytest.raises(EvidenceError):
            with collector.connect() as conn:
                conn.execute("SELECT 1")
    finally:
        with db.connect() as conn:
            conn.execute(sql.SQL("REVOKE csl_ws_reviews FROM {}").format(role))
    with db.connect() as conn:
        conn.execute("CREATE SCHEMA pipeline_scope_drift")
        conn.execute("CREATE TABLE pipeline_scope_drift.private_data(secret_value text)")
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA pipeline_scope_drift TO {}").format(role))
        conn.execute(
            sql.SQL("GRANT SELECT ON pipeline_scope_drift.private_data TO {}").format(role)
        )
    try:
        with pytest.raises(EvidenceError):
            with collector.connect() as conn:
                conn.execute("SELECT 1")
    finally:
        with db.connect() as conn:
            conn.execute(
                sql.SQL("REVOKE SELECT ON pipeline_scope_drift.private_data FROM {}").format(role)
            )
            conn.execute(
                sql.SQL("REVOKE USAGE ON SCHEMA pipeline_scope_drift FROM {}").format(role)
            )
            conn.execute("DROP TABLE pipeline_scope_drift.private_data")
            conn.execute("DROP SCHEMA pipeline_scope_drift")
    with collector.connect() as conn:
        assert conn.execute("SELECT 1 AS n").fetchone()["n"] == 1
    disable_pipeline(db, records["collector"]["pipeline_id"])
    with pytest.raises((EvidenceError, psycopg.Error)):
        with collector.connect() as conn:
            conn.execute("SELECT 1")
    with runtime["worker"].connect() as conn:
        assert conn.execute("SELECT 1 AS n").fetchone()["n"] == 1


def test_protected_restore_reconstructs_pipeline_roles_and_preserves_originals(
    pipeline, db_factory, tmp_path
):
    from cloudsecops_live.pipeline_roles import load_pipeline_config
    from cloudsecops_live.workspace_config import write_private_json
    from cloudsecops_live.workspace_roles import restore_security

    source, records, _, _ = pipeline
    publish(pipeline)
    before = snapshot(source)
    dump = pg_command(source, "pg_dump", ["--format=custom", "--no-owner", "--no-privileges"])
    restored = db_factory(migrate=False)
    pg_command(restored, "pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error"], dump)
    assert snapshot(restored) == before
    destinations = {}
    for kind, record in records.items():
        original = Database(record["dsn"])
        value = {
            **record,
            "dsn": make_conninfo(**{**original._values, "dbname": restored._values["dbname"]}),
        }
        direct = Database(value["dsn"])
        with pytest.raises(psycopg.Error), direct.connect() as conn:
            conn.execute("SELECT 1")
        path = tmp_path / f"restored-{kind}.json"
        write_private_json(path, value)
        destinations[kind] = path
    with pytest.raises(EvidenceError):
        verify_store(restored)
    restore_security(restored)
    assert verify_store(restored)["verified"] is True
    assert snapshot(restored) == before
    collector = load_pipeline_config(destinations["collector"], "collector")
    worker = load_pipeline_config(destinations["worker"], "worker")
    assert (
        ingest(
            collector,
            [("synthetic/recovered.gz", archive([event("p10", 10)]))],
            checkpoint="recovered",
        )["accepted"]
        == 1
    )
    assert work_once(worker)["status"] == "succeeded"
    assert current(restored)[0]["payload"]["evidence_event_ids"] == ["p0", "p10", "p20", "p40"]
    denied(collector, "SELECT * FROM csl.ws_users")
    denied(worker, "INSERT INTO csl.ws_verifications DEFAULT VALUES")
    assert snapshot(source) == before


def test_normal_cli_uses_restricted_private_pair_and_owner_requires_explicit_maintenance(
    pipeline, tmp_path, capsys
):
    import json

    from cloudsecops_live.cli import main
    from cloudsecops_live.workspace_config import write_private_json

    db, records, _, paths = pipeline
    owner = tmp_path / "forged-owner-worker.json"
    write_private_json(owner, {**records["worker"], "dsn": make_conninfo(**db._values)})
    assert main(["db-work", "--config", str(owner)]) == 2
    denied_output = capsys.readouterr()
    assert not denied_output.out
    assert "postgresql://" not in denied_output.err
    assert make_conninfo(**db._values) not in denied_output.err
    assert one(db, "SELECT count(*) AS n FROM csl.jobs")["n"] == 0
    fixture = tmp_path / "synthetic-pipeline.json.gz"
    fixture.write_bytes(batch())
    assert (
        main(
            [
                "db-ingest",
                str(fixture),
                "--checkpoint",
                "restricted-cli",
                "--config",
                str(paths["collector"]),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["accepted"] == 3
    assert main(["db-work", "--config", str(paths["worker"])]) == 0
    assert json.loads(capsys.readouterr().out)["operations"][0]["status"] == "succeeded"
    assert main(["db-cases", "--config", str(paths["worker"])]) == 0
    assert json.loads(capsys.readouterr().out)["cases"][0]["payload"]["evidence_event_ids"] == [
        "p0",
        "p20",
        "p40",
    ]
    assert main(["db-verify", "--config", str(paths["worker"])]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert main(["db-deliver", "--config", str(paths["worker"])]) == 0
    assert json.loads(capsys.readouterr().out)["operations"][0]["status"] == "locally_acknowledged"
    assert main(["db-migrate", "--config", str(owner)]) == 64
    assert not capsys.readouterr().out
    maintenance = tmp_path / "maintenance-only.json"
    write_private_json(maintenance, {"dsn": make_conninfo(**db._values)})
    assert main(["db-migrate", "--maintenance", "--config", str(maintenance)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "migrated"
    for kind in ("collector", "worker"):
        assert records[kind]["dsn"] not in denied_output.err


def test_pipeline_login_cannot_connect_to_an_independent_database_dataset(pipeline, db_factory):
    source, records, _, _ = pipeline
    publish(pipeline)
    independent = db_factory()
    source_before, target_before = snapshot(source), snapshot(independent)
    source_id = one(source, "SELECT database_id FROM csl.schema_migrations WHERE version=2")
    target_id = one(independent, "SELECT database_id FROM csl.schema_migrations WHERE version=2")
    assert source_id != target_id
    for record in records.values():
        original = Database(record["dsn"])
        redirected = Database(
            make_conninfo(**{**original._values, "dbname": independent._values["dbname"]})
        )
        # This deliberately uses raw Database, bypassing the Python identity
        # wrapper: PostgreSQL CONNECT itself must enforce independent datasets.
        with pytest.raises(psycopg.OperationalError) as denied_connection:
            with redirected.connect() as conn:
                conn.execute("SELECT archive_bytes FROM csl.raw_objects")
        # libpq startup failures may omit SQLSTATE, so also require PostgreSQL's
        # specific CONNECT-privilege detail; a network/authentication outage is
        # insufficient evidence. Keep the private driver text out of reports.
        assert denied_connection.value.sqlstate in (None, "42501")
        rejected_connect_privilege = "CONNECT privilege" in str(denied_connection.value)
        assert rejected_connect_privilege, "An independent dataset must deny CONNECT itself"
    assert snapshot(source) == source_before
    assert snapshot(independent) == target_before
