"""Storage expectations are explicit and independent of detector output."""

from __future__ import annotations

import gzip
from collections.abc import Callable

import psycopg
import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import ingest, load_logs, verify_store
from tests.helpers import archive, event
from tests.integration.support import explode_fault, one


def test_idempotent_checkpoint_retains_exact_receipt(db: Database) -> None:
    sources = [("first.gz", archive([event("a")]))]
    initial = ingest(db, sources, checkpoint="checkpoint")
    assert initial["accepted"] == 1
    assert initial["generation"] == 1
    assert ingest(db, sources, checkpoint="checkpoint") == initial
    assert one(db, "SELECT count(*) AS n FROM csl.source_references")["n"] == 1
    assert one(db, "SELECT count(*) AS n FROM csl.jobs")["n"] == 1
    with pytest.raises(EvidenceError, match="CHECKPOINT_CONFLICT"):
        ingest(db, [("first.gz", archive([event("b")]))], checkpoint="checkpoint")


def test_equivalent_gzip_retains_delivery_without_new_generation(db: Database) -> None:
    first = archive([event("a")])
    second = gzip.compress(gzip.decompress(first), mtime=123)
    ingest(db, [("same.gz", first)], checkpoint="first")
    result = ingest(db, [("same.gz", second)], checkpoint="second")
    assert result["accepted"] == 0
    assert result["duplicates"] == 1
    assert result["generation"] == 1
    with db.connect() as conn:
        logs = load_logs(conn)
    assert len(logs) == 2
    assert sum(len(e.references) for log in logs for e in log.events) == 2
    assert verify_store(db)["record_variants"] == 1


def test_same_archive_multiple_names_preserves_references(db: Database) -> None:
    data = archive([event("a")])
    result = ingest(db, [("one.gz", data), ("two.gz", data)], checkpoint="two-labels")
    assert result["accepted"] == 1
    assert result["duplicates"] == 1
    assert verify_store(db)["raw_objects"] == 1
    with db.connect() as conn:
        logs = load_logs(conn)
    assert {r.source_ref for r in logs[0].events[0].references} == {"one.gz", "two.gz"}


def test_unknown_field_conflict_is_retained(db: Database) -> None:
    ingest(db, [("one.gz", archive([event("a")]))], checkpoint="one")
    changed = event("a")
    changed["unknownFutureField"] = {"different": True}
    result = ingest(db, [("two.gz", archive([changed]))], checkpoint="two")
    assert result["conflicting"] == 1
    assert result["generation"] == 2
    assert verify_store(db)["record_variants"] == 2
    assert one(db, "SELECT count(*) AS n FROM csl.conflicts")["n"] == 1


def test_malformed_batch_has_no_partial_evidence(db: Database) -> None:
    with pytest.raises(EvidenceError, match="INVALID_GZIP"):
        ingest(db, [("good.gz", archive([event("a")])), ("bad.gz", b"bad")], checkpoint="bad")
    assert verify_store(db)["raw_objects"] == 0
    assert one(db, "SELECT count(*) AS n FROM csl.batches")["n"] == 0
    assert one(db, "SELECT count(*) AS n FROM csl.jobs")["n"] == 0


@pytest.mark.parametrize(
    "point,committed", [("before_ingest_commit", False), ("after_ingest_commit", True)]
)
def test_ingest_commit_boundaries(db: Database, point: str, committed: bool) -> None:
    with pytest.raises(RuntimeError, match="controlled_test_fault"):
        ingest(
            db, [("a.gz", archive([event("a")]))], checkpoint="fault", fault=explode_fault(point)
        )
    assert verify_store(db)["raw_objects"] == int(committed)
    assert one(db, "SELECT count(*) AS n FROM csl.checkpoints")["n"] == int(committed)
    assert one(db, "SELECT count(*) AS n FROM csl.jobs")["n"] == int(committed)


def test_raw_object_limit_rollback(db: Database) -> None:
    data = archive([event("a")])
    plain = gzip.decompress(data)
    sources = [(f"{i}.gz", gzip.compress(plain, mtime=i)) for i in range(64)]
    ingest(db, sources, checkpoint="full")
    with pytest.raises(EvidenceError, match="STORE_LIMIT"):
        ingest(db, [("extra.gz", gzip.compress(plain, mtime=100))], checkpoint="overflow")
    assert verify_store(db)["raw_objects"] == 64
    assert one(db, "SELECT count(*) AS n FROM csl.checkpoints")["n"] == 1


def test_missing_schema_refuses_operations(db_factory: Callable[..., Database]) -> None:
    db = db_factory(migrate=False)
    with pytest.raises(EvidenceError, match="SCHEMA_MISSING"):
        ingest(db, [("a.gz", archive([event("a")]))], checkpoint="missing")
    db.migrate()
    db.migrate()
    assert verify_store(db)["verified"] is True


@pytest.mark.parametrize(
    "tamper",
    [
        "ALTER TABLE csl.raw_objects DROP CONSTRAINT raw_objects_record_count_check",
        "ALTER TABLE csl.raw_objects DISABLE TRIGGER immutable_history",
        "ALTER TABLE csl.events ADD COLUMN unsupported text",
    ],
)
def test_incompatible_schema_refused(db: Database, tamper: str) -> None:
    with db.connect() as conn:
        conn.execute(tamper)
    with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
        db.migrate()


def test_preexisting_unknown_schema_not_adopted(db_factory: Callable[..., Database]) -> None:
    db = db_factory(migrate=False)
    with db.connect() as conn:
        conn.execute("CREATE SCHEMA csl")
    with pytest.raises(EvidenceError, match="SCHEMA_MISSING"):
        db.migrate()
    with db.connect() as conn:
        assert (
            conn.execute("SELECT count(*) AS n FROM pg_tables WHERE schemaname='csl'").fetchone()[
                "n"
            ]
            == 0
        )


@pytest.mark.parametrize(
    "query",
    [
        "UPDATE csl.raw_objects SET source_ref='changed'",
        "DELETE FROM csl.raw_objects",
        "UPDATE csl.record_variants SET canonical_bytes='evil'::bytea",
        "DELETE FROM csl.source_references",
    ],
)
def test_normal_sql_cannot_modify_immutable_evidence(db: Database, query: str) -> None:
    ingest(db, [("a.gz", archive([event("a")]))], checkpoint="initial")
    with pytest.raises(psycopg.Error):
        with db.connect() as conn:
            conn.execute(query)
    assert verify_store(db)["verified"] is True


def test_restore_validation_rejects_corrupted_source_hash(db: Database) -> None:
    ingest(db, [("a.gz", archive([event("a")]))], checkpoint="initial")
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.raw_objects DISABLE TRIGGER immutable_history")
        conn.execute("UPDATE csl.raw_objects SET content_hash=repeat('0',64)")
        conn.execute("ALTER TABLE csl.raw_objects ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="RAW_EVIDENCE_MISMATCH"):
        verify_store(db)


def test_restore_validation_rejects_missing_delivery(db: Database) -> None:
    ingest(db, [("a.gz", archive([event("a")]))], checkpoint="initial")
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.source_references DISABLE TRIGGER immutable_history")
        conn.execute("DELETE FROM csl.source_references")
        conn.execute("ALTER TABLE csl.source_references ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="SOURCE_REFERENCE_MISMATCH"):
        verify_store(db)


def test_migration_sql_failure_rolls_back_whole_schema(
    db_factory: Callable[..., Database], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import cloudsecops_live.database as module

    db = db_factory(migrate=False)
    broken = tmp_path / "broken.sql"
    broken.write_text("CREATE SCHEMA csl; CREATE TABLE csl.partial(n int); SELECT missing_func();")
    monkeypatch.setattr(module, "_MIGRATION", broken)
    with pytest.raises(psycopg.Error):
        db.migrate()
    with db.connect() as conn:
        assert conn.execute("SELECT to_regnamespace('csl') AS found").fetchone()["found"] is None


@pytest.mark.parametrize(
    "tamper",
    [
        "DELETE FROM csl.schema_migrations",
        "UPDATE csl.schema_migrations SET checksum=repeat('0',64)",
    ],
)
def test_stale_or_tampered_migration_ledger_fails_closed(db: Database, tamper: str) -> None:
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.schema_migrations DISABLE TRIGGER immutable_history")
        conn.execute(tamper)
        conn.execute("ALTER TABLE csl.schema_migrations ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="SCHEMA_INCOMPATIBLE"):
        verify_store(db)


def test_normalized_derivative_corruption_fails_recovery(db: Database) -> None:
    ingest(db, [("a.gz", archive([event("a")]))], checkpoint="initial")
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.record_variants DISABLE TRIGGER immutable_history")
        conn.execute(
            "UPDATE csl.record_variants SET normalized=jsonb_set(normalized,"
            "'{event_name}', '\"tampered\"'::jsonb)"
        )
        conn.execute("ALTER TABLE csl.record_variants ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="NORMALIZED_EVIDENCE_MISMATCH"):
        verify_store(db)


def test_recordless_sources_cannot_make_unbounded_batches(
    db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cloudsecops_live.storage as module

    monkeypatch.setattr(module, "MAX_BATCHES", 2)
    empty = [("empty.gz", archive([]))]
    first = ingest(db, empty, checkpoint="one")
    ingest(db, empty, checkpoint="two")
    with pytest.raises(EvidenceError, match="STORE_LIMIT"):
        ingest(db, empty, checkpoint="three")
    assert ingest(db, empty, checkpoint="one") == first
    assert verify_store(db)["raw_objects"] == 1
    assert one(db, "SELECT count(*) AS n FROM csl.batches")["n"] == 2
    assert one(db, "SELECT count(*) AS n FROM csl.ingestion_errors")["n"] == 1


def test_quarantine_never_stores_input_or_checkpoint_text(db: Database) -> None:
    with pytest.raises(EvidenceError, match="INVALID_GZIP"):
        ingest(
            db,
            [("private-source-label.gz", b"private-source-bytes")],
            checkpoint="private-checkpoint-label",
        )
    row = one(db, "SELECT * FROM csl.ingestion_errors")
    assert row["status"] == "quarantined"
    assert row["code"] == "INVALID_GZIP"
    assert len(row["checkpoint"]) == 64
    assert "private" not in str(row)


def test_recordless_original_missing_fails_recovery(db: Database) -> None:
    ingest(db, [("empty.gz", archive([]))], checkpoint="empty")
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.raw_deliveries DISABLE TRIGGER immutable_history")
        conn.execute("DELETE FROM csl.raw_deliveries")
        conn.execute("ALTER TABLE csl.raw_deliveries ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="RAW_DELIVERY_MISMATCH"):
        verify_store(db)


def test_recovery_rejects_removed_bridge_lineage(db: Database) -> None:
    from cloudsecops_live.worker import work_once
    from tests.integration.support import add

    add(db, [0, 20, 40])
    work_once(db)
    add(db, [100, 120, 140], "separate")
    work_once(db)
    add(db, [70], "bridge")
    work_once(db)
    assert one(db, "SELECT count(*) AS n FROM csl.case_lineage")["n"] == 2
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.case_lineage DISABLE TRIGGER immutable_history")
        conn.execute("DELETE FROM csl.case_lineage")
        conn.execute("ALTER TABLE csl.case_lineage ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="CASE_LINEAGE_MISMATCH"):
        verify_store(db)


def test_recovery_rejects_removed_complete_current_case_subtree(db: Database) -> None:
    from cloudsecops_live.worker import work_once
    from tests.integration.support import add

    add(db, [0, 20, 40])
    work_once(db)
    assert one(db, "SELECT count(*) AS n FROM csl.findings WHERE status='current'")["n"] == 1
    assert one(db, "SELECT count(*) AS n FROM csl.cases WHERE status='current'")["n"] == 1
    with db.connect() as conn:
        for table in ("outbox", "case_timeline", "case_revisions"):
            conn.execute(
                f"ALTER TABLE csl.{table} DISABLE TRIGGER immutable_history"
                if table != "outbox"
                else "ALTER TABLE csl.outbox DISABLE TRIGGER immutable_outbox"
            )
        for table in ("outbox", "case_timeline", "case_revisions"):
            conn.execute(f"DELETE FROM csl.{table}")
        conn.execute("DELETE FROM csl.cases")
        conn.execute("SET CONSTRAINTS ALL IMMEDIATE")
        for table in ("outbox", "case_timeline", "case_revisions"):
            conn.execute(
                f"ALTER TABLE csl.{table} ENABLE TRIGGER immutable_history"
                if table != "outbox"
                else "ALTER TABLE csl.outbox ENABLE TRIGGER immutable_outbox"
            )
    with pytest.raises(EvidenceError, match="CASE_FINDING_COVERAGE_MISMATCH"):
        verify_store(db)


def test_recovery_rejects_consistently_rehashed_false_event_timeline(db: Database) -> None:
    from psycopg.types.json import Jsonb

    from cloudsecops_live.cases import evidence_fingerprint
    from cloudsecops_live.worker import work_once
    from tests.integration.support import add

    add(db, [0, 20, 40])
    work_once(db)
    payload = one(db, "SELECT payload FROM csl.case_revisions")["payload"]
    assert [item["event_time"] for item in payload["event_timeline"]] == [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:20Z",
        "2026-01-01T00:00:40Z",
    ]
    payload["event_timeline"][0]["event_time"] = "2026-01-01T00:59:59Z"
    fingerprint = evidence_fingerprint(
        {k: v for k, v in payload.items() if k not in {"case_id", "revision", "case_status"}}
    )
    message = one(db, "SELECT payload FROM csl.outbox")["payload"]
    message["evidence_fingerprint"] = fingerprint
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.case_revisions DISABLE TRIGGER immutable_history")
        conn.execute(
            "UPDATE csl.case_revisions SET payload=%s,fingerprint=%s", (Jsonb(payload), fingerprint)
        )
        conn.execute("ALTER TABLE csl.case_revisions ENABLE TRIGGER immutable_history")
        conn.execute("ALTER TABLE csl.case_timeline DISABLE TRIGGER immutable_history")
        conn.execute("UPDATE csl.case_timeline SET payload=%s", (Jsonb(payload),))
        conn.execute("ALTER TABLE csl.case_timeline ENABLE TRIGGER immutable_history")
        conn.execute("ALTER TABLE csl.outbox DISABLE TRIGGER immutable_outbox")
        conn.execute("UPDATE csl.outbox SET payload=%s", (Jsonb(message),))
        conn.execute("ALTER TABLE csl.outbox ENABLE TRIGGER immutable_outbox")
    with pytest.raises(EvidenceError, match="CASE_EVENT_TIMELINE_MISMATCH"):
        verify_store(db)
