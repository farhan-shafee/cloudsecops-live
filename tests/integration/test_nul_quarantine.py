"""Real PostgreSQL NUL rejection preserves the entire preexisting durable store."""

from __future__ import annotations

import gzip
import json
from hashlib import sha256
from pathlib import Path

import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.cli import main
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.outbox import deliver_once
from cloudsecops_live.storage import ingest, verify_store
from cloudsecops_live.worker import work_once
from tests.helpers import archive, event

# Explicit inventory catches a missing/new table rather than silently narrowing the oracle.
TABLES = (
    "schema_migrations",
    "pipeline",
    "batches",
    "checkpoints",
    "raw_objects",
    "events",
    "record_variants",
    "raw_deliveries",
    "source_references",
    "conflicts",
    "ingestion_errors",
    "jobs",
    "job_attempts",
    "findings",
    "finding_evidence",
    "cases",
    "case_revisions",
    "case_timeline",
    "case_lineage",
    "outbox",
    "offline_sink",
    "audit",
    "ws_users",
    "ws_sessions",
    "ws_csrf",
    "ws_preauth",
    "ws_throttle",
    "ws_case_grants",
    "ws_notes",
)


def snapshot(db):
    with db.connect() as conn:
        found = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='csl' ORDER BY tablename"
        ).fetchall()
        assert {row["tablename"] for row in found} == set(TABLES)
        return {
            table: conn.execute(
                sql.SQL(
                    "SELECT row_to_json(t)::text AS row FROM csl.{} t ORDER BY row_to_json(t)::text"
                ).format(sql.Identifier(table))
            ).fetchall()
            for table in TABLES
        }


def populate_demo(db):
    fixture = Path(__file__).resolve().parents[2] / "fixtures/synthetic/inventory-burst.json.gz"
    result = ingest(db, [(fixture.name, fixture.read_bytes())], checkpoint="existing-demo")
    assert result["accepted"] > 0
    assert work_once(db)["status"] == "succeeded"
    assert deliver_once(db)["status"] == "locally_acknowledged"
    state = snapshot(db)
    assert all(state[table] for table in ("events", "cases", "findings", "jobs", "offline_sink"))


def bad_record(location):
    row = event("private-rejected-event")
    if location in ("eventSource", "eventName", "eventCategory", "eventType"):
        row[location] += "\x00private-payload"
    elif location == "issuer-path":
        row["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
            "arn:aws:iam::LABACCOUNT_A:role/private\x00path/InventoryLab"
        )
    elif location == "unknown-value":
        row["privateFutureField"] = {"leaf": ["private\x00payload"]}
    elif location == "unknown-key":
        row["privateFutureField"] = {"private\x00key": None}
    else:
        raise AssertionError(location)
    return row


def assert_only_quarantine_changed(db, before, checkpoint, reason="NUL_CHARACTER"):
    after = snapshot(db)
    assert {k: v for k, v in after.items() if k != "ingestion_errors"} == {
        k: v for k, v in before.items() if k != "ingestion_errors"
    }
    assert len(after["ingestion_errors"]) == len(before["ingestion_errors"]) + 1
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM csl.ingestion_errors WHERE checkpoint=%s",
            (sha256(checkpoint.encode()).hexdigest(),),
        ).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["checkpoint"] == sha256(checkpoint.encode()).hexdigest()
    assert row["code"] == reason
    assert row["status"] == "quarantined"
    assert set(row) == {"error_id", "checkpoint", "code", "status", "created_at"}
    assert "private" not in str(row)


@pytest.mark.parametrize("populated", [False, True], ids=["clean", "populated-demo"])
@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_nul_batches_quarantine_without_any_partial_or_existing_state_change(
    db, tmp_path, capsys, populated, entrypoint
):
    if populated:
        populate_demo(db)
    config = tmp_path / "database.json"
    config.write_text(json.dumps({"dsn": make_conninfo(**db._values)}), encoding="utf-8")
    for location in (
        "eventSource",
        "eventName",
        "eventCategory",
        "eventType",
        "issuer-path",
        "unknown-value",
        "unknown-key",
    ):
        for shape in ("two-files", "two-records"):
            checkpoint = f"private-{entrypoint}-{location}-{shape}"
            good = event("private-valid-first")
            bad = bad_record(location)
            sources = (
                [("private-good.json.gz", archive([good])), ("private-bad.json.gz", archive([bad]))]
                if shape == "two-files"
                else [("private-bad.json.gz", archive([good, bad]))]
            )
            before = snapshot(db)
            if entrypoint == "api":
                with pytest.raises(EvidenceError) as rejected:
                    ingest(db, sources, checkpoint=checkpoint)
                assert rejected.value.code == "NUL_CHARACTER"
            else:
                paths = []
                for label, data in sources:
                    path = tmp_path / label
                    path.write_bytes(data)
                    paths.append(str(path))
                assert (
                    main(["db-ingest", "--config", str(config), "--checkpoint", checkpoint, *paths])
                    == 2
                )
                output = capsys.readouterr()
                assert output.out == ""
                assert json.loads(output.err) == {
                    "error": {
                        "code": "NUL_CHARACTER",
                        "message": "Operation rejected; no partial result was emitted.",
                    },
                    "source_kind": "synthetic",
                    "authenticated": False,
                }
                assert "private" not in output.err
            assert_only_quarantine_changed(db, before, checkpoint)


@pytest.mark.parametrize("entrypoint", ["api", "cli"])
@pytest.mark.parametrize(
    "replacement,source_reason,quarantine_reason",
    [(b"\x00", "INVALID_JSON", "INVALID_JSON"), (b"\xc0\x80", "INVALID_UTF8", "INVALID_UNICODE")],
)
def test_invalid_encoding_preserves_source_reason_and_safe_quarantine_code(
    db, tmp_path, capsys, entrypoint, replacement, source_reason, quarantine_reason
):
    plain = (
        json.dumps(
            {
                "fixture_schema_version": "1.0",
                "source_kind": "synthetic",
                "Records": [bad_record("unknown-value")],
            }
        )
        .encode()
        .replace(b"\\u0000", replacement)
    )
    before = snapshot(db)
    checkpoint = "private-invalid-encoding"
    payload = gzip.compress(plain, mtime=0)
    if entrypoint == "api":
        with pytest.raises(EvidenceError) as rejected:
            ingest(db, [("private-source.json.gz", payload)], checkpoint=checkpoint)
        assert rejected.value.code == source_reason
    else:
        config = tmp_path / "database.json"
        config.write_text(json.dumps({"dsn": make_conninfo(**db._values)}), encoding="utf-8")
        source = tmp_path / "private-source.json.gz"
        source.write_bytes(payload)
        assert (
            main(["db-ingest", "--config", str(config), "--checkpoint", checkpoint, str(source)])
            == 2
        )
        output = capsys.readouterr()
        assert output.out == ""
        assert json.loads(output.err)["error"]["code"] == source_reason
        assert "private" not in output.err
    assert_only_quarantine_changed(db, before, checkpoint, quarantine_reason)


def test_legitimate_escaped_literal_zero_null_and_non_bmp_round_trip_postgresql(db):
    row = event("legitimate")
    row["eventName"] = r"literal\u0000" + "\U0001f642\t\n"
    row["futureField"] = {r"literal\u0000": [r"\u0000", 0, None, "\U0001f642"]}
    payload = archive([row])
    assert ingest(db, [("legitimate.json.gz", payload)], checkpoint="legitimate")["accepted"] == 1
    assert verify_store(db)["verified"] is True
    with db.connect() as conn:
        raw = conn.execute("SELECT archive_bytes FROM csl.raw_objects").fetchone()
        variant = conn.execute(
            "SELECT canonical_bytes,normalized FROM csl.record_variants"
        ).fetchone()
    assert bytes(raw["archive_bytes"]) == payload
    assert json.loads(bytes(variant["canonical_bytes"]))["futureField"] == row["futureField"]
    assert variant["normalized"]["event_name"] == row["eventName"]


@pytest.mark.parametrize("populated", [False, True], ids=["clean", "populated-demo"])
def test_controlled_nul_reason_before_commit_rolls_back_real_staged_transaction(db, populated):
    """A controlled fault tests SQL rollback separately from source prevalidation."""
    if populated:
        populate_demo(db)
    before = snapshot(db)
    reached = []

    def fail_before_commit(point):
        reached.append(point)
        if point == "before_ingest_commit":
            raise EvidenceError("NUL_CHARACTER")

    checkpoint = "private-controlled-transaction-rollback"
    with pytest.raises(EvidenceError) as rejected:
        ingest(
            db,
            [("private-valid-source.json.gz", archive([event("controlled-valid")]))],
            checkpoint=checkpoint,
            fault=fail_before_commit,
        )
    assert rejected.value.code == "NUL_CHARACTER"
    assert reached == ["before_ingest_commit"]
    assert_only_quarantine_changed(db, before, checkpoint)


@pytest.mark.parametrize("legacy_field", ["unknownFutureField", "errorMessage"])
def test_legacy_nul_original_is_preserved_and_replay_fails_closed(db, monkeypatch, legacy_field):
    """Simulate old acceptance only during setup; all replay uses the current guard."""
    import cloudsecops_live.ingestion as parser

    row = event("legacy-nul")
    row[legacy_field] = "private-legacy\x00payload"
    payload = archive([row])
    expected_canonical = json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    # These two fields were bytea-only under the prior parser. This is the sole
    # controlled legacy-fixture bypass; PostgreSQL and ingest are never mocked.
    with monkeypatch.context() as legacy:
        legacy.setattr(parser, "_check_tree", lambda _value, _limits: None)
        assert (
            ingest(db, [("legacy.json.gz", payload)], checkpoint="legacy-original")["accepted"] == 1
        )
    with db.connect() as conn:
        original = conn.execute("SELECT * FROM csl.raw_objects").fetchone()
        variant = conn.execute("SELECT * FROM csl.record_variants").fetchone()
    assert bytes(original["archive_bytes"]) == payload
    assert original["archive_hash"] == sha256(payload).hexdigest()
    assert original["content_hash"] == sha256(gzip.decompress(payload)).hexdigest()
    assert bytes(variant["canonical_bytes"]) == expected_canonical
    assert variant["record_hash"] == sha256(expected_canonical).hexdigest()
    assert original["parser_version"] == variant["parser_version"] == "1.0.0"
    before = snapshot(db)
    with pytest.raises(EvidenceError) as rejected:
        verify_store(db)
    assert rejected.value.code == "NUL_CHARACTER"
    assert snapshot(db) == before
    checkpoint = "private-new-ingestion-blocked-by-legacy"
    with pytest.raises(EvidenceError) as rejected:
        ingest(
            db,
            [("private-new-valid.json.gz", archive([event("new-valid")]))],
            checkpoint=checkpoint,
        )
    assert rejected.value.code == "NUL_CHARACTER"
    assert_only_quarantine_changed(db, before, checkpoint)
