"""CLI preload rejection must retain bounded failure metadata."""

import json

from psycopg.conninfo import make_conninfo

from cloudsecops_live.cli import main


def test_cli_malformed_source_is_durably_quarantined_without_partial_evidence(db, tmp_path):
    config = tmp_path / "db.json"
    config.write_text(json.dumps({"dsn": make_conninfo(**db._values)}), encoding="utf-8")
    source = tmp_path / "malformed.json.gz"
    source.write_bytes(b"bad-gzip")
    assert main(["db-ingest", "--config", str(config), "--checkpoint", "bad", str(source)]) == 2
    with db.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM csl.raw_objects").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM csl.checkpoints").fetchone()["n"] == 0
        errors = conn.execute("SELECT status FROM csl.ingestion_errors").fetchall()
    assert errors == [{"status": "quarantined"}]
