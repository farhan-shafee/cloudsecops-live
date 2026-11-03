"""Exercise the real persistence CLI boundary and its fixed failure receipts."""

from __future__ import annotations

import json
import socket

from psycopg.conninfo import make_conninfo

from cloudsecops_live.cli import main
from tests.helpers import archive, event
from tests.integration.support import add, one


def config_for(db, directory):
    path = directory / "database.json"
    path.write_text(json.dumps({"dsn": make_conninfo(**db._values)}), encoding="utf-8")
    return str(path)


def test_cli_durable_pipeline_commits_then_reports_pending_and_local_delivery(db, tmp_path, capsys):
    config = config_for(db, tmp_path)
    fixture = tmp_path / "synthetic.json.gz"
    fixture.write_bytes(archive([event("e0"), event("e20", 20), event("e40", 40)]))
    assert main(["db-migrate", "--config", config]) == 0
    capsys.readouterr()
    assert main(["db-ingest", str(fixture), "--config", config, "--checkpoint", "cli"]) == 0
    ingested = json.loads(capsys.readouterr().out)
    assert ingested["accepted"] == 3
    assert "committed" in ingested["acknowledgment"]
    assert main(["db-status", "--config", config]) == 0
    assert json.loads(capsys.readouterr().out)["pending"] is True
    assert main(["db-work", "--config", config]) == 0
    assert json.loads(capsys.readouterr().out)["operations"][0]["status"] == "succeeded"
    assert main(["db-cases", "--config", config]) == 0
    cases = json.loads(capsys.readouterr().out)["cases"]
    assert cases[0]["payload"]["evidence_event_ids"] == ["e0", "e20", "e40"]
    assert main(["db-deliver", "--config", config]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["operations"][0]["status"] == "locally_acknowledged"
    assert receipt["operations"][0]["searchable_siem_alert"] is False
    assert main(["db-verify", "--config", config]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_cli_database_failure_is_nonzero_and_does_not_expose_dsn(db, tmp_path, capsys):
    # Reserve an unused port so no unrelated local service is contacted.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        path = tmp_path / "unavailable.json"
        path.write_text(
            json.dumps(
                {"dsn": make_conninfo(**{**db._values, "port": str(port), "connect_timeout": "1"})}
            ),
            encoding="utf-8",
        )
        assert main(["db-status", "--config", str(path)]) == 75
    output = capsys.readouterr()
    assert output.out == ""
    assert "DATABASE_OPERATION_FAILED" in output.err
    assert db._values.get("password", "password-never-present") not in output.err
    assert "postgresql://" not in output.err


def test_cli_active_work_never_reports_completed_pipeline(db, tmp_path, capsys):
    from cloudsecops_live.worker import claim_job

    add(db, [0, 20, 40])
    assert claim_job(db) is not None
    config = config_for(db, tmp_path)
    assert main(["db-work", "--config", config]) == 75
    result = json.loads(capsys.readouterr().out)
    assert result["pending"] is True
    assert result["operations"][0]["status"] == "idle"
    assert one(db, "SELECT count(*) AS n FROM csl.case_revisions")["n"] == 0
