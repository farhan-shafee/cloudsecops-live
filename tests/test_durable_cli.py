"""The durable CLI fails closed without echoing private connection material."""

import json

from cloudsecops_live.cli import main


def test_missing_private_config_fails_without_success(capsys, tmp_path) -> None:
    assert main(["db-status", "--config", str(tmp_path / "private-secret.json")]) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert json.loads(captured.err)["error"]["code"] == "INVALID_DATABASE_CONFIG"
    assert "private-secret" not in captured.err


def test_invalid_worker_bound_is_usage_failure(capsys) -> None:
    assert main(["db-work", "--limit", "65"]) == 64
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "USAGE"


def test_migrate_receipt_reports_current_schema_only_after_success(monkeypatch, capsys) -> None:
    from cloudsecops_live import durable_cli
    from cloudsecops_live.errors import EvidenceError

    class SuccessfulMigration:
        def migrate(self):
            pass

    monkeypatch.setattr(durable_cli, "_database", lambda path: SuccessfulMigration())
    assert main(["db-migrate"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == 2
    assert result["status"] == "migrated"

    class RejectedMigration:
        def migrate(self):
            raise EvidenceError("SCHEMA_INCOMPATIBLE")

    monkeypatch.setattr(durable_cli, "_database", lambda path: RejectedMigration())
    assert main(["db-migrate"]) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert json.loads(captured.err)["error"]["code"] == "SCHEMA_INCOMPATIBLE"
