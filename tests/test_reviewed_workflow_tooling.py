"""Provisioning output excludes verifier authority and never accepts a verdict flag."""

import json
from unittest.mock import Mock

import pytest

from cloudsecops_live import workspace_cli


def test_explicit_case_scoped_verifier_provisioning_writes_only_private_config(
    tmp_path, monkeypatch, capsys
):
    from cloudsecops_live import workspace_roles

    db = object()
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: db)
    provision = Mock(
        return_value={"dsn": "private-fixture", "verifier_id": "a" * 32, "case_id": "b" * 64}
    )
    monkeypatch.setattr(workspace_roles, "provision_verifier", provision)
    writer = Mock()
    monkeypatch.setattr(workspace_cli, "write_private_json", writer)
    config = tmp_path / "verifier.json"
    assert (
        workspace_cli.main(
            [
                "verifier-add",
                "--maintenance-config",
                "private-maintenance.json",
                "--case-id",
                "b" * 64,
                "--config",
                str(config),
            ]
        )
        == 0
    )
    args = provision.call_args.args
    assert args[0] is db and args[1] == "b" * 64 and len(args[2]) == 64
    assert writer.call_args.args == (config, provision.return_value)
    assert json.loads(capsys.readouterr().out) == {"state": "complete", "command": "verifier-add"}


def test_existing_verifier_config_cannot_be_overwritten_or_reprovisioned(
    tmp_path, monkeypatch, capsys
):
    from cloudsecops_live import workspace_roles

    config = tmp_path / "verifier.json"
    config.write_text("preserved fixture", encoding="utf-8")
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: object())
    provision = Mock()
    monkeypatch.setattr(workspace_roles, "provision_verifier", provision)
    assert (
        workspace_cli.main(
            [
                "verifier-add",
                "--maintenance-config",
                "private",
                "--case-id",
                "b" * 64,
                "--config",
                str(config),
            ]
        )
        == 2
    )
    provision.assert_not_called()
    assert config.read_text(encoding="utf-8") == "preserved fixture"
    assert "preserved" not in capsys.readouterr().err


def test_explicit_verifier_disabling_uses_maintenance_only(monkeypatch, capsys):
    from cloudsecops_live import workspace_roles

    db = object()
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: db)
    disabled = Mock()
    monkeypatch.setattr(workspace_roles, "disable_verifier", disabled)
    assert (
        workspace_cli.main(
            [
                "verifier-disable",
                "--maintenance-config",
                "private",
                "--verifier-id",
                "a" * 32,
            ]
        )
        == 0
    )
    disabled.assert_called_once_with(db, "a" * 32)
    assert "dsn" not in capsys.readouterr().out


def test_verifier_dispatch_keeps_result_flags_out_of_interface(monkeypatch, capsys):
    from cloudsecops_live.cli import main

    assert main(["verifier", "--verified", "sensitive-fixture"]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "sensitive-fixture" not in captured.err


def test_https_demo_cli_does_not_echo_unrecognized_secret_arguments(monkeypatch, capsys):
    import sys

    from scripts import reviewed_workflow_smoke

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo",
            "--workspace-config",
            "private",
            "--verifier-config",
            "private2",
            "--analyst",
            "alice",
            "--reviewer",
            "reviewer",
            "--case-id",
            "b" * 64,
            "--password",
            "sensitive-fixture",
        ],
    )
    assert reviewed_workflow_smoke.main() == 2
    output = capsys.readouterr()
    assert not output.out and "sensitive-fixture" not in output.err


@pytest.mark.parametrize("kind", ["collector", "worker"])
def test_pipeline_provisioning_persists_generated_authority_only_in_private_config(
    tmp_path, monkeypatch, capsys, kind
):
    from cloudsecops_live import pipeline_roles

    db = object()
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: db)
    provision = Mock(
        return_value={"dsn": "private_generated_marker", "pipeline_id": "a" * 32, "kind": kind}
    )
    monkeypatch.setattr(pipeline_roles, "provision_pipeline", provision)
    writer = Mock()
    monkeypatch.setattr(workspace_cli, "write_private_json", writer)
    target = tmp_path / "pipeline.json"
    assert (
        workspace_cli.main(
            [
                "pipeline-add",
                "--maintenance-config",
                "private_maintenance_marker",
                "--kind",
                kind,
                "--config",
                str(target),
            ]
        )
        == 0
    )
    provision.assert_called_once_with(db, kind)
    writer.assert_called_once_with(target, provision.return_value)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"state": "complete", "command": "pipeline-add"}
    assert not captured.err and "private_" not in captured.out


def test_existing_pipeline_config_preserves_bytes_and_never_creates_a_second_identity(
    tmp_path, monkeypatch, capsys
):
    from cloudsecops_live import pipeline_roles

    target = tmp_path / "pipeline.json"
    target.write_bytes(b"preserved_private_marker")
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: object())
    provision = Mock()
    monkeypatch.setattr(pipeline_roles, "provision_pipeline", provision)
    assert (
        workspace_cli.main(
            [
                "pipeline-add",
                "--maintenance-config",
                "private",
                "--kind",
                "worker",
                "--config",
                str(target),
            ]
        )
        == 2
    )
    provision.assert_not_called()
    assert target.read_bytes() == b"preserved_private_marker"
    captured = capsys.readouterr()
    assert not captured.out and captured.err == '{"error":"workspace_operation_failed"}\n'


def test_pipeline_disable_delegates_to_explicit_maintenance_and_prints_no_authority(
    monkeypatch, capsys
):
    from cloudsecops_live import pipeline_roles

    db = object()
    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: db)
    disable = Mock()
    monkeypatch.setattr(pipeline_roles, "disable_pipeline", disable)
    assert (
        workspace_cli.main(
            [
                "pipeline-disable",
                "--maintenance-config",
                "private",
                "--pipeline-id",
                "a" * 32,
            ]
        )
        == 0
    )
    disable.assert_called_once_with(db, "a" * 32)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"state": "complete", "command": "pipeline-disable"}
    assert not captured.err


def test_private_pipeline_file_failure_is_nonzero_redacted_and_never_retried(
    tmp_path, monkeypatch, capsys
):
    from cloudsecops_live import pipeline_roles

    monkeypatch.setattr(workspace_cli, "_maintenance", lambda path: object())
    provision = Mock(
        return_value={"dsn": "private_generated_marker", "pipeline_id": "b" * 32, "kind": "worker"}
    )
    monkeypatch.setattr(pipeline_roles, "provision_pipeline", provision)
    writer = Mock(side_effect=OSError("private_generated_marker"))
    monkeypatch.setattr(workspace_cli, "write_private_json", writer)
    assert (
        workspace_cli.main(
            [
                "pipeline-add",
                "--maintenance-config",
                "private",
                "--kind",
                "worker",
                "--config",
                str(tmp_path / "pipeline.json"),
            ]
        )
        == 2
    )
    assert provision.call_count == writer.call_count == 1
    captured = capsys.readouterr()
    assert not captured.out and captured.err == '{"error":"workspace_operation_failed"}\n'
