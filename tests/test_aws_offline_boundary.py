"""Offline execution and absence of paths into the accepted synthetic pipeline."""

import ast
import importlib
import json
import runpy
from pathlib import Path

import pytest

from cloudsecops_live.cli import main as synthetic_cli
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import require_authenticated
from cloudsecops_live.integrations.aws_cloudtrail.demo import main
from tests.aws_helpers import archive, scope

ROOT = Path(__file__).resolve().parents[1]


def test_demo_is_deterministic_private_and_cannot_authenticate(capsys):
    assert main() == 0
    first = capsys.readouterr().out
    assert main() == 0
    assert capsys.readouterr().out == first
    report = json.loads(first)
    assert report["unique_event_count"] == 3
    assert report["authenticated"] is False
    assert report["trusted_findings_available"] is False
    assert report["controlled_digest_consistency"] is True
    assert report["authentication_gate"] == "AWS_AUTHENTICATION_UNAVAILABLE"
    assert report["state"] == "pending_source_authentication"
    for private in (scope().account, "ASIA" + "A" * 16, "arn:aws:", "s3://"):
        assert private not in first


def test_public_module_entrypoint_executes_only_the_offline_demo(capsys):
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("cloudsecops_live.integrations.aws_cloudtrail", run_name="__main__")
    assert stopped.value.code == 0
    assert json.loads(capsys.readouterr().out)["authenticated"] is False


def test_imports_and_demo_have_no_network_or_credential_modules(monkeypatch):
    # Runtime denial supplements source checks. It does not emulate AWS.
    import socket

    def denied(*args, **kwargs):
        pytest.fail("offline boundary attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    package = ROOT / "src/cloudsecops_live/integrations/aws_cloudtrail"
    forbidden = {"boto3", "botocore", "requests", "httpx", "urllib", "socket", "subprocess", "os"}
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(n.name.split(".")[0] in forbidden for n in node.names)
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in forbidden
        if path.stem != "__main__":
            importlib.import_module("cloudsecops_live.integrations.aws_cloudtrail." + path.stem)
    assert main() == 0


def test_raw_aws_envelope_is_not_accepted_by_synthetic_cli(tmp_path, capsys):
    path = tmp_path / "aws-shaped.json.gz"
    path.write_bytes(archive())
    assert synthetic_cli(["import-synthetic", str(path)]) == 2
    report = json.loads(capsys.readouterr().err)
    assert report["error"]["code"] == "INVALID_FIXTURE_ENVELOPE"
    assert report["authenticated"] is False
    assert "normalized_events" not in report
    assert synthetic_cli(["import-synthetic", "--authenticated", str(path)]) == 64
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "USAGE"


@pytest.mark.parametrize("forged", [{"authenticated": True}, {"verified": True}, object(), None])
def test_future_trust_and_closure_gate_is_unconditionally_unavailable(forged):
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(forged)
