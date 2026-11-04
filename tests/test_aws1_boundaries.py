"""New adapters must not add an executable AWS path or relax acceptance gates."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import require_authenticated

ROOT = Path(__file__).resolve().parents[1]


def test_sdk_import_never_constructs_sessions_or_uses_network():
    code = """
import socket
import boto3
import botocore.session
def denied(*args, **kwargs):
    raise AssertionError('import attempted a forbidden operation')
boto3.client = denied
boto3.Session = denied
boto3.session.Session = denied
botocore.session.get_session = denied
socket.socket.connect = denied
socket.create_connection = denied
import cloudsecops_live.integrations.aws_sdk.transport
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


def test_no_sdk_session_factory_or_live_entrypoint_is_shipped():
    package = ROOT / "src/cloudsecops_live/integrations/aws_sdk"
    assert not (package / "__main__.py").exists()
    assert {p.name for p in package.glob("*.py")} == {"__init__.py", "transport.py"}
    tree = ast.parse((package / "transport.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            assert not {name.split(".")[0] for name in imports} & {
                "boto3",
                "subprocess",
                "os",
                "socket",
            }
        if isinstance(node, ast.Call):
            assert not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"create_client", "get_session", "get_credentials"}
            )


@pytest.mark.parametrize("flag", ["authenticated", "trusted", "verified", "source_kind"])
def test_guarded_receipt_claims_cannot_authorize_existing_closure(flag):
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated({flag: True, "case_id": "guessed-case", "result": "verified"})


def test_ci_preserves_old_gates_and_requires_guarded_module_coverage():
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert document["permissions"] == {"contents": "read"}
    assert document["env"]["AWS_EC2_METADATA_DISABLED"] == "true"
    for name in ("validate", "postgres-integration"):
        steps = document["jobs"][name]["steps"]
        gates = [step["run"] for step in steps if "check_coverage.py" in step.get("run", "")]
        assert len(gates) == 1
        assert "--require-aws1" in gates[0] and "--require-aws" in gates[0]
    assert document["jobs"]["postgres-integration"]["strategy"]["max-parallel"] == 1
    assert "native-terraform" in document["jobs"]
    assert "id-token" not in json.dumps(document)


def test_new_security_coverage_modules_are_individually_required(tmp_path, monkeypatch, capsys):
    from scripts import check_coverage

    module_names = (
        *check_coverage.FOUNDATION,
        *(name for modules in check_coverage.DURABLE.values() for name in modules),
        *check_coverage.AWS_GUARDED,
    )
    report = {
        "meta": {"branch_coverage": True},
        "files": {
            f"cloudsecops_live/{name}.py": {
                "summary": {
                    "num_statements": 100,
                    "covered_lines": 100,
                    "num_branches": 100,
                    "covered_branches": 100,
                }
            }
            for name in module_names
        },
    }
    path = tmp_path / "coverage.json"
    monkeypatch.setattr("sys.argv", ["check_coverage.py", str(path), "--require-aws1"])
    path.write_text(json.dumps(report), encoding="utf-8")
    assert check_coverage.main() == 0
    for name in check_coverage.AWS_GUARDED:
        entry = report["files"][f"cloudsecops_live/{name}.py"]
        entry["summary"]["covered_branches"] = 84
        path.write_text(json.dumps(report), encoding="utf-8")
        assert check_coverage.main() == 1
        entry["summary"]["covered_branches"] = 100
    assert "required >=85%" in capsys.readouterr().out
