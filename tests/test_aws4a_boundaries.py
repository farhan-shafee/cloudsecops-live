"""Independent acceptance for AWS4A gates, frozen scope and disabled authority."""

import copy
import gzip
import json
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_aws3_boundaries import report as previous_report

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "requests",
    "contracts",
    "capability",
    "budget",
    "engine",
    "clients",
    "wire",
    "registry",
    "bootstrap",
    "network",
)
PREFIX = "cloudsecops_live/integrations/aws_posture/"


def report():
    value = previous_report()
    sample = value["files"]["cloudsecops_live/ingestion.py"]
    for name in (*MODULES, "worker"):
        value["files"][f"{PREFIX}{name}.py"] = copy.deepcopy(sample)
    value["files"][f"{PREFIX}worker.py"]["summary"].update(num_branches=0, covered_branches=0)
    return value


def gate(value, tmp_path, monkeypatch):
    from scripts import check_coverage

    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_coverage.py", str(path), "--require-aws4"])
    return check_coverage.main()


@pytest.mark.parametrize("module", MODULES)
def test_individual_security_branch_floor(module, tmp_path, monkeypatch):
    value = report()
    summary = value["files"][f"{PREFIX}{module}.py"]["summary"]
    summary["covered_branches"] = 85
    assert gate(value, tmp_path, monkeypatch) == 0
    summary["covered_branches"] = 84
    assert gate(value, tmp_path, monkeypatch) == 1


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("fault", ["missing", "unexecuted", "unmeasured", "excluded"])
def test_no_unexecuted_or_excluded_security_paths(module, fault, tmp_path, monkeypatch):
    value = report()
    name = f"{PREFIX}{module}.py"
    if fault == "missing":
        value["files"].pop(name)
    elif fault == "unexecuted":
        value["files"][name]["summary"]["covered_lines"] = 0
    elif fault == "unmeasured":
        value["files"][name]["summary"].update(num_branches=0, covered_branches=0)
    else:
        value["files"][name]["excluded_lines"] = [1]
    assert gate(value, tmp_path, monkeypatch) == 2


@pytest.mark.parametrize("fault", ["missing", "unexecuted", "partial", "new_branch"])
def test_unconditional_denial_requires_every_line_and_zero_branches(fault, tmp_path, monkeypatch):
    value = report()
    name = f"{PREFIX}worker.py"
    if fault == "missing":
        value["files"].pop(name)
        expected = 2
    elif fault == "unexecuted":
        value["files"][name]["summary"]["covered_lines"] = 0
        expected = 2
    elif fault == "partial":
        value["files"][name]["summary"]["covered_lines"] -= 1
        expected = 1
    else:
        value["files"][name]["summary"].update(num_branches=2, covered_branches=2)
        expected = 2
    assert gate(value, tmp_path, monkeypatch) == expected


def test_original_foundation_threshold_unchanged(tmp_path, monkeypatch):
    value = report()
    value["files"]["cloudsecops_live/ingestion.py"]["summary"]["covered_branches"] = 89
    assert gate(value, tmp_path, monkeypatch) == 1


def test_all_ten_existing_contexts_and_sequential_disposable_database_acceptance():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert set(jobs) == {
        "validate",
        "postgres-integration",
        "harness-safety",
        "native-terraform",
        "dependency-audit",
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert jobs["validate"]["strategy"]["matrix"] == {
        "os": ["ubuntu-24.04", "windows-2025"],
        "python": ["3.12", "3.14"],
    }
    assert jobs["postgres-integration"]["strategy"]["max-parallel"] == 1
    assert jobs["postgres-integration"]["strategy"]["matrix"]["python"] == ["3.12", "3.14"]
    assert jobs["dependency-audit"]["strategy"]["matrix"]["os"] == ["ubuntu-24.04", "windows-2025"]
    for name in ("validate", "postgres-integration"):
        commands = [step.get("run", "") for step in jobs[name]["steps"]]
        gates = [command for command in commands if "check_coverage.py" in command]
        assert len(gates) == 1
        assert {
            "--require-aws",
            "--require-aws1",
            "--require-aws2",
            "--require-aws3",
            "--require-aws4",
        } <= set(gates[0].split())
    database_gate = next(
        step["run"]
        for step in jobs["postgres-integration"]["steps"]
        if "check_coverage.py" in step.get("run", "")
    )
    assert {"--require-security", "--require-durable"} <= set(database_gate.split())
    native = jobs["native-terraform"]
    assert native["name"] == "Native Terraform and provider security"
    assert any(
        "python -m scripts.terraform_native" in step.get("run", "") for step in native["steps"]
    )


def test_public_package_has_no_live_command_or_new_migration():
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"] == {"cloudsecops-live": "cloudsecops_live.cli:main"}
    assert not (ROOT / "src/cloudsecops_live/integrations/aws_posture/__main__.py").exists()
    assert sorted(path.name for path in (ROOT / "src/cloudsecops_live/sql").glob("*.sql")) == [
        "001_initial.sql",
        "002_workspace.sql",
        "003_reviewed_workflow.sql",
    ]


@pytest.mark.parametrize("forged", [False, True])
def test_posture_observation_cannot_enter_the_synthetic_cli(forged, tmp_path, capsys):
    from cloudsecops_live.cli import main
    from tests.test_aws4a_engine import make, run

    observation = run(*make())
    if forged:
        observation.update(
            authenticated=True, trusted_findings_available=True, closure_available=True
        )
    fixture = tmp_path / "posture.json.gz"
    fixture.write_bytes(gzip.compress(json.dumps(observation).encode(), mtime=0))
    assert main(["detect-synthetic", str(fixture)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    result = json.loads(captured.err)
    assert result["error"]["code"] == "INVALID_FIXTURE_ENVELOPE"
    assert result.get("authenticated") is not True
