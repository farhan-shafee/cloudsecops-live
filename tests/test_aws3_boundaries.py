"""Independently specified CI and trust gates for the fixed offline workers."""

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

from tests.test_aws2_boundaries import coverage_report

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "integrations/aws_readiness/sessions",
    "integrations/aws_readiness/permissions",
    "integrations/aws_readiness/requests",
    "integrations/aws_readiness/registry",
    "integrations/aws_readiness/transport",
    "integrations/aws_readiness/workers",
)


def report():
    value = coverage_report()
    sample = value["files"]["cloudsecops_live/ingestion.py"]
    for name in MODULES:
        value["files"][f"cloudsecops_live/{name}.py"] = copy.deepcopy(sample)
    return value


def gate(value, tmp_path, monkeypatch):
    from scripts import check_coverage

    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_coverage.py", str(path), "--require-aws3"])
    return check_coverage.main()


@pytest.mark.parametrize("module", MODULES)
def test_every_new_security_module_requires_85_percent_actual_branches(
    module, tmp_path, monkeypatch
):
    value = report()
    summary = value["files"][f"cloudsecops_live/{module}.py"]["summary"]
    summary["covered_branches"] = 85
    assert gate(value, tmp_path, monkeypatch) == 0
    summary["covered_branches"] = 84
    assert gate(value, tmp_path, monkeypatch) == 1


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("fault", ["missing", "not_executed", "no_branches", "excluded"])
def test_missing_or_fabricated_measurement_fails_closed(module, fault, tmp_path, monkeypatch):
    value = report()
    name = f"cloudsecops_live/{module}.py"
    if fault == "missing":
        value["files"].pop(name)
    elif fault == "not_executed":
        value["files"][name]["summary"]["covered_lines"] = 0
    elif fault == "no_branches":
        value["files"][name]["summary"].update(num_branches=0, covered_branches=0)
    else:
        value["files"][name]["excluded_lines"] = [1]
    assert gate(value, tmp_path, monkeypatch) == 2


def test_new_gate_preserves_the_existing_foundation_requirement(tmp_path, monkeypatch):
    value = report()
    value["files"]["cloudsecops_live/detection.py"]["summary"]["covered_branches"] = 89
    assert gate(value, tmp_path, monkeypatch) == 1


def test_existing_ci_jobs_gain_new_checks_without_cloud_authority():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert workflow["permissions"] == {"contents": "read"}
    for name in ("validate", "postgres-integration"):
        commands = [step.get("run", "") for step in jobs[name]["steps"]]
        gates = [command for command in commands if "check_coverage.py" in command]
        assert len(gates) == 1
        assert {"--require-aws", "--require-aws1", "--require-aws2", "--require-aws3"} <= set(
            gates[0].split()
        )
    for name in ("validate", "native-terraform"):
        assert any(
            "python scripts/check_aws3_permissions.py" in step.get("run", "")
            for step in jobs[name]["steps"]
        )
    assert jobs["postgres-integration"]["strategy"]["max-parallel"] == 1


def test_no_new_dependencies_migrations_or_executable_live_entrypoint():
    import tomllib

    current = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert current["project"]["scripts"] == {"cloudsecops-live": "cloudsecops_live.cli:main"}
    assert not (ROOT / "src/cloudsecops_live/integrations/aws_readiness/__main__.py").exists()
    assert sorted(path.name for path in (ROOT / "src/cloudsecops_live/sql").glob("*.sql")) == [
        "001_initial.sql",
        "002_workspace.sql",
        "003_reviewed_workflow.sql",
    ]
