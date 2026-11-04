"""AWS2 coverage and CI policy preserve offline, untrusted execution boundaries."""

import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes
from cloudsecops_live.integrations.aws_cloudtrail.collection import require_authenticated
from cloudsecops_live.integrations.aws_runner.process import IsolatedResult
from tests.test_aws_cli_preflight import evidence, prepared
from tests.test_aws_runner_contracts import authorization, budget

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "integrations/aws_runner/contracts",
    "integrations/aws_runner/cli_preflight",
    "integrations/aws_runner/sdk_budget",
    "integrations/aws_runner/process",
)
PLATFORM = (
    "integrations/aws_runner/bootstrap",
    "integrations/aws_runner/network",
    "integrations/aws_runner/containment",
)


def coverage_report():
    # Literal module names ensure dropping one production gate breaks these tests.
    names = (
        "__init__",
        "__main__",
        "cli",
        "contracts",
        "errors",
        "ingestion",
        "detection",
        "database",
        "storage",
        "worker",
        "outbox",
        "cases",
        *REQUIRED,
        *PLATFORM,
    )
    return {
        "meta": {"branch_coverage": True},
        "files": {
            f"cloudsecops_live/{name}.py": {
                "summary": {
                    "num_statements": 100,
                    "covered_lines": 100,
                    "num_branches": 100,
                    "covered_branches": 100,
                },
                "excluded_lines": [],
            }
            for name in names
        },
    }


def run_gate(report, tmp_path, monkeypatch, *extra):
    from scripts import check_coverage

    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_coverage.py", str(path), "--require-aws2", *extra])
    return check_coverage.main()


@pytest.mark.parametrize("module", REQUIRED)
def test_each_required_runner_module_has_an_independent_85_percent_branch_gate(
    module,
    tmp_path,
    monkeypatch,
):
    report = coverage_report()
    assert run_gate(report, tmp_path, monkeypatch) == 0
    report["files"][f"cloudsecops_live/{module}.py"]["summary"]["covered_branches"] = 84
    assert run_gate(report, tmp_path, monkeypatch) == 1


@pytest.mark.parametrize("module", REQUIRED)
def test_missing_or_unexecuted_runner_measurement_is_not_a_passing_gate(
    module, tmp_path, monkeypatch
):
    report = coverage_report()
    entry = report["files"].pop(f"cloudsecops_live/{module}.py")
    assert run_gate(report, tmp_path, monkeypatch) == 2
    report["files"][f"cloudsecops_live/{module}.py"] = entry
    entry["summary"]["covered_lines"] = 0
    assert run_gate(report, tmp_path, monkeypatch) == 2


@pytest.mark.parametrize("module", PLATFORM)
def test_platform_modules_report_real_unexecuted_coverage_without_exclusions(
    module,
    tmp_path,
    monkeypatch,
    capsys,
):
    report = coverage_report()
    summary = report["files"][f"cloudsecops_live/{module}.py"]["summary"]
    summary.update(covered_lines=0, covered_branches=0)
    assert run_gate(report, tmp_path, monkeypatch) == 0
    output = capsys.readouterr().out
    assert (
        f"{module}.py: lines 0.00%, branches 0.00% (reported; native acceptance separate)" in output
    )
    report["files"][f"cloudsecops_live/{module}.py"]["excluded_lines"] = [1]
    assert run_gate(report, tmp_path, monkeypatch) == 2


@pytest.mark.parametrize("module", PLATFORM)
def test_platform_coverage_cannot_disappear_from_required_report(module, tmp_path, monkeypatch):
    report = coverage_report()
    report["files"].pop(f"cloudsecops_live/{module}.py")
    assert run_gate(report, tmp_path, monkeypatch) == 2


@pytest.mark.parametrize("module", PLATFORM)
def test_platform_branch_measurement_cannot_be_replaced_by_an_empty_counter(
    module,
    tmp_path,
    monkeypatch,
):
    report = coverage_report()
    report["files"][f"cloudsecops_live/{module}.py"]["summary"].update(
        num_branches=0,
        covered_branches=0,
    )
    assert run_gate(report, tmp_path, monkeypatch) == 2


def test_aws2_flag_preserves_foundation_branch_and_full_database_line_gates(tmp_path, monkeypatch):
    report = coverage_report()
    report["files"]["cloudsecops_live/ingestion.py"]["summary"]["covered_branches"] = 89
    assert run_gate(report, tmp_path, monkeypatch) == 1
    report = coverage_report()
    for module in PLATFORM:
        report["files"][f"cloudsecops_live/{module}.py"]["summary"]["covered_lines"] = 0
    assert run_gate(report, tmp_path, monkeypatch, "--require-durable") == 1
    report = coverage_report()
    report["files"]["cloudsecops_live/cli.py"]["summary"]["covered_lines"] = 0
    assert run_gate(report, tmp_path, monkeypatch) == 1


def test_ci_preserves_ten_jobs_and_sequential_postgres_acceptance():
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = document["jobs"]
    assert set(jobs) == {
        "validate",
        "postgres-integration",
        "harness-safety",
        "native-terraform",
        "dependency-audit",
    }
    assert jobs["validate"]["strategy"]["matrix"] == {
        "os": ["ubuntu-24.04", "windows-2025"],
        "python": ["3.12", "3.14"],
    }
    assert jobs["postgres-integration"]["strategy"]["matrix"] == {"python": ["3.12", "3.14"]}
    assert jobs["dependency-audit"]["strategy"]["matrix"] == {
        "os": ["ubuntu-24.04", "windows-2025"],
    }
    assert jobs["postgres-integration"]["name"] == "PostgreSQL recovery (py${{ matrix.python }})"
    assert jobs["harness-safety"]["name"] == "PostgreSQL harness safety"
    assert jobs["native-terraform"]["name"] == "Native Terraform and provider security"
    assert jobs["postgres-integration"]["strategy"]["max-parallel"] == 1
    for name in ("validate", "postgres-integration"):
        gates = [
            step["run"]
            for step in jobs[name]["steps"]
            if "check_coverage.py" in step.get("run", "")
        ]
        assert len(gates) == 1
        assert {"--require-aws", "--require-aws1", "--require-aws2"} <= set(gates[0].split())
    assert "--require-durable" in gates[0] and "--require-security" in gates[0]


def test_ci_provides_no_aws_credentials_oidc_or_live_cli():
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert document["permissions"] == {"contents": "read"}
    assert document["env"]["AWS_EC2_METADATA_DISABLED"] == "true"
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    }
    environments = [document["env"]]
    for job in document["jobs"].values():
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}
        environments.append(job.get("env", {}))
        for step in job["steps"]:
            environments.append(step.get("env", {}))
            for line in step.get("run", "").splitlines():
                assert not line.lstrip().lower().startswith(("aws ", "aws.exe "))
    assert not any(forbidden & set(environment) for environment in environments)
    assert "id-token" not in json.dumps(document)
    assert "${{ secrets." not in json.dumps(document)


def test_runner_imports_do_not_discover_credentials_launch_workers_or_use_network():
    script = """
import socket, subprocess, boto3, botocore.session
def denied(*args, **kwargs):
    raise AssertionError('runner import attempted a forbidden operation')
boto3.client = denied
boto3.Session = denied
boto3.session.Session = denied
botocore.session.get_session = denied
socket.socket.connect = denied
socket.create_connection = denied
subprocess.Popen = denied
import cloudsecops_live.integrations.aws_runner.contracts
import cloudsecops_live.integrations.aws_runner.cli_preflight
import cloudsecops_live.integrations.aws_runner.sdk_budget
import cloudsecops_live.integrations.aws_runner.process
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind", ["identity", "budget", "cli", "prepared", "process"])
def test_runner_receipts_cannot_gain_accepted_classification_or_closure(kind):
    from cloudsecops_live.integrations.aws_runner.cli_preflight import assess_cli_preflight

    values = {
        "identity": authorization(),
        "budget": budget(),
        "cli": assess_cli_preflight(*evidence()),
        "prepared": prepared(),
        "process": IsolatedResult("ok", b'{"authenticated":true}', 0.1, True, "AWS_RUNNER_OK"),
    }
    value = values[kind]
    public = value.to_public_dict()
    assert public["authenticated"] is False
    assert public["trusted_findings_available"] is False
    assert public["closure_available"] is False
    for candidate in (value, public, {**public, "authenticated": True, "source_kind": "synthetic"}):
        with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
            require_authenticated(candidate)
    raw = gzip.compress(json.dumps(public).encode(), mtime=0)
    with pytest.raises(EvidenceError, match="INVALID_FIXTURE_ENVELOPE"):
        parse_bytes(raw)
