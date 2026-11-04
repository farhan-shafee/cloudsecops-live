"""Exercise scan failures and branch gates through their public script interfaces."""

import gzip
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_unicode_text_cannot_hide_a_secret_on_windows_locale(tmp_path: Path) -> None:
    candidate = tmp_path / "unicode.py"
    token = "AKIA" + "Z7Q3M8R2N5P6V9T4"
    candidate.write_text("# comment " + chr(129) + f'\naccess_key="{token}"\n', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(candidate)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1 and "AWS Access Key" in result.stdout
    assert token not in result.stdout + result.stderr


def test_scanner_io_warning_is_failure_not_a_clean_scan(tmp_path: Path, capsys: object) -> None:
    from scripts.check_secrets import main

    candidate = tmp_path / "clean.py"
    candidate.write_text("clean = True\n", encoding="utf-8")
    with (
        patch("sys.argv", ["check_secrets.py", str(candidate)]),
        patch(
            "detect_secrets.core.scan._get_lines_from_file",
            side_effect=OSError("private-error-detail"),
        ),
    ):
        assert main() == 2


def test_workflow_can_be_loaded_as_yaml_with_executable_string_steps() -> None:
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert set(document["jobs"]) == {
        "validate",
        "dependency-audit",
        "postgres-integration",
        "native-terraform",
    }
    # GitHub's job context is available to step env, not jobs.<job_id>.env.
    postgres = document["jobs"]["postgres-integration"]
    assert "job.services" not in json.dumps(postgres.get("env", {}))
    recovery = next(
        step for step in postgres["steps"] if "scripts/run_integration.py" in step.get("run", "")
    )
    assert recovery["env"]["CSL_POSTGRES_CONTAINER"] == "${{ job.services.postgres.id }}"
    for job in document["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                assert isinstance(step["run"], str) and step["run"].strip()
    database = document["jobs"]["postgres-integration"]
    assert database["runs-on"] == "ubuntu-24.04"
    assert database["strategy"]["matrix"]["python"] == ["3.12", "3.14"]
    assert database["strategy"]["max-parallel"] == 1
    assert "@sha256:" in database["services"]["postgres"]["image"]
    assert database["services"]["postgres"]["ports"] == ["127.0.0.1:5432:5432"]
    runs = "\n".join(step.get("run", "") for step in database["steps"])
    assert "scripts/run_integration.py" in runs
    assert "--require-durable" in runs
    assert "continue-on-error" not in json.dumps(database)
    native = document["jobs"]["native-terraform"]
    assert native["runs-on"] == "ubuntu-24.04"
    assert native["defaults"]["run"]["shell"] == "bash"
    assert "continue-on-error" not in json.dumps(native)
    commands = "\n".join(step.get("run", "") for step in native["steps"])
    assert "python -m scripts.terraform_native" in commands
    assert "git rev-parse HEAD" in commands
    assert document["permissions"] == {"contents": "read"}


def test_compressed_fixture_secrets_and_accounts_cannot_bypass_scan(tmp_path: Path) -> None:
    candidate = tmp_path / "sample.json.gz"
    token = "AKIA" + "Z7Q3M8R2N5P6V9T4"
    account = "123456" + "789012"
    candidate.write_bytes(
        gzip.compress(json.dumps({"access_key": token, "account": account}).encode())
    )
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(candidate)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout and "account-shaped identifier" in result.stdout
    assert (
        token not in result.stdout + result.stderr and account not in result.stdout + result.stderr
    )


def test_corrupt_or_trailing_compressed_scan_input_is_not_a_clean_result(tmp_path: Path) -> None:
    candidate = tmp_path / "sample.json.gz"
    for data in [b"bad", gzip.compress(b"{}")[:-1], gzip.compress(b"{}") + b"junk"]:
        candidate.write_bytes(data)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(candidate)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "no findings" not in result.stdout


def test_scanner_blocks_a_new_secret_without_printing_value(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.py"
    token = "AKIA" + "Z7Q3M8R2N5P6V9T4"
    candidate.write_text(f'access_key = "{token}"\n', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(candidate)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout
    assert token not in result.stdout + result.stderr


def test_scanner_checks_test_files_and_accepts_named_synthetic_values(tmp_path: Path) -> None:
    candidate = tmp_path / "test_fixture.py"
    candidate.write_text('access_key = "SYNTHETIC_KEY_A"\n', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(candidate)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "scanned 1 file" in result.stdout


def test_missing_scan_input_is_failure(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_secrets.py"), str(tmp_path / "missing")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def coverage_report(branches: int, covered: int) -> dict[str, object]:
    summary = {
        "num_branches": branches,
        "covered_branches": covered,
        "num_statements": 100,
        "covered_lines": 95,
    }
    return {
        "meta": {"branch_coverage": True},
        "files": {
            f"src/cloudsecops_live/{name}.py": {"summary": summary}
            for name in (
                "__init__",
                "__main__",
                "cli",
                "contracts",
                "errors",
                "ingestion",
                "detection",
            )
        },
        "totals": {"num_statements": 100, "covered_lines": 95},
    }


def test_branch_gate_rejects_low_actual_branch_coverage(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps(coverage_report(100, 89)), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "ingestion.py: branch 89.00%" in result.stdout


def test_branch_gate_accepts_exact_threshold(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps(coverage_report(100, 90)), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_branch_gate_rejects_missing_module_evidence(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text('{"meta": {"branch_coverage": true}, "files": {}}', encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_database_gate_requires_measured_durable_modules(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps(coverage_report(100, 95)), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report), "--require-durable"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def test_foundation_line_gate_still_rejects_low_lines(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    data = coverage_report(100, 95)
    for entry in data["files"].values():
        entry["summary"]["covered_lines"] = 89
    report.write_text(json.dumps(data), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1


def test_durable_reports_preserve_package_gate_and_separate_measurements(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    data = coverage_report(100, 95)
    for name in ("database", "storage", "worker", "outbox", "cases"):
        data["files"][f"src/cloudsecops_live/{name}.py"] = {
            "summary": {
                "num_statements": 100,
                "covered_lines": 80,
                "num_branches": 50,
                "covered_branches": 35,
            }
        }
    report.write_text(json.dumps(data), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_coverage.py"), str(report), "--require-durable"],
        capture_output=True,
        text=True,
        check=False,
    )
    # Foundation lines are 95%, but the complete package is only 88.75%.
    assert result.returncode == 1, result.stdout + result.stderr
    assert "persistence: lines 80.00%, branches 70.00%" in result.stdout
    assert "worker/outbox: lines 80.00%, branches 70.00%" in result.stdout
    assert "cases: lines 80.00%, branches 70.00%" in result.stdout
