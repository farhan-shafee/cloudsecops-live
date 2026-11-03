"""Exercise scan failures and branch gates through their public script interfaces."""

import gzip
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_workflow_can_be_loaded_as_yaml_with_executable_string_steps() -> None:
    document = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert set(document["jobs"]) == {"validate", "dependency-audit"}
    for job in document["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                assert isinstance(step["run"], str) and step["run"].strip()


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
    summary = {"num_branches": branches, "covered_branches": covered}
    return {
        "meta": {"branch_coverage": True},
        "files": {
            f"src/cloudsecops_live/{name}.py": {"summary": summary}
            for name in ("ingestion", "detection")
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
