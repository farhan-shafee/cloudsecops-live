"""Exercise CLI effects and error boundaries with real fixture files."""

import gzip
import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from cloudsecops_live.cli import main
from tests.helpers import archive, event


def invoke(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


def test_detection_demo_is_synthetic_and_repeatable() -> None:
    args = ["detect-synthetic", "fixtures/synthetic/inventory-burst.json.gz"]
    first = invoke(args)
    assert first == invoke(args)
    assert first[0] == 0 and first[2] == ""
    output = json.loads(first[1])
    assert output["source_kind"] == "synthetic" and output["authenticated"] is False
    assert output["findings"][0]["evidence_event_ids"] == ["demo-001", "demo-002", "demo-003"]


def test_import_retains_normalized_records_and_hash_references() -> None:
    code, out, err = invoke(["import-synthetic", "fixtures/synthetic/inventory-burst.json.gz"])
    assert code == 0 and not err
    output = json.loads(out)
    assert len(output["normalized_events"]) == 3
    assert output["raw_objects"][0]["archive_sha256"] != output["raw_objects"][0]["content_sha256"]
    assert "findings" not in output


@pytest.mark.parametrize(
    "args",
    [[], ["unknown"], ["detect-synthetic"], ["detect-synthetic", "--verified", "secret-value"]],
)
def test_usage_is_structured_and_does_not_echo_arguments(args: list[str]) -> None:
    code, out, err = invoke(args)
    assert code == 64 and out == ""
    assert json.loads(err)["error"]["code"] == "USAGE"
    assert "secret-value" not in err


def test_missing_file_error_never_echoes_private_path(tmp_path: Path) -> None:
    code, out, err = invoke(["detect-synthetic", str(tmp_path / "private-sensitive.json.gz")])
    assert code == 2 and out == ""
    assert json.loads(err)["error"]["code"] == "FILE_READ_ERROR"
    assert "private-sensitive" not in err and str(tmp_path) not in err


def test_invalid_second_file_emits_no_partial_report(tmp_path: Path) -> None:
    path = tmp_path / "bad.json.gz"
    path.write_bytes(gzip.compress(b"not-json"))
    code, out, err = invoke(
        ["detect-synthetic", "fixtures/synthetic/inventory-burst.json.gz", str(path)]
    )
    assert code == 2 and not out and json.loads(err)["error"]["code"] == "INVALID_JSON"


def test_conflict_returns_distinct_nonzero_status(tmp_path: Path) -> None:
    first, second = event("same", 0), event("same", 0)
    second["unknown"] = "changed"
    path = tmp_path / "conflict.json.gz"
    path.write_bytes(archive([first, second]))
    code, out, err = invoke(["detect-synthetic", str(path)])
    assert code == 3 and not err
    result = json.loads(out)
    assert result["provenance"] == "conflicting" and result["findings"] == []


def test_file_count_is_bounded_before_opening() -> None:
    code, out, err = invoke(["detect-synthetic", *["not-opened.json.gz"] * 17])
    assert code == 2 and not out
    assert json.loads(err)["error"]["code"] == "BATCH_LIMIT"


def test_unexpected_failure_is_nonzero_sanitized_and_not_a_clean_result() -> None:
    with patch("cloudsecops_live.cli.parse_file", side_effect=RuntimeError("private-token")):
        code, out, err = invoke(["detect-synthetic", "fixtures/synthetic/inventory-burst.json.gz"])
    assert code == 70 and not out
    assert json.loads(err)["error"]["code"] == "INTERNAL_ERROR" and "private-token" not in err


def test_module_entrypoint_help_is_executable() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "cloudsecops_live", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0 and "detect-synthetic" in result.stdout
