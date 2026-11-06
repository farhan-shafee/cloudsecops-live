"""Measured security branches must pass independently of the package average."""

import copy
import json
import sys

import pytest

from tests.test_aws4a_boundaries import report as previous_report

MODULES = ("crypto", "parsing", "verification")
PREFIX = "cloudsecops_live/integrations/aws_cloudtrail/signed/"


def report():
    value = previous_report()
    sample = value["files"]["cloudsecops_live/ingestion.py"]
    for name in MODULES:
        value["files"][f"{PREFIX}{name}.py"] = copy.deepcopy(sample)
    return value


def gate(value, tmp_path, monkeypatch):
    from scripts import check_coverage

    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_coverage.py", str(path), "--require-aws4b"])
    return check_coverage.main()


@pytest.mark.parametrize("module", MODULES)
def test_each_new_module_requires_85_percent_branches(module, tmp_path, monkeypatch):
    value = report()
    summary = value["files"][f"{PREFIX}{module}.py"]["summary"]
    summary["covered_branches"] = 85
    assert gate(value, tmp_path, monkeypatch) == 0
    summary["covered_branches"] = 84
    assert gate(value, tmp_path, monkeypatch) == 1


@pytest.mark.parametrize("module", MODULES)
@pytest.mark.parametrize("fault", ["missing", "unexecuted", "unmeasured", "excluded"])
def test_missing_or_hidden_new_security_measurements_fail_closed(
    module, fault, tmp_path, monkeypatch
):
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
