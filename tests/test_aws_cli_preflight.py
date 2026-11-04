"""CLI installation preflight evaluates supplied observations without execution."""

from dataclasses import replace
from datetime import timedelta

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_runner.cli_preflight import (
    CliInstallationExpectation,
    CliInstallationObservation,
    CliPreflightAssessment,
    PreparedCliExecution,
    assess_cli_preflight,
)
from tests.aws_helpers import BASE_TIME
from tests.test_aws_runner_contracts import authorization


def evidence(**changes):
    expected = CliInstallationExpectation(
        artifact_sha256="a" * 64,
        platform="windows-amd64",
        provenance="owner_reviewed_official_release",
    )
    observed = CliInstallationObservation(
        platform="windows-amd64",
        artifact_sha256_before="a" * 64,
        artifact_sha256_after="a" * 64,
        version_output=b"aws-cli/2.37.11 Python/3.13.11 Windows/11 exe/AMD64\n",
        signature_verified=True,
        provenance="operator_supplied_local_observation",
    )
    return expected, replace(observed, **changes)


def test_consistent_installation_observations_do_not_authenticate_aws_evidence():
    result = assess_cli_preflight(*evidence())
    assert result.observations_consistent is True
    assert result.authenticated is False
    public = result.to_public_dict()
    assert public == {
        "schema_version": "aws-cli-preflight/1",
        "tool_version": "aws-cli/2.37.11",
        "output_contract": "aws-cli/2.37.11/cloudtrail-validate-logs/verbose/1",
        "state": "pending_source_authentication",
        "reason": "AWS_CLI_PREFLIGHT_CONSISTENT",
        "observations_consistent": True,
        "authenticated": False,
        "trusted_findings_available": False,
        "closure_available": False,
    }
    assert "a" * 64 not in str(public)
    assert "windows" not in str(public)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"platform": "linux-amd64"}, "AWS_CLI_PREFLIGHT_PLATFORM"),
        ({"artifact_sha256_before": "b" * 64}, "AWS_CLI_PREFLIGHT_ARTIFACT"),
        ({"artifact_sha256_after": "b" * 64}, "AWS_CLI_PREFLIGHT_ARTIFACT"),
        ({"artifact_sha256_before": "not-a-hash"}, "AWS_CLI_PREFLIGHT_ARTIFACT"),
        ({"signature_verified": False}, "AWS_CLI_PREFLIGHT_SIGNATURE"),
        ({"signature_verified": 1}, "AWS_CLI_PREFLIGHT_SIGNATURE"),
        ({"provenance": "discovered_from_path"}, "AWS_CLI_PREFLIGHT_PROVENANCE"),
        ({"version_output": b"aws-cli/2.37.12"}, "AWS_CLI_PREFLIGHT_VERSION"),
        ({"version_output": b"aws-cli/2.37.110"}, "AWS_CLI_PREFLIGHT_VERSION"),
        ({"version_output": b"aws-cli/2.37.11\r\n"}, "AWS_CLI_PREFLIGHT_OUTPUT"),
        ({"version_output": b"aws-cli/2.37.11\nextra"}, "AWS_CLI_PREFLIGHT_OUTPUT"),
        ({"version_output": b"aws-cli/2.37.11\x1b[0m"}, "AWS_CLI_PREFLIGHT_OUTPUT"),
        ({"version_output": b"x" * 1025}, "AWS_CLI_PREFLIGHT_OUTPUT"),
        ({"version_output": "aws-cli/2.37.11"}, "AWS_CLI_PREFLIGHT_OUTPUT"),
    ],
)
def test_inconsistent_or_unverified_observation_fails_closed(changes, reason):
    result = assess_cli_preflight(*evidence(**changes))
    assert result.observations_consistent is False
    assert result.reason == reason
    assert result.authenticated is False
    assert result.to_public_dict()["trusted_findings_available"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_sha256": "A" * 64},
        {"artifact_sha256": ""},
        {"platform": "unreviewed-platform"},
        {"provenance": "ambient"},
        {"tool_version": "aws-cli/2.37.12"},
        {"output_contract": "arbitrary"},
    ],
)
def test_expectation_cannot_relax_supported_release_or_provenance(changes):
    expected, _ = evidence()
    with pytest.raises(EvidenceError, match="AWS_CLI_PREFLIGHT_EXPECTATION"):
        replace(expected, **changes)


@pytest.mark.parametrize("field", ["artifact_sha256", "platform"])
def test_unstructured_expectation_is_rejected_with_a_fixed_reason(field):
    expected, _ = evidence()
    with pytest.raises(EvidenceError, match="AWS_CLI_PREFLIGHT_EXPECTATION"):
        replace(expected, **{field: []})


def test_assessment_constructor_cannot_expose_arbitrary_public_diagnostics():
    with pytest.raises(EvidenceError, match="AWS_CLI_PREFLIGHT_STRUCTURE"):
        CliPreflightAssessment("private-unreviewed-reason")


def test_preflight_has_no_cli_or_credential_side_effects(monkeypatch):
    import socket
    import subprocess

    def denied(*args, **kwargs):
        pytest.fail("pure CLI preflight attempted execution or network access")

    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    assert assess_cli_preflight(*evidence()).observations_consistent is True


def test_wrong_input_types_are_sanitized():
    expected, observed = evidence()
    for arguments in ((object(), observed), (expected, object())):
        result = assess_cli_preflight(*arguments)
        assert result.reason == "AWS_CLI_PREFLIGHT_STRUCTURE"
        assert result.observations_consistent is False


def test_installation_provenance_is_required_for_both_expectation_and_observation():
    with pytest.raises(TypeError):
        CliInstallationExpectation("a" * 64, "windows-amd64")
    with pytest.raises(TypeError):
        CliInstallationObservation("windows-amd64", "a" * 64, "a" * 64, b"aws-cli/2.37.11", True)


def prepared(**changes):
    values = {
        "authorization": authorization(),
        "preflight": assess_cli_preflight(*evidence()),
        "start_time": BASE_TIME,
        "end_time": BASE_TIME + timedelta(hours=1),
        "deadline_seconds": 5,
        "max_output_bytes": 128 * 1024,
    }
    values.update(changes)
    return PreparedCliExecution(**values)


def test_prepared_execution_builds_exact_scoped_arguments_but_remains_disabled():
    plan = prepared()
    assert plan.argv == (
        "cloudtrail",
        "validate-logs",
        "--trail-arn",
        "arn:aws:cloudtrail:us-east-1:" + "1" * 12 + ":trail/offline-lab",
        "--start-time",
        "2026-01-01T00:00:00Z",
        "--end-time",
        "2026-01-01T01:00:00Z",
        "--s3-bucket",
        "offline-evidence-lab",
        "--s3-prefix",
        "offline-lab",
        "--region",
        "us-east-1",
        "--verbose",
        "--no-cli-pager",
        "--no-cli-auto-prompt",
        "--color",
        "off",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "5",
    )
    public = plan.to_public_dict()
    assert public["execution_enabled"] is False
    assert public["authenticated"] is False
    for private in ("1" * 12, "arn:aws:", "offline-lab", "2026-01-01"):
        assert private not in repr(plan)
        assert private not in str(public)


@pytest.mark.parametrize(
    "changes",
    [
        {"start_time": BASE_TIME.replace(tzinfo=None)},
        {"start_time": BASE_TIME.replace(microsecond=1)},
        {"end_time": BASE_TIME},
        {"end_time": BASE_TIME + timedelta(days=1, seconds=1)},
        {"deadline_seconds": 0},
        {"deadline_seconds": 31},
        {"deadline_seconds": True},
        {"deadline_seconds": float("nan")},
        {"max_output_bytes": True},
        {"max_output_bytes": 0},
        {"max_output_bytes": 1024 * 1024 + 1},
        {"preflight": CliPreflightAssessment("AWS_CLI_PREFLIGHT_SIGNATURE")},
        {"authorization": object()},
    ],
)
def test_prepared_execution_rejects_unbounded_or_unverified_inputs(changes):
    with pytest.raises(EvidenceError, match="AWS_CLI_EXECUTION_CONTRACT"):
        prepared(**changes)


def test_prepared_execution_has_no_arbitrary_argv_or_endpoint_input():
    with pytest.raises(TypeError):
        prepared(argv=("--endpoint-url", "https://foreign.invalid"))
