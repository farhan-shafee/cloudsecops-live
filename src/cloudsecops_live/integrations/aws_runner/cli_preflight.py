"""Pure CLI installation-observation consistency; never executes or authenticates AWS."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import isfinite
from typing import Literal

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.cli_receipts import (
    OUTPUT_CONTRACT,
    SUPPORTED_CLI_VERSION,
)
from cloudsecops_live.integrations.aws_runner.contracts import IdentityAuthorization

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PLATFORMS = frozenset({"windows-amd64", "linux-amd64", "linux-aarch64", "macos-universal"})


@dataclass(frozen=True, slots=True)
class CliInstallationExpectation:
    artifact_sha256: str = field(repr=False)
    platform: str
    provenance: Literal["owner_reviewed_official_release"]
    tool_version: str = SUPPORTED_CLI_VERSION
    output_contract: str = OUTPUT_CONTRACT

    def __post_init__(self) -> None:
        if (
            not isinstance(self.artifact_sha256, str)
            or _HASH.fullmatch(self.artifact_sha256) is None
            or not isinstance(self.platform, str)
            or self.platform not in _PLATFORMS
            or self.provenance != "owner_reviewed_official_release"
            or self.tool_version != SUPPORTED_CLI_VERSION
            or self.output_contract != OUTPUT_CONTRACT
        ):
            raise EvidenceError("AWS_CLI_PREFLIGHT_EXPECTATION")


@dataclass(frozen=True, slots=True)
class CliInstallationObservation:
    platform: str
    artifact_sha256_before: str = field(repr=False)
    artifact_sha256_after: str = field(repr=False)
    version_output: bytes = field(repr=False)
    signature_verified: bool
    provenance: str


Reason = Literal[
    "AWS_CLI_PREFLIGHT_CONSISTENT",
    "AWS_CLI_PREFLIGHT_STRUCTURE",
    "AWS_CLI_PREFLIGHT_PLATFORM",
    "AWS_CLI_PREFLIGHT_ARTIFACT",
    "AWS_CLI_PREFLIGHT_SIGNATURE",
    "AWS_CLI_PREFLIGHT_PROVENANCE",
    "AWS_CLI_PREFLIGHT_VERSION",
    "AWS_CLI_PREFLIGHT_OUTPUT",
]
_REASONS = frozenset(
    {
        "AWS_CLI_PREFLIGHT_CONSISTENT",
        "AWS_CLI_PREFLIGHT_STRUCTURE",
        "AWS_CLI_PREFLIGHT_PLATFORM",
        "AWS_CLI_PREFLIGHT_ARTIFACT",
        "AWS_CLI_PREFLIGHT_SIGNATURE",
        "AWS_CLI_PREFLIGHT_PROVENANCE",
        "AWS_CLI_PREFLIGHT_VERSION",
        "AWS_CLI_PREFLIGHT_OUTPUT",
    }
)


@dataclass(frozen=True, slots=True)
class CliPreflightAssessment:
    reason: Reason
    authenticated: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str) or self.reason not in _REASONS:
            raise EvidenceError("AWS_CLI_PREFLIGHT_STRUCTURE")

    @property
    def observations_consistent(self) -> bool:
        return self.reason == "AWS_CLI_PREFLIGHT_CONSISTENT"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "aws-cli-preflight/1",
            "tool_version": SUPPORTED_CLI_VERSION,
            "output_contract": OUTPUT_CONTRACT,
            "state": "pending_source_authentication" if self.observations_consistent else "invalid",
            "reason": self.reason,
            "observations_consistent": self.observations_consistent,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


def assess_cli_preflight(
    expected: CliInstallationExpectation,
    observed: CliInstallationObservation,
) -> CliPreflightAssessment:
    """Compare owner-reviewed artifact data and supplied observations, without I/O.

    Hash equality and signature_verified are observations supplied by the caller.
    Neither proves execution provenance or authenticates any CloudTrail evidence.
    """
    reason: Reason
    if (
        type(expected) is not CliInstallationExpectation
        or type(observed) is not CliInstallationObservation
    ):
        reason = "AWS_CLI_PREFLIGHT_STRUCTURE"
    elif observed.provenance != "operator_supplied_local_observation":
        reason = "AWS_CLI_PREFLIGHT_PROVENANCE"
    elif observed.platform != expected.platform:
        reason = "AWS_CLI_PREFLIGHT_PLATFORM"
    elif (
        observed.artifact_sha256_before != expected.artifact_sha256
        or observed.artifact_sha256_after != expected.artifact_sha256
    ):
        reason = "AWS_CLI_PREFLIGHT_ARTIFACT"
    elif observed.signature_verified is not True:
        reason = "AWS_CLI_PREFLIGHT_SIGNATURE"
    elif (
        type(observed.version_output) is not bytes
        or not 1 <= len(observed.version_output) <= 1024
        or any(not 32 <= value <= 126 for value in observed.version_output.rstrip(b"\n"))
        or observed.version_output.count(b"\n") > 1
        or b"\n" in observed.version_output[:-1]
    ):
        reason = "AWS_CLI_PREFLIGHT_OUTPUT"
    elif re.fullmatch(rb"aws-cli/2\.37\.11(?: [!-~]+)*\n?", observed.version_output) is None:
        reason = "AWS_CLI_PREFLIGHT_VERSION"
    else:
        reason = "AWS_CLI_PREFLIGHT_CONSISTENT"
    return CliPreflightAssessment(reason)


@dataclass(frozen=True, slots=True)
class PreparedCliExecution:
    """Disabled fixed-argument preparation, with no executable or environment input.

    A real CLI run has internal API calls, retries and bytes beyond this contract.
    This object cannot authorize execution or claim those limits are enforced.
    External process cancellation is required for a future separately approved run.
    """

    authorization: IdentityAuthorization = field(repr=False)
    preflight: CliPreflightAssessment = field(repr=False)
    start_time: datetime = field(repr=False)
    end_time: datetime = field(repr=False)
    deadline_seconds: float
    max_output_bytes: int
    argv: tuple[str, ...] = field(init=False, repr=False)
    authenticated: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.authorization) is not IdentityAuthorization
            or type(self.preflight) is not CliPreflightAssessment
            or not self.preflight.observations_consistent
            or type(self.start_time) is not datetime
            or type(self.end_time) is not datetime
            or self.start_time.utcoffset() != timedelta(0)
            or self.end_time.utcoffset() != timedelta(0)
            or self.start_time.microsecond != 0
            or self.end_time.microsecond != 0
            or not timedelta(0) < self.end_time - self.start_time <= timedelta(days=1)
            or type(self.deadline_seconds) not in (int, float)
            or not 0 < self.deadline_seconds <= 30
            or not isfinite(self.deadline_seconds)
            or type(self.max_output_bytes) is not int
            or not 1 <= self.max_output_bytes <= 1024 * 1024
        ):
            raise EvidenceError("AWS_CLI_EXECUTION_CONTRACT")
        scope = self.authorization.scope
        suffix = f"AWSLogs/{scope.account}/CloudTrail/{scope.region}/"
        root = scope.log_prefix.removesuffix(suffix).removesuffix("/")
        # The SDK timeouts are not the deadline; an external supervisor owns it.
        io_timeout = str(max(1, min(5, int(self.deadline_seconds))))
        object.__setattr__(
            self,
            "argv",
            (
                "cloudtrail",
                "validate-logs",
                "--trail-arn",
                scope.trail_arn,
                "--start-time",
                self.start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "--end-time",
                self.end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "--s3-bucket",
                scope.bucket,
                "--s3-prefix",
                root,
                "--region",
                scope.region,
                "--verbose",
                "--no-cli-pager",
                "--no-cli-auto-prompt",
                "--color",
                "off",
                "--cli-connect-timeout",
                io_timeout,
                "--cli-read-timeout",
                io_timeout,
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "aws-cli-execution-preparation/1",
            "tool_version": SUPPORTED_CLI_VERSION,
            "output_contract": OUTPUT_CONTRACT,
            "state": "prepared_execution_disabled",
            "execution_enabled": False,
            "deadline_seconds": self.deadline_seconds,
            "max_output_bytes": self.max_output_bytes,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }
