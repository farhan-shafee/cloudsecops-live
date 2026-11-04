"""Bounded offline CLI-output consistency; no execution or source authentication."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from math import isfinite
from typing import Any, Literal, NoReturn, cast

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion, RetrievedLog
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsLog, AwsScope
from cloudsecops_live.integrations.aws_cloudtrail.validation import (
    CheckOutcome,
    ControlledValidation,
    DigestMember,
    assess_digest,
)

RECEIPT_SCHEMA = "aws-cli-receipt/1"
SUPPORTED_CLI_VERSION = "aws-cli/2.37.11"
OUTPUT_CONTRACT = "aws-cli/2.37.11/cloudtrail-validate-logs/verbose/1"
_MAX_RECEIPT = 2 * 1024 * 1024
_DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_KEYS = {
    "bucket",
    "key",
    "version_id",
    "archive_sha256",
    "content_sha256",
    "before_version_id",
    "after_version_id",
    "before_observed_at",
    "after_observed_at",
}
Location = tuple[str, str]


@dataclass(frozen=True, slots=True)
class CliReceiptAssessment:
    state: str
    reason: str
    consistency_passed: bool = False
    object_count: int = 0
    digest_count: int = 0
    authenticated: Literal[False] = field(default=False, init=False)
    source_kind: Literal["aws_shaped_unverified"] = field(
        default="aws_shaped_unverified", init=False
    )

    def to_public_dict(self) -> dict[str, object]:
        """No raw output, private identifiers, source locations, times or hashes."""
        return {
            "schema_version": RECEIPT_SCHEMA,
            "state": self.state,
            "reason": self.reason,
            "consistency_passed": self.consistency_passed,
            "object_count": self.object_count,
            "digest_count": self.digest_count,
            "source_kind": "aws_shaped_unverified",
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
            "unproven": [
                "execution_provenance",
                "digest_signature",
                "authenticated_chain_coverage",
                "source_version_observations",
                "digest_archive_content_binding",
            ],
        }


class _Rejected(Exception):
    def __init__(self, state: str, reason: str) -> None:
        self.state, self.reason = state, reason


def _fail(reason: str, state: str = "invalid") -> NoReturn:
    raise _Rejected(state, reason)


def _dict(value: Any, keys: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (keys is not None and set(value) != keys):
        _fail("AWS_CLI_RECEIPT_STRUCTURE")
    return cast(dict[str, Any], value)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("AWS_CLI_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _loads(raw: bytes) -> dict[str, Any]:
    if len(raw) > _MAX_RECEIPT:
        _fail("AWS_CLI_RECEIPT_LIMIT")
    value = _dict(
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: _fail("AWS_CLI_RECEIPT_JSON"),
        )
    )
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 8192:
            _fail("AWS_CLI_RECEIPT_LIMIT")
        if isinstance(item, float) and not isfinite(item):
            _fail("AWS_CLI_RECEIPT_JSON")
        if isinstance(item, str) and any(
            (ord(c) < 32 and c not in "\n\t") or 127 <= ord(c) <= 159 for c in item
        ):
            _fail("AWS_CLI_RECEIPT_CONTROL")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0) or value.microsecond:
        _fail("AWS_CLI_RECEIPT_TIME")
    return value.astimezone(UTC)


def _stamp(value: object) -> datetime:
    if not isinstance(value, str) or re.fullmatch(_DATE, value) is None:
        _fail("AWS_CLI_RECEIPT_TIME")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _list(value: Any, maximum: int) -> list[Any]:
    if type(value) is not list or len(value) > maximum:
        _fail("AWS_CLI_RECEIPT_LIMIT")
    return value


def _stream(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 256 * 1024
        or any(c not in "\n\t" and not 32 <= ord(c) <= 126 for c in value)
        or len(value.split("\n")) > 2048
        or any(len(line) > 2048 for line in value.split("\n"))
    ):
        _fail("AWS_CLI_OUTPUT_INVALID")
    return value


def _location(bucket: Any, key: Any) -> Location:
    if (
        not isinstance(bucket, str)
        or not isinstance(key, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
        or re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", key) is None
        or "//" in key
        or any(p in (".", "..") for p in key.split("/"))
        or not key.endswith(".json.gz")
    ):
        _fail("AWS_CLI_SOURCE_LOCATION")
    return bucket, key


def _source(
    value: Any, scope: AwsScope, prefix: str, execution: tuple[datetime, datetime]
) -> tuple[Location, dict[str, Any]]:
    obs = _dict(value, _SOURCE_KEYS)
    location = _location(obs["bucket"], obs["key"])
    if location[0] != scope.bucket or not location[1].startswith(prefix):
        _fail("AWS_CLI_SOURCE_SCOPE", "conflicting")
    for key in ("archive_sha256", "content_sha256"):
        if not isinstance(obs[key], str) or _HASH.fullmatch(obs[key]) is None:
            _fail("AWS_CLI_SOURCE_HASH")
    for key in ("version_id", "before_version_id", "after_version_id"):
        version = obs[key]
        if (
            not isinstance(version, str)
            or version == "null"
            or re.fullmatch(r"[A-Za-z0-9._+~=/:-]{1,1024}", version) is None
        ):
            _fail("AWS_CLI_SOURCE_VERSION")
    if not obs["before_version_id"] == obs["version_id"] == obs["after_version_id"]:
        _fail("AWS_CLI_SOURCE_CHANGED", "conflicting")
    before, after = _stamp(obs["before_observed_at"]), _stamp(obs["after_observed_at"])
    if not before <= execution[0] <= execution[1] <= after:
        _fail("AWS_CLI_SOURCE_OBSERVATION_INTERVAL", "conflicting")
    return location, obs


@dataclass(frozen=True, slots=True)
class _Output:
    digests: dict[Location, str]
    logs: dict[Location, Location]
    found: tuple[datetime, datetime] | None


def _output(stdout: str, stderr: str, scope: AwsScope, start: datetime, end: datetime) -> _Output:
    """Exact successful verbose grammar from the pinned official implementation."""
    if stderr:
        gap = (
            r"(?:\(backfill\) )?No log files were delivered by CloudTrail between "
            rf"{_DATE} and {_DATE}"
        )
        lines = [line for line in stderr.split("\n") if line]
        if lines and all(re.fullmatch(gap, line) is not None for line in lines):
            _fail("AWS_CLI_DIGEST_GAP", "incomplete")
        _fail("AWS_CLI_DIAGNOSTIC_PRESENT")
    header = (
        f"Validating log files for trail {scope.trail_arn} between "
        f"{_format(start)} and {_format(end)}\n\n"
    )
    requested = f"Results requested for {_format(start)} to {_format(end)}\n"
    if not stdout.startswith(header) or not stdout.endswith("\n"):
        _fail("AWS_CLI_OUTPUT_INVALID")
    body, separator, tail = stdout[len(header) :].partition(requested)
    if not separator or requested in tail:
        _fail("AWS_CLI_OUTPUT_INCOMPLETE", "incomplete")
    digests: dict[Location, str] = {}
    logs: dict[Location, Location] = {}
    parent: Location | None = None
    backfill_seen = False
    if body:
        if not body.endswith("\n\n"):
            _fail("AWS_CLI_OUTPUT_INVALID")
        for line in body[:-2].split("\n"):
            match = re.fullmatch(
                r"(\(backfill\) )?(Digest|Log) file\ts3://([^/\t]+)/([^\t]+)\tvalid", line
            )
            if match is None:
                _fail("AWS_CLI_OUTPUT_INVALID")
            backfill, kind, bucket, key = match.groups()
            location = _location(bucket, key)
            if kind == "Digest":
                chain = "backfill" if backfill else "standard"
                if (
                    location in digests
                    or (backfill_seen and not backfill)
                    or bool(backfill) != key.endswith("_backfill.json.gz")
                ):
                    _fail("AWS_CLI_OUTPUT_CONFLICT", "conflicting")
                backfill_seen = backfill_seen or bool(backfill)
                digests[location], parent = chain, location
            else:
                if backfill or parent is None or location in logs:
                    _fail("AWS_CLI_OUTPUT_DUPLICATE_OR_ORPHAN")
                logs[location] = parent
    if len(digests) > 64 or len(logs) > 256:
        _fail("AWS_CLI_RECEIPT_LIMIT")
    if not digests:
        if tail != "No digests found\n" or logs:
            _fail("AWS_CLI_OUTPUT_INVALID")
        return _Output(digests, logs, None)
    found_line, sep, ratios = tail.partition("\n")
    found_match = re.fullmatch(rf"Results found for ({_DATE}) to ({_DATE}):", found_line)
    if not sep or found_match is None:
        _fail("AWS_CLI_OUTPUT_INVALID")
    found = _stamp(found_match[1]), _stamp(found_match[2])
    if not start <= found[0] <= found[1] <= end:
        _fail("AWS_CLI_OUTPUT_INTERVAL", "conflicting")
    expected = ""
    for label, count in (
        ("digest", list(digests.values()).count("standard")),
        ("backfill digest", list(digests.values()).count("backfill")),
        ("log", len(logs)),
    ):
        if count:
            expected += f"\n{count}/{count} {label} files valid"
    if ratios != expected + "\n":
        _fail("AWS_CLI_OUTPUT_COUNTS", "conflicting")
    return _Output(digests, logs, found)


def _assess(
    objects: tuple[RetrievedLog, ...], scope: AwsScope, start: datetime, end: datetime, raw: bytes
) -> CliReceiptAssessment:
    if type(scope) is not AwsScope or type(objects) is not tuple or not 1 <= len(objects) <= 64:
        _fail("AWS_CLI_EXPECTED_SOURCE_REQUIRED")
    start, end = _time(start), _time(end)
    if not start < end or end - start > timedelta(days=1):
        _fail("AWS_CLI_RECEIPT_TIME")
    envelope = _loads(raw)
    _dict(
        envelope,
        {
            "schema_version",
            "tool_version",
            "output_contract",
            "scope",
            "execution",
            "standard_chain",
            "backfill_chain",
            "sources",
            "digests",
        },
    )
    if (
        envelope["schema_version"] != RECEIPT_SCHEMA
        or envelope["tool_version"] != SUPPORTED_CLI_VERSION
        or envelope["output_contract"] != OUTPUT_CONTRACT
    ):
        _fail("AWS_CLI_OUTPUT_CONTRACT_UNSUPPORTED", "unsupported")
    root = scope.log_prefix.removesuffix(f"AWSLogs/{scope.account}/CloudTrail/{scope.region}/")
    expected_scope = {
        "account": scope.account,
        "region": scope.region,
        "trail_arn": scope.trail_arn,
        "bucket": scope.bucket,
        "s3_prefix": root.removesuffix("/"),
        "start_time": _format(start),
        "end_time": _format(end),
    }
    if _dict(envelope["scope"], set(expected_scope)) != expected_scope:
        _fail("AWS_CLI_SCOPE_CONFLICT", "conflicting")
    run = _dict(
        envelope["execution"], {"started_at", "completed_at", "exit_code", "stdout", "stderr"}
    )
    execution = _stamp(run["started_at"]), _stamp(run["completed_at"])
    if (
        execution[1] < execution[0]
        or execution[1] - execution[0] > timedelta(days=1)
        or type(run["exit_code"]) is not int
        or run["exit_code"] != 0
    ):
        _fail("AWS_CLI_EXECUTION_FAILED")
    output = _output(_stream(run["stdout"]), _stream(run["stderr"]), scope, start, end)
    observations: dict[Location, dict[str, Any]] = {}
    for source in _list(envelope["sources"], 64):
        location, obs = _source(source, scope, scope.log_prefix, execution)
        if location in observations:
            _fail("AWS_CLI_DUPLICATE_SOURCE", "conflicting")
        observations[location] = obs
    digest_locations: dict[Location, str] = {}
    members: dict[Location, str] = {}
    digest_members: dict[Location, set[Location]] = {}
    intervals: dict[str, list[tuple[datetime, datetime]]] = {"standard": [], "backfill": []}
    for entry in _list(envelope["digests"], 64):
        entry = _dict(entry, {"source", "content"})
        location, obs = _source(entry["source"], scope, scope.digest_prefix, execution)
        if location in digest_locations:
            _fail("AWS_CLI_DUPLICATE_DIGEST", "conflicting")
        content = entry["content"]
        if not isinstance(content, str) or len(content.encode("utf-8")) > 256 * 1024:
            _fail("AWS_CLI_RECEIPT_LIMIT")
        if sha256(content.encode("utf-8")).hexdigest() != obs["content_sha256"]:
            _fail("AWS_CLI_DIGEST_CONTENT_CONFLICT", "conflicting")
        digest = _loads(content.encode("utf-8"))
        if (
            digest.get("awsAccountId") != scope.account
            or (digest.get("digestS3Bucket"), digest.get("digestS3Object")) != location
        ):
            _fail("AWS_CLI_DIGEST_SOURCE_CONFLICT", "conflicting")
        first, last = _stamp(digest.get("digestStartTime")), _stamp(digest.get("digestEndTime"))
        if first >= last:
            _fail("AWS_CLI_DIGEST_INTERVAL")
        chain = "backfill" if location[1].endswith("_backfill.json.gz") else "standard"
        digest_locations[location] = chain
        intervals[chain].append((first, last))
        locations: set[Location] = set()
        for member in _list(digest.get("logFiles"), 256):
            member = _dict(member)
            if (
                not {"s3Bucket", "s3Object", "hashValue", "hashAlgorithm"} <= set(member)
                or set(member)
                - {
                    "s3Bucket",
                    "s3Object",
                    "hashValue",
                    "hashAlgorithm",
                    "oldestEventTime",
                    "newestEventTime",
                }
                or member["hashAlgorithm"] != "SHA-256"
                or not isinstance(member["hashValue"], str)
                or _HASH.fullmatch(member["hashValue"]) is None
            ):
                _fail("AWS_CLI_DIGEST_MEMBER_INVALID")
            member_location = _location(member["s3Bucket"], member["s3Object"])
            if member_location[0] != scope.bucket or not member_location[1].startswith(
                scope.log_prefix
            ):
                _fail("AWS_CLI_MEMBER_SCOPE_CONFLICT", "conflicting")
            if member_location in members:
                _fail("AWS_CLI_DUPLICATE_MEMBER", "conflicting")
            members[member_location] = member["hashValue"]
            locations.add(member_location)
            if len(members) > 256:
                _fail("AWS_CLI_RECEIPT_LIMIT")
        digest_members[location] = locations
    if output.digests != digest_locations:
        _fail("AWS_CLI_DIGEST_OUTPUT_CONFLICT", "conflicting")
    if set(output.logs) != set(members) or any(
        location not in digest_members[parent] for location, parent in output.logs.items()
    ):
        _fail("AWS_CLI_MEMBER_OUTPUT_CONFLICT", "conflicting")
    for chain, spans in intervals.items():
        claim = _dict(envelope[f"{chain}_chain"], {"outcome", "complete"})
        if (
            claim["outcome"] not in ("valid", "invalid", "pending", "absent")
            or type(claim["complete"]) is not bool
        ):
            _fail("AWS_CLI_CHAIN_OBSERVATION")
        if claim["outcome"] == "invalid":
            _fail("AWS_CLI_CHAIN_INVALID")
        if not claim["complete"] or claim["outcome"] == "pending":
            _fail("AWS_CLI_CHAIN_INCOMPLETE", "incomplete")
        if (claim["outcome"] == "absent") != (not spans):
            _fail("AWS_CLI_CHAIN_CONFLICT", "conflicting")
        covered = start
        for first, last in sorted(spans):
            if first > covered:
                _fail("AWS_CLI_DIGEST_COVERAGE_GAP", "incomplete")
            covered = max(covered, last)
        if spans and covered < end:
            _fail("AWS_CLI_DIGEST_COVERAGE_GAP", "incomplete")
    if not digest_locations:
        _fail("AWS_CLI_DIGESTS_MISSING", "incomplete")
    all_spans = intervals["standard"] + intervals["backfill"]
    found = (
        max(start, min(first for first, _ in all_spans)),
        min(end, max(last for _, last in all_spans)),
    )
    if output.found != found:
        _fail("AWS_CLI_FOUND_INTERVAL_CONFLICT", "conflicting")
    expected: set[Location] = set()
    for obj in objects:
        if (
            type(obj) is not RetrievedLog
            or type(obj.reference) is not ObjectVersion
            or type(obj.log) is not AwsLog
        ):
            _fail("AWS_CLI_EXPECTED_SOURCE_REQUIRED")
        location = _location(obj.reference.bucket, obj.reference.key)
        if location in expected:
            _fail("AWS_CLI_DUPLICATE_EXPECTED_SOURCE", "conflicting")
        expected.add(location)
        retained = observations.get(location)
        if retained is None or location not in members:
            _fail("AWS_CLI_EXPECTED_MEMBER_MISSING", "incomplete")
        obs = retained
        if (
            obs["version_id"] != obj.reference.version_id
            or obs["archive_sha256"] != obj.log.archive_sha256
            or obs["content_sha256"] != obj.log.content_sha256
            or members[location] != obj.log.content_sha256
        ):
            _fail("AWS_CLI_EXPECTED_SOURCE_CONFLICT", "conflicting")
        if not (
            _stamp(obs["before_observed_at"])
            <= _time(obj.retrieval_started)
            <= _time(obj.retrieval_completed)
            <= _stamp(obs["after_observed_at"])
        ):
            _fail("AWS_CLI_RETRIEVAL_INTERVAL_CONFLICT", "conflicting")
        # Select the existing bounded byte-consistency path only. These local
        # flags are not parsed CLI fields or authenticated signature/chain facts.
        controlled = ControlledValidation(
            SUPPORTED_CLI_VERSION,
            0,
            CheckOutcome.VALID,
            CheckOutcome.VALID,
            CheckOutcome.VALID,
            (DigestMember(*location, obj.reference.version_id, members[location]),),
            True,
            True,
        )
        assessment = assess_digest(obj, controlled)
        if not assessment.consistency_passed:
            _fail(assessment.reason)
    if expected != set(observations):
        _fail("AWS_CLI_SOURCE_SET_CONFLICT", "conflicting")
    return CliReceiptAssessment(
        "pending_source_authentication",
        "AWS_AUTHENTICATION_UNAVAILABLE",
        True,
        len(objects),
        len(digest_locations),
    )


def assess_cli_receipt(
    objects: tuple[RetrievedLog, ...],
    scope: AwsScope,
    start: datetime,
    end: datetime,
    receipt: bytes | None,
) -> CliReceiptAssessment:
    """Compare supplied observations only; fabricated agreement never proves AWS origin."""
    if receipt is None:
        return CliReceiptAssessment("missing", "AWS_CLI_RECEIPT_MISSING")
    if type(receipt) is not bytes:
        return CliReceiptAssessment("invalid", "AWS_CLI_RECEIPT_STRUCTURE")
    try:
        return _assess(objects, scope, start, end, receipt)
    except _Rejected as exc:
        return CliReceiptAssessment(exc.state, exc.reason)
    except EvidenceError:
        return CliReceiptAssessment("invalid", "AWS_CLI_RETAINED_EVIDENCE_INVALID")
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError, AttributeError):
        return CliReceiptAssessment("invalid", "AWS_CLI_RECEIPT_INVALID")
