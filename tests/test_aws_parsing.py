"""The AWS-shaped boundary never promotes locally supplied evidence to trusted data."""

import gzip
import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cloudsecops_live.cli import main
from cloudsecops_live.contracts import Limits, NormalizedEvent, ParsedLog
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes
from cloudsecops_live.integrations.aws_cloudtrail import AwsLog, parse_aws_shaped
from tests.aws_helpers import archive, event, scope


def test_preserves_archive_content_and_general_management_event() -> None:
    record = event()
    record.update(eventSource="iam.amazonaws.com", eventName="CreateRole", readOnly=False)
    data = archive([record])
    result = parse_aws_shaped(data, scope())
    normalized = result.events[0]
    assert result.archive_bytes == data
    assert result.content_bytes == gzip.decompress(data)
    assert result.archive_sha256 == hashlib.sha256(data).hexdigest()
    assert result.content_sha256 == hashlib.sha256(gzip.decompress(data)).hexdigest()
    assert result.archive_sha256 != result.content_sha256
    assert normalized.identity == ("1" * 12, "us-east-1", record["eventID"])
    assert normalized.event_source == "iam.amazonaws.com"
    assert normalized.event_name == "CreateRole" and normalized.read_only is False
    assert normalized.event_category == "Management" and normalized.event_type == "AwsApiCall"
    assert normalized.record_index == 0 and normalized.has_error is False
    assert normalized.event_time == datetime(2026, 1, 1, tzinfo=UTC)
    assert normalized.record_sha256 == hashlib.sha256(normalized.canonical_record).hexdigest()
    assert json.loads(normalized.canonical_record) == record


def test_models_are_separate_immutable_and_cannot_set_authentication() -> None:
    result = parse_aws_shaped(archive(), scope())
    assert not isinstance(result, ParsedLog)
    assert not isinstance(result.events[0], NormalizedEvent)
    assert result.source_kind == "aws_shaped_unverified" and result.authenticated is False
    assert result.schema_version == "aws-offline/1"
    with pytest.raises(FrozenInstanceError):
        result.authenticated = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        AwsLog(b"", b"", "", "", (), authenticated=True)  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "changes",
    [
        {"account": "LABACCOUNT_A"},
        {"account": "١" * 12},
        {"region": "us-gov-west-1"},
        {"region": "cn-north-1"},
        {"region": "us-east-1\x00"},
        {"role_arn": "arn:aws:iam::" + "2" * 12 + ":role/OfflineCollector"},
        {"role_arn": "arn:aws:iam::" + "1" * 12 + ":user/OfflineCollector"},
        {"role_arn": "arn:aws:iam::" + "1" * 12 + ":role/a/../OfflineCollector"},
        {"role_arn": "arn:aws:iam::" + "1" * 12 + ":role/./OfflineCollector"},
        {"role_id": "OfflineCollector"},
        {"trail_arn": "arn:aws:cloudtrail:us-west-2:" + "1" * 12 + ":trail/offline-lab"},
        {"trail_arn": "arn:aws:cloudtrail:us-east-1:" + "2" * 12 + ":trail/offline-lab"},
        {"trail_arn": "arn:aws:cloudtrail:us-east-1:" + "1" * 12 + ":trail/*"},
        {"bucket": "s3://offline-evidence-lab"},
        {"bucket": "Offline-evidence-lab"},
        {"bucket": "127.0.0.1"},
        {"bucket": "offline..evidence-lab"},
        {"log_prefix": "../AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1/"},
        {"log_prefix": "AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1"},
        {"log_prefix": "s3://x/AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1/"},
        {"log_prefix": "offline-lab//AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1/"},
        {"log_prefix": "offline-lab/AWSLogs/" + "2" * 12 + "/CloudTrail/us-east-1/"},
        {"digest_prefix": "other/AWSLogs/" + "1" * 12 + "/CloudTrail-Digest/us-east-1/"},
        {"digest_prefix": "offline-lab/AWSLogs/" + "1" * 12 + "/CloudTrail-Digest/us-west-2/"},
    ],
)
def test_scope_rejects_unbounded_or_inconsistent_configuration(changes: dict[str, str]) -> None:
    with pytest.raises(EvidenceError) as caught:
        scope(**changes)
    assert caught.value.code == "INVALID_AWS_SCOPE"
    assert len(str(caught.value)) < 100


def test_scope_accepts_shared_fixed_custom_root_or_no_custom_root() -> None:
    configured = scope()
    assert configured.account == "1" * 12
    assert replace(
        configured,
        log_prefix=configured.log_prefix.removeprefix("offline-lab/"),
        digest_prefix=configured.digest_prefix.removeprefix("offline-lab/"),
    ).log_prefix.startswith("AWSLogs/")


@pytest.mark.parametrize(
    "changes",
    [
        {"recipientAccountId": "2" * 12},
        {"recipientAccountId": "LABACCOUNT_A"},
        {"awsRegion": "us-west-2"},
        {"eventID": "not-a-uuid"},
        {"eventID": "a" * 32},
        {"eventCategory": "Data"},
        {"eventCategory": "NetworkActivity"},
        {"eventTime": "2026-02-30T00:00:00Z"},
        {"readOnly": "true"},
        {"eventSource": {}},
        {"eventName": ""},
        {"errorCode": []},
        {"errorMessage": {}},
    ],
)
def test_rejects_wrong_scope_category_or_required_schema(changes: dict[str, object]) -> None:
    record = event()
    record.update(changes)
    with pytest.raises(EvidenceError):
        parse_aws_shaped(archive([record]), scope())


def test_session_identity_uses_aws_formats_and_does_not_require_collector_role() -> None:
    normalized = parse_aws_shaped(archive(), scope()).events[0]
    session = normalized.session
    assert session is not None and normalized.identity_reason is None
    assert session.issuer_arn.endswith(":role/ObservedRole")
    assert session.issuer_arn != scope().role_arn
    assert session.access_key_id == "ASIA" + "A" * 16
    assert session.creation_time == datetime(2025, 12, 31, 23, tzinfo=UTC)
    other = event(actor_account="2" * 12)
    cross_account = parse_aws_shaped(archive([other]), scope()).events[0]
    assert cross_account.session is not None
    assert cross_account.session.account == "2" * 12


@pytest.mark.parametrize("kind", ["Root", "IAMUser", "AWSService", "IdentityCenterUser", None])
def test_unsupported_actors_remain_hashed_events_with_no_session(kind: str | None) -> None:
    record = event()
    record["userIdentity"] = {"type": kind, "unknownActor": "preserve-me"}
    normalized = parse_aws_shaped(archive([record]), scope()).events[0]
    assert normalized.session is None and normalized.identity_reason is not None
    assert b"preserve-me" in normalized.canonical_record


@pytest.mark.parametrize(
    "change",
    ["issuer_account", "principal", "actor_arn", "key", "missing_context", "future", "creation"],
)
def test_inconsistent_session_identity_is_retained_without_session(change: str) -> None:
    record = event()
    user = record["userIdentity"]
    if change == "issuer_account":
        user["sessionContext"]["sessionIssuer"]["accountId"] = "2" * 12
    elif change == "principal":
        user["principalId"] = "AROA" + "C" * 17 + ":offline-session"
    elif change == "actor_arn":
        user["arn"] += "wrong"
    elif change == "key":
        user["accessKeyId"] = "SYNTHETIC_KEY_A"
    elif change == "missing_context":
        del user["sessionContext"]
    elif change == "future":
        user["sessionContext"]["attributes"]["creationDate"] = "2026-01-02T00:00:00Z"
    else:
        user["sessionContext"]["attributes"]["creationDate"] = "not-time"
    normalized = parse_aws_shaped(archive([record]), scope()).events[0]
    assert normalized.session is None and normalized.identity_reason is not None
    assert json.loads(normalized.canonical_record) == record


def test_unknown_fields_and_forged_record_trust_are_retained_before_derivation() -> None:
    first = event()
    second = event()
    second.update(
        unknown={"keep": [1, False, None]}, authenticated=True, source_kind="aws_verified"
    )
    one = parse_aws_shaped(archive([first]), scope())
    two = parse_aws_shaped(archive([second]), scope())
    assert one.events[0].identity == two.events[0].identity
    assert one.events[0].record_sha256 != two.events[0].record_sha256
    assert json.loads(two.events[0].canonical_record) == second
    assert two.authenticated is False and two.source_kind == "aws_shaped_unverified"


@pytest.mark.parametrize(
    "content",
    [
        b'{"Records":[],"Records":[]}',
        b'{"Records":[{"x":1,"x":2}]}',
        b'{"Records":[{"unknown":NaN}]}',
        b'{"Records":[{"unknown":Infinity}]}',
        b'{"Records":[{"unknown":-Infinity}]}',
        b'{"Records":[{"unknown":1e309}]}',
        b'{"Records":[{"bad\\u0000key":true}]}',
        b'{"Records":[{"unknown":{"bad":"x\\u0000y"}}]}',
        b'{"Records":[{"unknown":"\\ud800"}]}',
        b'{"Records":[{"unknown":"\\udc00"}]}',
        b'{"Records":[],"authenticated":true}',
        b'{"Records":[],"source_kind":"aws_verified"}',
        b'{"Records":[],"fixture_schema_version":"1.0","source_kind":"synthetic"}',
        b'{"Records":{}}',
        b'{"Records":[null]}',
        b"[]",
        b"null",
        b"\xff",
        b"{",
    ],
)
def test_malicious_content_is_rejected_with_fixed_errors(content: bytes) -> None:
    with pytest.raises(EvidenceError) as caught:
        parse_aws_shaped(gzip.compress(content), scope())
    assert len(str(caught.value)) < 100
    assert "bad" not in str(caught.value) and "unknown" not in str(caught.value)


def test_decimal_canonicalization_preserves_full_unknown_precision() -> None:
    content = gzip.decompress(archive()).replace(b'"readOnly":true', b'"readOnly":true,"n":1.0001')
    first = parse_aws_shaped(gzip.compress(content), scope()).events[0]
    second = parse_aws_shaped(gzip.compress(content.replace(b"1.0001", b"1.0002")), scope()).events[
        0
    ]
    assert b'"n":1.0001' in first.canonical_record
    assert first.record_sha256 != second.record_sha256


def test_bounds_compressed_expanded_and_record_count_before_import() -> None:
    data = archive()
    content = gzip.decompress(data)
    exact = Limits(max_compressed_bytes=len(data), max_expanded_bytes=len(content), max_records=1)
    assert len(parse_aws_shaped(data, scope(), limits=exact).events) == 1
    for limits, candidate in [
        (replace(exact, max_compressed_bytes=len(data) - 1), data),
        (replace(exact, max_expanded_bytes=len(content) - 1), data),
        (Limits(max_records=1), archive([event(), event()])),
        (Limits(max_string_length=10), data),
        (Limits(max_depth=2), data),
        (Limits(max_nodes=2), data),
        (Limits(max_number_length=2), gzip.compress(b'{"Records":[123]}')),
    ]:
        with pytest.raises(EvidenceError):
            parse_aws_shaped(candidate, scope(), limits=limits)


def test_empty_records_and_invalid_input_transport() -> None:
    assert parse_aws_shaped(archive([]), scope()).events == ()
    data = archive()
    for candidate in [data[:-1], data + b"junk", data + data, b"not gzip", "not bytes"]:
        with pytest.raises(EvidenceError):
            parse_aws_shaped(candidate, scope())  # type: ignore[arg-type]


def test_runtime_limits_cannot_be_replaced_with_unbounded_duck_type() -> None:
    class UnsafeLimits:
        max_compressed_bytes = 1_000_000_000
        max_expanded_bytes = 1_000_000_000
        max_records = 1_000_000
        max_depth = 1_000_000
        max_string_length = 1_000_000
        max_nodes = 1_000_000
        max_number_length = 1_000_000

    with pytest.raises(EvidenceError) as caught:
        parse_aws_shaped(archive([]), scope(), limits=UnsafeLimits())  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_LIMITS"


def test_raw_aws_envelope_is_rejected_by_synthetic_parser_and_cli(tmp_path: Path) -> None:
    data = archive()
    with pytest.raises(EvidenceError) as caught:
        parse_bytes(data)
    assert caught.value.code == "INVALID_FIXTURE_ENVELOPE"
    candidate = tmp_path / "aws-shaped.json.gz"
    candidate.write_bytes(data)
    for command in ["import-synthetic", "detect-synthetic"]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main([command, str(candidate)])
        assert status == 2 and out.getvalue() == ""
        assert json.loads(err.getvalue())["error"]["code"] == "INVALID_FIXTURE_ENVELOPE"
