"""Hand-checked scenarios for the offline inventory-burst detector."""

from __future__ import annotations

import gzip
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import permutations

import pytest

from cloudsecops_live.contracts import (
    EventIdentity,
    NormalizedEvent,
    ParsedLog,
    Provenance,
    ProvenanceState,
    RawEvidence,
    RecordReference,
    SessionIdentity,
)
from cloudsecops_live.detection import detect
from cloudsecops_live.errors import EvidenceError


def record(event_id: str, seconds: float = 0, **changes: object) -> dict[str, object]:
    """A complete synthetic source record; expected outcomes never use this helper."""
    value: dict[str, object] = {
        "eventVersion": "1.09",
        "eventID": event_id,
        "eventTime": (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z"),
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "recipientAccountId": "LABACCOUNT_A",
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "readOnly": True,
        "responseElements": None,
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "LABACCOUNT_A",
            "principalId": "LABROLEID_A:lab-session",
            "arn": "arn:aws:sts::LABACCOUNT_A:assumed-role/LabRole/lab-session",
            "accessKeyId": "SYNTHETIC_KEY_A",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "LABROLEID_A",
                    "arn": "arn:aws:iam::LABACCOUNT_A:role/LabRole",
                    "accountId": "LABACCOUNT_A",
                    "userName": "LabRole",
                },
                "attributes": {"creationDate": "2025-12-31T23:00:00Z"},
            },
        },
    }
    value.update(changes)
    return value


def archive(*records: dict[str, object], source: str = "unit.json.gz", mtime: int = 0) -> ParsedLog:
    """Construct immutable normalized fixtures, independent of the production parser."""
    body = json.dumps(records, sort_keys=True).encode()
    compressed = gzip.compress(body, mtime=mtime)
    archive_hash, content_hash = sha256(compressed).hexdigest(), sha256(body).hexdigest()
    events = []
    for index, value in enumerate(records):
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        identity = EventIdentity(
            "synthetic",
            str(value["recipientAccountId"]),
            str(value["awsRegion"]),
            str(value["eventID"]),
        )
        raw_identity = value["userIdentity"]
        assert isinstance(raw_identity, dict)
        session = None
        if raw_identity.get("type") == "AssumedRole":
            session = SessionIdentity(
                identity.account,
                identity.region,
                "arn:aws:iam::LABACCOUNT_A:role/LabRole",
                "SYNTHETIC_KEY_A",
                "2025-12-31T23:00:00Z",
            )
        events.append(
            NormalizedEvent(
                identity=identity,
                event_time=datetime.fromisoformat(str(value["eventTime"])),
                event_source=str(value["eventSource"]),
                event_name=str(value["eventName"]),
                event_category=str(value["eventCategory"]),
                event_type=str(value["eventType"]),
                read_only=value["readOnly"] if isinstance(value["readOnly"], bool) else None,
                has_error="errorCode" in value or "errorMessage" in value,
                session=session,
                identity_reason=None if session else "not_assumed_role",
                canonical_record=canonical,
                record_sha256=sha256(canonical).hexdigest(),
                references=(RecordReference(source, index, archive_hash, content_hash),),
            )
        )
    return ParsedLog(
        RawEvidence(source, compressed, body, archive_hash, content_hash), tuple(events)
    )


def evidence(report):
    return [finding.to_dict()["evidence_event_ids"] for finding in report.findings]


def test_empty_batch_has_no_findings_or_conflicts():
    report = detect([])
    assert report.to_dict()["findings"] == []
    assert report.to_dict()["events"] == []
    assert report.has_conflicts is False


@pytest.mark.parametrize(
    ("times", "expected"),
    [
        ((0, 20), []),
        ((0, 30, 60), [["a", "b", "c"]]),
        ((0, 30, 60.000001), []),
        ((0, 0, 0), [["a", "b", "c"]]),
        ((0, 30, 60, 90, 120), [["a", "b", "c", "d", "e"]]),
        ((0, 10, 20, 100, 110, 120), [["a", "b", "c"], ["d", "e", "f"]]),
        ((0, 1, 2, 62, 63, 64), [["a", "b", "c"], ["d", "e", "f"]]),
        ((0, 60, 120, 180), []),
    ],
)
def test_inclusive_unique_windows_and_transitive_components(times, expected):
    records = [record(chr(97 + index), seconds) for index, seconds in enumerate(times)]
    assert evidence(detect([archive(*records)])) == expected


def test_component_window_records_full_span_with_candidate_and_visibility_limits():
    report = detect([archive(record("a", 0), record("b", 30), record("c", 60), record("d", 90))])
    finding = report.findings[0].to_dict()
    assert finding["evidence_event_ids"] == ["a", "b", "c", "d"]
    assert finding["count"] == 4
    assert finding["window_start"] == "2026-01-01T00:00:00Z"
    assert finding["window_end"] == "2026-01-01T00:01:30Z"
    assert finding["rule_id"] == "AWS-LAB-001"
    assert finding["rule_version"] == "1.0"
    assert finding["status"] == "synthetic_candidate"
    assert finding["attack"] == {"technique_id": "T1580", "name": "Cloud Infrastructure Discovery"}
    assert any("benign" in item.lower() for item in finding["limitations"])
    assert any("visibility" in item.lower() for item in finding["limitations"])
    assert "60" in finding["window_explanation"]


def test_duplicate_deliveries_retain_refs_but_never_reach_threshold():
    first = archive(record("a", 0), record("b", 30), source="first.gz")
    second = archive(record("a", 0), record("b", 30), source="second.gz", mtime=12)
    report = detect([first, second])
    assert evidence(report) == []
    result = report.to_dict()
    assert result["delivery_count"] == 4
    assert result["unique_event_count"] == 2
    assert [item["delivery_count"] for item in result["events"]] == [2, 2]
    assert [ref["source_ref"] for ref in result["events"][0]["references"]] == [
        "first.gz",
        "second.gz",
    ]
    assert len(first.events[0].references) == 1


def test_unknown_field_conflict_fails_closed_for_entire_batch():
    good = archive(record("a", 0), record("b", 10), record("c", 20))
    changed = archive(record("a", 0, futureField={"new": "value"}), source="conflict.gz")
    report = detect([good, changed])
    assert report.has_conflicts is True
    assert evidence(report) == []
    assert report.to_dict()["provenance"] == "conflicting"
    assert report.to_dict()["conflicts"][0]["identity"]["event_id"] == "a"
    assert report.to_dict()["delivery_count"] == 4


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"eventSource": "s3.amazonaws.com"}, "event_source_mismatch"),
        ({"eventName": "DescribeInstanceStatus"}, "event_name_mismatch"),
        ({"eventCategory": "Data"}, "event_category_mismatch"),
        ({"eventType": "AwsServiceEvent"}, "event_type_mismatch"),
        ({"readOnly": False}, "not_read_only"),
        ({"readOnly": "true"}, "not_read_only"),
        ({"errorCode": "AccessDenied"}, "aws_error"),
        ({"errorMessage": "denied"}, "aws_error"),
        ({"userIdentity": {"type": "IAMUser"}}, "invalid_session"),
    ],
)
def test_exact_qualification_has_bounded_explicit_reasons(changes, reason):
    report = detect([archive(record("a"), record("b", 10), record("c", 20, **changes))])
    assert evidence(report) == []
    assert report.to_dict()["events"][2]["reasons"] == [reason]


def test_missing_session_normalizer_reason_never_becomes_a_qualifying_event():
    log = archive(record("a"), record("b", 10), record("c", 20))
    event = replace(log.events[2], session=None)
    report = detect([replace(log, events=(*log.events[:2], event))])
    assert evidence(report) == []
    assert report.to_dict()["events"][2]["reasons"] == ["invalid_session"]


@pytest.mark.parametrize(
    "field", ["account", "region", "issuer_arn", "access_key_id", "creation_time"]
)
def test_every_credential_session_key_field_prevents_cross_session_join(field):
    log = archive(record("a"), record("b", 10), record("c", 20))
    original = log.events[2]
    assert original.session is not None
    replacement = {
        "account": "LABACCOUNT_B",
        "region": "us-west-2",
        "issuer_arn": "arn:aws:iam::LABACCOUNT_A:role/OtherRole",
        "access_key_id": "SYNTHETIC_KEY_B",
        "creation_time": "2025-12-31T22:00:00Z",
    }[field]
    changed = replace(original, session=replace(original.session, **{field: replacement}))
    assert evidence(detect([replace(log, events=(*log.events[:2], changed))])) == []


def test_finding_identity_survives_input_order_paths_and_gzip_headers():
    records = (record("c", 60), record("a", 0), record("b", 30))
    baseline = detect([archive(*records)]).findings[0].to_dict()
    for order in permutations(records):
        result = detect([archive(*order, source="different.gz", mtime=123)]).findings[0].to_dict()
        assert result == baseline


def test_stable_finding_identity_binds_unknown_source_content():
    baseline = detect([archive(record("a"), record("b", 10), record("c", 20))])
    changed = detect([archive(record("a", futureField=True), record("b", 10), record("c", 20))])
    assert (
        baseline.findings[0].to_dict()["finding_id"] != changed.findings[0].to_dict()["finding_id"]
    )


def test_full_identity_keeps_same_event_id_in_different_account_or_region_distinct():
    first = archive(record("same"))
    second = archive(record("same", recipientAccountId="LABACCOUNT_B"))
    third = archive(record("same", awsRegion="us-west-2"))
    report = detect([first, second, third])
    assert report.has_conflicts is False
    assert report.to_dict()["unique_event_count"] == 3
    assert evidence(report) == []


@pytest.mark.parametrize("field", ["schema_version", "parser_version", "canonicalization_version"])
def test_unsupported_derivative_versions_are_rejected(field):
    log = archive(record("a"))
    changed = replace(log.events[0], **{field: "999"})
    with pytest.raises(EvidenceError, match="UNSUPPORTED_VERSION"):
        detect([replace(log, events=(changed,))])


def test_detector_bounds_aggregate_deliveries_and_input_logs():
    empty = archive()
    with pytest.raises(EvidenceError, match="DETECTION_LIMIT"):
        detect([empty] * 65)
    single = archive(record("a"))
    with pytest.raises(EvidenceError, match="DETECTION_LIMIT"):
        detect([replace(single, events=single.events * 10001)])


def test_duplicate_deliveries_do_not_change_finding_content_or_identity():
    first = archive(record("a"), record("b", 10), record("c", 20), source="first.gz")
    second = archive(record("c", 20), record("a"), record("b", 10), source="second.gz", mtime=12)
    assert detect([first]).findings[0].to_dict() == detect([second, first]).findings[0].to_dict()
    assert detect([second, first]).to_dict() == detect([first, second]).to_dict()


@pytest.mark.parametrize("field", ["schema_version", "parser_version", "canonicalization_version"])
def test_unsupported_archive_versions_are_rejected_even_without_events(field):
    log = archive()
    with pytest.raises(EvidenceError, match="UNSUPPORTED_VERSION"):
        detect([replace(log, evidence=replace(log.evidence, **{field: "999"}))])


@pytest.mark.parametrize(
    "state", [ProvenanceState.PENDING, ProvenanceState.UNVERIFIED, ProvenanceState.CONFLICTING]
)
def test_non_synthetic_derivatives_cannot_be_reinterpreted_as_synthetic(state):
    log = archive(record("a"))
    provenance = Provenance(state=state)
    with pytest.raises(EvidenceError, match="INVALID_PROVENANCE"):
        detect([replace(log, evidence=replace(log.evidence, provenance=provenance))])
    with pytest.raises(EvidenceError, match="INVALID_PROVENANCE"):
        detect([replace(log, events=(replace(log.events[0], provenance=provenance),))])


def test_forged_source_kind_is_rejected_at_detector_boundary():
    log = archive(record("a"))
    forged_identity = replace(log.events[0].identity)
    object.__setattr__(forged_identity, "source_kind", "aws")
    changed = replace(log.events[0], identity=forged_identity)
    with pytest.raises(EvidenceError, match="INVALID_PROVENANCE"):
        detect([replace(log, events=(changed,))])


def test_naive_event_time_is_rejected_with_a_fixed_error():
    log = archive(record("a"))
    changed = replace(log.events[0], event_time=datetime(2026, 1, 1))
    with pytest.raises(EvidenceError, match="INVALID_EVENT_TIME"):
        detect([replace(log, events=(changed,))])
