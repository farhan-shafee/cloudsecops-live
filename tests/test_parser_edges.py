"""Regression oracles for allocation and timestamp validation boundaries."""

import gzip
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from cloudsecops_live.contracts import EventIdentity, Limits, Provenance
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes, parse_file
from tests.helpers import archive, event


def test_record_limit_stops_before_json_tree_allocation() -> None:
    with patch("cloudsecops_live.ingestion.json.loads", wraps=json.loads) as loader:
        with pytest.raises(EvidenceError, match="RECORD_LIMIT"):
            parse_bytes(archive([{}, {}]), limits=Limits(max_records=1))
        loader.assert_not_called()


def test_decoded_string_limit_stops_before_json_tree_allocation() -> None:
    row = event("a")
    row["unknown"] = "x" * 129
    with patch("cloudsecops_live.ingestion.json.loads", wraps=json.loads) as loader:
        with pytest.raises(EvidenceError, match="STRING_LIMIT"):
            parse_bytes(archive([row]), limits=Limits(max_string_length=128))
        loader.assert_not_called()


def test_unicode_surrogate_pairs_obey_decoded_not_encoded_length() -> None:
    row = event("a")
    row["unknown"] = "\U0001f600" * 128
    assert len(parse_bytes(archive([row]), limits=Limits(max_string_length=128)).events) == 1
    row["unknown"] += "\U0001f600"
    with pytest.raises(EvidenceError, match="STRING_LIMIT"):
        parse_bytes(archive([row]), limits=Limits(max_string_length=128))


@pytest.mark.parametrize(
    "timestamp",
    [
        "0001-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59-01:00",
        "2026-01-01T00:00:00+00:99",
        "2026-01-01T00:00:00+24:00",
        "2026-02-30T00:00:00Z",
    ],
)
def test_invalid_timestamp_calendar_offset_or_overflow_is_structured(timestamp: str) -> None:
    row = event("a")
    row["eventTime"] = timestamp
    with pytest.raises(EvidenceError, match="INVALID_TIMESTAMP"):
        parse_bytes(archive([row]))


@pytest.mark.parametrize(
    "timestamp",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00", "2026-01-01T00:00:00+00:99"],
)
def test_invalid_session_timestamp_is_nonqualifying_not_internal_failure(timestamp: str) -> None:
    result = parse_bytes(archive([event("a", creation=timestamp)]))
    assert result.events[0].session is None
    assert result.events[0].identity_reason == "missing_session_creation"


@pytest.mark.parametrize(
    "field,value",
    [
        ("eventID", ""),
        ("eventSource", 1),
        ("errorCode", []),
        ("recipientAccountId", "not-a-lab-account"),
        ("awsRegion", "invalid-region"),
    ],
)
def test_malformed_record_fields_reject_the_whole_input(field: str, value: object) -> None:
    row = event("a")
    row[field] = value
    with pytest.raises(EvidenceError):
        parse_bytes(archive([event("good"), row]))


@pytest.mark.parametrize("source_ref", ["", "x" * 257, "line\nbreak", "\ud800"])
def test_invalid_source_references_are_rejected_without_echo(source_ref: str) -> None:
    with pytest.raises(EvidenceError, match="INVALID_SOURCE_REFERENCE"):
        parse_bytes(archive([]), source_ref=source_ref)


def test_invalid_api_types_and_limits_are_not_coerced() -> None:
    with pytest.raises(EvidenceError, match="INVALID_INPUT_TYPE"):
        parse_bytes(bytearray(archive([])))  # type: ignore[arg-type]
    for value in (0, -1, True, 33):
        with pytest.raises(ValueError):
            replace(Limits(), max_depth=value)
    with pytest.raises(ValueError):
        Provenance("verified")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        EventIdentity("actual_aws", "LABACCOUNT_A", "us-east-1", "a")  # type: ignore[arg-type]


def test_numeric_canonical_zero_and_positive_exponent_have_literal_oracles() -> None:
    row = event("a")
    raw = (
        __import__("json")
        .dumps({"fixture_schema_version": "1.0", "source_kind": "synthetic", "Records": [row]})
        .encode()
    )
    raw = raw.replace(b'"readOnly": true', b'"readOnly": true, "zero": -0.000, "positive": 1e3')
    canonical = parse_bytes(gzip.compress(raw)).events[0].canonical_record
    assert b'"zero":0.0' in canonical and b'"positive":1000.0' in canonical


def test_missing_session_structure_and_future_issuance_are_explained() -> None:
    row = event("a")
    row["userIdentity"]["sessionContext"] = None
    assert parse_bytes(archive([row])).events[0].identity_reason == "missing_session_context"
    row = event("a")
    row["userIdentity"]["sessionContext"]["attributes"] = None
    assert parse_bytes(archive([row])).events[0].identity_reason == "missing_session_identity"
    assert (
        parse_bytes(archive([event("a", creation="2026-01-01T00:00:01Z")]))
        .events[0]
        .identity_reason
        == "future_session_creation"
    )


def test_wrong_file_type_is_rejected_before_open(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="INVALID_FILE_TYPE"):
        parse_file(tmp_path / "not-opened.txt")
