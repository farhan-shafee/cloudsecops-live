"""Independent literal oracles for hostile synthetic input and correlation."""

from __future__ import annotations

import copy
import gzip
import hashlib
import itertools
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cloudsecops_live.contracts import Limits
from cloudsecops_live.detection import detect
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes, parse_file
from tests.helpers import archive, content, envelope, event


def findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return detect([parse_bytes(archive(records))]).to_dict()["findings"]


def evidence_sets(result: list[dict[str, Any]]) -> set[frozenset[str]]:
    return {frozenset(item["evidence_event_ids"]) for item in result}


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        ([], set()),
        ([0], set()),
        ([0, 1], set()),
        ([0, 1, 2], {frozenset({"e0", "e1", "e2"})}),
        ([0, 30, 59], {frozenset({"e0", "e1", "e2"})}),
        ([0, 30, 60], {frozenset({"e0", "e1", "e2"})}),
        ([0, 30, 61], set()),
        ([0, 0, 0], {frozenset({"e0", "e1", "e2"})}),
        ([60, 0, 30], {frozenset({"e0", "e1", "e2"})}),
        ([0, 30, 60, 90, 120], {frozenset({"e0", "e1", "e2", "e3", "e4"})}),
        (
            [0, 30, 60, 121, 151, 181],
            {frozenset({"e0", "e1", "e2"}), frozenset({"e3", "e4", "e5"})},
        ),
        # Nearby windows do not merge merely because their clock ranges touch.
        (
            [0, 0, 0, 61, 61, 61],
            {frozenset({"e0", "e1", "e2"}), frozenset({"e3", "e4", "e5"})},
        ),
    ],
)
def test_literal_window_components(seconds: list[int], expected: set[frozenset[str]]) -> None:
    records = [event(f"e{i}", second) for i, second in enumerate(seconds)]
    assert evidence_sets(findings(records)) == expected


def test_repeated_delivery_never_reaches_threshold() -> None:
    one = event("same-id")
    logs = [parse_bytes(archive([one]), source_ref=f"delivery-{i}.json.gz") for i in range(5)]
    report = detect(logs)
    assert report.to_dict()["findings"] == []
    assert not report.has_conflicts


def test_unknown_field_conflict_blocks_entire_batch() -> None:
    records = [event("good-1"), event("good-2", 20), event("good-3", 40)]
    changed = event("good-1")
    changed["futureExtension"] = {"value": "different"}
    report = detect([parse_bytes(archive(records)), parse_bytes(archive([changed]))])
    assert report.has_conflicts
    assert report.to_dict()["findings"] == []


@pytest.mark.parametrize(
    "separation",
    [
        {"account": "LABACCOUNT_B"},
        {"region": "us-west-2"},
        {"role": "OtherInventoryRole"},
        {"key": "SYNTHETIC_KEY_B"},
        {"creation": "2025-12-31T23:10:00Z"},
    ],
)
def test_session_dimensions_do_not_cross_count(separation: dict[str, str]) -> None:
    records = [event("base-1"), event("base-2", 1), event("other-1", 2, **separation)]
    assert findings(records) == []


def test_same_role_and_session_name_new_credentials_have_two_findings() -> None:
    records = [event("a1"), event("a2", 10), event("a3", 20)]
    records += [
        event("b1", 1, key="SYNTHETIC_KEY_B"),
        event("b2", 11, key="SYNTHETIC_KEY_B"),
        event("b3", 21, key="SYNTHETIC_KEY_B"),
    ]
    assert evidence_sets(findings(records)) == {
        frozenset({"a1", "a2", "a3"}),
        frozenset({"b1", "b2", "b3"}),
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventName", "DescribeInstancesExtra"),
        ("eventSource", "iam.amazonaws.com"),
        ("eventCategory", "Data"),
        ("eventType", "AwsServiceEvent"),
        ("readOnly", False),
        ("errorCode", "SyntheticDenied"),
        ("errorMessage", "Synthetic failure"),
        ("errorCode", None),
        ("errorCode", ""),
        ("errorMessage", None),
        ("errorMessage", ""),
    ],
)
def test_nonqualifying_record_never_completes_burst(field: str, value: Any) -> None:
    rejected = event("reject", 30)
    rejected[field] = value
    assert findings([event("valid-1"), event("valid-2", 10), rejected]) == []


@pytest.mark.parametrize(
    "damage",
    [
        "missing-key",
        "empty-key",
        "missing-creation",
        "invalid-creation",
        "wrong-identity-type",
        "actor-account",
        "issuer-account",
        "actor-arn",
        "issuer-arn",
        "principal-prefix",
        "session-suffix",
    ],
)
def test_incomplete_or_inconsistent_identity_is_nonqualifying(damage: str) -> None:
    bad = event("bad", 20)
    identity = bad["userIdentity"]
    issuer = identity["sessionContext"]["sessionIssuer"]
    attributes = identity["sessionContext"]["attributes"]
    if damage == "missing-key":
        del identity["accessKeyId"]
    elif damage == "empty-key":
        identity["accessKeyId"] = ""
    elif damage == "missing-creation":
        del attributes["creationDate"]
    elif damage == "invalid-creation":
        attributes["creationDate"] = "yesterday"
    elif damage == "wrong-identity-type":
        identity["type"] = "IAMUser"
    elif damage == "actor-account":
        identity["accountId"] = "LABACCOUNT_B"
    elif damage == "issuer-account":
        issuer["accountId"] = "LABACCOUNT_B"
    elif damage == "actor-arn":
        identity["arn"] = "arn:aws:sts::LABACCOUNT_A:assumed-role/AnotherRole/lab-session"
    elif damage == "issuer-arn":
        issuer["arn"] = "arn:aws:iam::LABACCOUNT_B:role/InventoryLab"
    elif damage == "principal-prefix":
        identity["principalId"] = "SYNTHETIC_ROLE_B:lab-session"
    else:
        identity["principalId"] = "SYNTHETIC_ROLE_A:other-session"
    assert findings([event("valid-1"), event("valid-2", 10), bad]) == []


def test_null_response_is_successful_and_output_never_claims_verified() -> None:
    records = [event("a"), event("b", 30), event("c", 60)]
    result = findings(records)
    assert evidence_sets(result) == {frozenset({"a", "b", "c"})}
    serialized = json.dumps(result)
    assert '"verified"' not in serialized
    assert "synthetic" in serialized


def test_duplicate_delivery_within_one_archive_has_three_unique_evidence_ids() -> None:
    records = [event("a"), event("b", 20), event("c", 40), event("a"), event("b", 20)]
    result = findings(records)
    assert evidence_sets(result) == {frozenset({"a", "b", "c"})}
    assert result[0]["count"] == 3
    assert len(result[0]["evidence"]) == 3


def test_two_ids_repeated_within_archive_are_below_threshold() -> None:
    assert findings([event("a"), event("b", 20), event("a"), event("b", 20)]) == []


def test_late_delivery_and_permutations_have_stable_finding_identity() -> None:
    records = [event("late", 0), event("middle", 30), event("early-arrival", 60)]
    baseline = findings(records)
    assert evidence_sets(baseline) == {frozenset({"late", "middle", "early-arrival"})}
    for permutation in itertools.permutations(records):
        report = detect(
            [
                parse_bytes(archive([record]), source_ref=f"record-{record['eventID']}.json.gz")
                for record in permutation
            ]
        )
        result = report.to_dict()["findings"]
        assert result[0]["finding_id"] == baseline[0]["finding_id"]
        assert evidence_sets(result) == {frozenset({"late", "middle", "early-arrival"})}


def test_same_identity_different_account_or_region_is_not_a_conflict() -> None:
    logs = [
        parse_bytes(archive([event("reused", **change)]))
        for change in ({}, {"account": "LABACCOUNT_B"}, {"region": "us-west-2"})
    ]
    report = detect(logs)
    assert not report.has_conflicts
    assert report.to_dict()["findings"] == []


def test_fixture_demo_is_deterministic_and_matches_literal_expected() -> None:
    directory = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
    raw = (directory / "inventory-burst.json").read_bytes()
    compressed = (directory / "inventory-burst.json.gz").read_bytes()
    expected = json.loads((directory / "inventory-burst.expected.json").read_text())
    # The fixed artifact is reproducible. Recompression can vary across zlib
    # versions, and Python 3.12 can emit a different host OS header byte.
    assert (
        hashlib.sha256(compressed).hexdigest()
        == (
            "5bfca5401abd303936dbbeea639f334af4b78bd1831f07c078057cc44bee9c1f"  # pragma: allowlist secret  # noqa: E501 - public synthetic fixture SHA-256
        )
    )
    assert compressed[4:8] == b"\x00\x00\x00\x00"
    assert gzip.decompress(compressed) == raw
    result = detect([parse_file(directory / "inventory-burst.json.gz")]).to_dict()["findings"]
    assert len(result) == expected["finding_count"] == 1
    assert evidence_sets(result) == {frozenset({"demo-001", "demo-002", "demo-003"})}
    assert result[0]["count"] == expected["qualifying_count"] == 3


def test_hash_domains_preserve_exact_bytes_and_canonical_record() -> None:
    raw = content([event("one")])
    zipped = gzip.compress(raw, mtime=0)
    changed_header = gzip.compress(raw, mtime=1)
    spaced_raw = json.dumps(envelope([event("one")]), indent=2).encode()
    first = parse_bytes(zipped)
    second = parse_bytes(changed_header)
    third = parse_bytes(gzip.compress(spaced_raw, mtime=0))
    assert first.evidence.archive_sha256 == hashlib.sha256(zipped).hexdigest()
    assert first.evidence.content_sha256 == hashlib.sha256(raw).hexdigest()
    assert first.evidence.archive_sha256 != second.evidence.archive_sha256
    assert first.evidence.content_sha256 == second.evidence.content_sha256
    assert first.evidence.content_sha256 != third.evidence.content_sha256
    assert (
        first.events[0].record_sha256
        == second.events[0].record_sha256
        == third.events[0].record_sha256
    )
    assert (
        first.events[0].record_sha256
        == hashlib.sha256(first.events[0].canonical_record).hexdigest()
    )


def test_complete_canonical_record_sorts_objects_but_preserves_array_order() -> None:
    original = event("one")
    original["futureExtension"] = {"z": ["first", "second"], "a": "kept"}
    reordered = dict(reversed(list(original.items())))
    reordered["futureExtension"] = {"a": "kept", "z": ["first", "second"]}
    first = parse_bytes(archive([original]))
    second = parse_bytes(archive([reordered]))
    assert first.events[0].record_sha256 == second.events[0].record_sha256
    assert not detect([first, second]).has_conflicts
    reordered["futureExtension"]["z"].reverse()
    assert detect([first, parse_bytes(archive([reordered]))]).has_conflicts


def test_unknown_field_numeric_precision_and_types_cannot_hide_conflict() -> None:
    for left, right in [
        ("9007199254740992.0", "9007199254740993.0"),
        ("1", "1.0"),
        ("1.00000000000000000001", "1.00000000000000000002"),
    ]:
        raw = content([event("one")]).replace(
            b'"eventVersion":"1.11"', b'"eventVersion":"1.11","futureNumber":NUM'
        )
        one = parse_bytes(gzip.compress(raw.replace(b"NUM", left.encode()), mtime=0))
        two = parse_bytes(gzip.compress(raw.replace(b"NUM", right.encode()), mtime=0))
        assert one.events[0].record_sha256 != two.events[0].record_sha256
        assert detect([one, two]).has_conflicts


@pytest.mark.parametrize(
    "raw",
    [
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"Records":[]}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[{"eventID":"one","eventID":"two"}]}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"\\u0052ecords":[]}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"x":NaN}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"x":Infinity}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"x":-Infinity}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[],"x":"\\ud800"}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[]} trailing',
        b"[]",
        b"{}",
        b'{"fixture_schema_version":"999.0","source_kind":"synthetic","Records":[]}',
        b'{"fixture_schema_version":"1.0","source_kind":"aws","Records":[]}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":{}}',
        b'{"fixture_schema_version":"1.0","source_kind":"synthetic","Records":[null]}',
        b"\xff",
    ],
)
def test_strict_json_rejects_ambiguous_or_unsupported_input(raw: bytes) -> None:
    with pytest.raises(EvidenceError):
        parse_bytes(gzip.compress(raw, mtime=0))


@pytest.mark.parametrize("expression", [b"NaN", b"Infinity", b"-Infinity", b'"\\ud800"'])
def test_invalid_unknown_record_values_cannot_bypass_canonical_validation(
    expression: bytes,
) -> None:
    raw = content([event("one")]).replace(
        b'"eventVersion":"1.11"',
        b'"eventVersion":"1.11","futureExtension":' + expression,
    )
    with pytest.raises(EvidenceError):
        parse_bytes(gzip.compress(raw, mtime=0))


def test_duplicate_key_in_otherwise_valid_record_is_rejected() -> None:
    raw = content([event("one")]).replace(b'"eventID":"one"', b'"eventID":"one","eventID":"one"')
    with pytest.raises(EvidenceError):
        parse_bytes(gzip.compress(raw, mtime=0))


def test_bad_record_does_not_allow_partial_import() -> None:
    valid = event("one")
    invalid = event("two")
    invalid["eventTime"] = "PRIVATE_INVALID_TIMESTAMP"
    with pytest.raises(EvidenceError) as raised:
        parse_bytes(archive([valid, invalid]))
    assert "PRIVATE_INVALID_TIMESTAMP" not in str(raised.value)


@pytest.mark.parametrize("transform", ["truncated", "trailing", "second-member", "crc", "plain"])
def test_gzip_integrity_and_exact_single_member(transform: str) -> None:
    zipped = archive([])
    if transform == "truncated":
        zipped = zipped[:-5]
    elif transform == "trailing":
        zipped += b"untrusted trailing bytes"
    elif transform == "second-member":
        zipped += archive([])
    elif transform == "crc":
        changed = bytearray(zipped)
        changed[-8] ^= 1
        zipped = bytes(changed)
    else:
        zipped = content([])
    with pytest.raises(EvidenceError):
        parse_bytes(zipped)


def test_forged_envelope_trust_cannot_elevate_source() -> None:
    records = [event("one"), event("two", 20), event("three", 40)]
    forged = archive(
        records, provenance="verified", digest_validated=True, source_authenticated=True
    )
    try:
        parsed = parse_bytes(forged)
    except EvidenceError:
        return  # Rejecting unknown envelope authority fields is also fail-closed.
    report = detect([parsed]).to_dict()
    serialized = json.dumps(report)
    assert '"verified"' not in serialized
    assert "synthetic" in serialized


def test_forged_record_authority_fields_remain_untrusted() -> None:
    forged = event("one")
    forged["provenance"] = "verified"
    forged["source_kind"] = "aws"
    forged["digest_validated"] = True
    parsed = parse_bytes(archive([forged]), source_ref="verified-aws-original.json.gz")
    assert parsed.evidence.provenance.state.value == "synthetic"
    assert parsed.evidence.provenance.authenticated is False
    assert parsed.events[0].identity.source_kind == "synthetic"
    assert parsed.events[0].provenance.authenticated is False


def test_parser_error_never_echoes_attacker_value() -> None:
    sentinel = "PRIVATE_ATTACKER_CONTROLLED_SENTINEL"
    raw = json.dumps(envelope([], fixture_schema_version=sentinel)).encode()
    with pytest.raises(EvidenceError) as raised:
        parse_bytes(gzip.compress(raw, mtime=0), source_ref=sentinel)
    assert sentinel not in str(raised.value)


def test_mutation_of_original_input_cannot_change_parsed_records() -> None:
    original = event("one")
    saved = copy.deepcopy(original)
    parsed = parse_bytes(archive([original]))
    original["eventID"] = "changed"
    assert parsed.events[0].identity.event_id == saved["eventID"]


@pytest.mark.parametrize("value", ["true", 1, [], {}])
def test_read_only_requires_boolean_or_unknown(value: Any) -> None:
    bad = event("one")
    bad["readOnly"] = value
    with pytest.raises(EvidenceError):
        parse_bytes(archive([bad]))


def test_compressed_limit_boundary_and_one_over() -> None:
    zipped = archive([])
    assert (
        parse_bytes(zipped, limits=replace(Limits(), max_compressed_bytes=len(zipped))).events == ()
    )
    with pytest.raises(EvidenceError):
        parse_bytes(zipped, limits=replace(Limits(), max_compressed_bytes=len(zipped) - 1))


def test_expanded_limit_boundary_and_one_over() -> None:
    raw = content([])
    zipped = gzip.compress(raw, mtime=0)
    assert parse_bytes(zipped, limits=replace(Limits(), max_expanded_bytes=len(raw))).events == ()
    with pytest.raises(EvidenceError):
        parse_bytes(zipped, limits=replace(Limits(), max_expanded_bytes=len(raw) - 1))


def test_record_limit_boundary_and_one_over() -> None:
    limit = replace(Limits(), max_records=2)
    assert len(parse_bytes(archive([event("one"), event("two")]), limits=limit).events) == 2
    with pytest.raises(EvidenceError):
        parse_bytes(archive([event("one"), event("two"), event("three")]), limits=limit)


def test_depth_limit_boundary_and_one_over() -> None:
    assert parse_bytes(archive([]), limits=replace(Limits(), max_depth=2)).events == ()
    with pytest.raises(EvidenceError):
        parse_bytes(archive([]), limits=replace(Limits(), max_depth=1))


def test_node_limit_boundary_and_one_over() -> None:
    assert parse_bytes(archive([]), limits=replace(Limits(), max_nodes=7)).events == ()
    with pytest.raises(EvidenceError):
        parse_bytes(archive([]), limits=replace(Limits(), max_nodes=6))


def test_decoded_string_limit_boundary_and_one_over() -> None:
    record = event("one")
    record["futureText"] = "x" * 128
    assert (
        len(parse_bytes(archive([record]), limits=replace(Limits(), max_string_length=128)).events)
        == 1
    )
    record["futureText"] = "x" * 129
    with pytest.raises(EvidenceError):
        parse_bytes(archive([record]), limits=replace(Limits(), max_string_length=128))


def test_decoded_string_limit_counts_characters_not_json_escape_bytes() -> None:
    record = event("one")
    record["futureText"] = "\u2603" * 128
    assert (
        len(parse_bytes(archive([record]), limits=replace(Limits(), max_string_length=128)).events)
        == 1
    )


def test_numeric_token_limit_boundary_and_one_over() -> None:
    raw = content([event("one")]).replace(
        b'"eventVersion":"1.11"', b'"eventVersion":"1.11","futureNumber":123456'
    )
    assert (
        len(
            parse_bytes(
                gzip.compress(raw, mtime=0), limits=replace(Limits(), max_number_length=6)
            ).events
        )
        == 1
    )
    raw = raw.replace(b"123456", b"1234567")
    with pytest.raises(EvidenceError):
        parse_bytes(gzip.compress(raw, mtime=0), limits=replace(Limits(), max_number_length=6))


def test_small_compression_bomb_is_bounded() -> None:
    bomb = gzip.compress(b" " * 100_000, mtime=0)
    assert len(bomb) < 1024
    with pytest.raises(EvidenceError):
        parse_bytes(bomb, limits=replace(Limits(), max_expanded_bytes=1024))


def test_extreme_depth_rejects_without_python_recursion_error() -> None:
    nested = b"[" * 2000 + b"0" + b"]" * 2000
    with pytest.raises(EvidenceError):
        parse_bytes(gzip.compress(nested, mtime=0))


@pytest.mark.parametrize("expression", [b"1e999999999", b"-1e999999999", b"0e-999999999"])
def test_numeric_exponent_cannot_create_unbounded_canonical_output(expression: bytes) -> None:
    raw = content([event("one")]).replace(
        b'"eventVersion":"1.11"', b'"eventVersion":"1.11","futureNumber":' + expression
    )
    # A finite compact decimal representation is allowed, as is bounded rejection.
    try:
        parsed = parse_bytes(gzip.compress(raw, mtime=0))
    except EvidenceError:
        return
    assert len(parsed.events[0].canonical_record) < 10_000
