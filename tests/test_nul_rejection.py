"""Decoded NUL has a fixed rejection reason before normalization or output."""

from __future__ import annotations

import gzip
import json

import pytest

from cloudsecops_live.cli import main
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes
from tests.helpers import archive, envelope, event


def nul_document(location: str) -> object:
    """Hand-authored input positions; no expected values come from the parser."""
    row = event("private-event")
    document = envelope([row])
    if location in ("eventSource", "eventName", "eventCategory", "eventType"):
        row[location] += "\x00private-payload"
    elif location == "issuer-path":
        row["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
            "arn:aws:iam::LABACCOUNT_A:role/private\x00path/InventoryLab"
        )
    elif location == "root-string":
        return "private\x00payload"
    elif location == "envelope-value":
        document["source_kind"] = "synthetic\x00private-payload"
    elif location == "envelope-key":
        document["private\x00key"] = None
    elif location == "record-string":
        document["Records"] = ["private\x00payload"]
    elif location == "record-key":
        row["private\x00key"] = 0
    elif location == "unknown-value":
        row["futureField"] = "private\x00payload"
    elif location == "nested-value":
        row["futureField"] = {"array": [0, None, {"leaf": "private\x00payload"}]}
    elif location == "nested-key":
        row["futureField"] = {"array": [{"private\x00key": True}]}
    elif location == "unknown-envelope-field":
        document["futureField"] = {"leaf": "private\x00payload"}
    else:
        raise AssertionError(location)
    return document


NUL_LOCATIONS = (
    "eventSource",
    "eventName",
    "eventCategory",
    "eventType",
    "issuer-path",
    "root-string",
    "envelope-value",
    "envelope-key",
    "record-string",
    "record-key",
    "unknown-value",
    "nested-value",
    "nested-key",
    "unknown-envelope-field",
)


@pytest.mark.parametrize("location", NUL_LOCATIONS)
def test_decoded_nul_rejected_everywhere_with_exact_reason(location):
    plain = json.dumps(nul_document(location)).encode("utf-8")
    assert b"\\u0000" in plain and b"\x00" not in plain
    with pytest.raises(EvidenceError) as rejected:
        parse_bytes(gzip.compress(plain, mtime=0))
    assert rejected.value.code == "NUL_CHARACTER"


def test_equivalent_json_escapes_cannot_hide_decoded_nul():
    plain = json.dumps(nul_document("eventName"), separators=(",", ":")).encode()
    equivalent = plain.replace(b'"eventName"', b'"\\u0065ventName"').replace(
        b"DescribeInstances", b"\\u0044escribeInstances"
    )
    assert plain != equivalent
    assert json.loads(plain) == json.loads(equivalent)
    for encoded in (plain, equivalent):
        with pytest.raises(EvidenceError) as rejected:
            parse_bytes(gzip.compress(encoded, mtime=0))
        assert rejected.value.code == "NUL_CHARACTER"


@pytest.mark.parametrize(
    "replacement,reason", [(b"\x00", "INVALID_JSON"), (b"\xc0\x80", "INVALID_UTF8")]
)
def test_invalid_raw_nul_and_overlong_utf8_keep_existing_reasons(replacement, reason):
    plain = json.dumps(nul_document("unknown-value")).encode().replace(b"\\u0000", replacement)
    with pytest.raises(EvidenceError) as rejected:
        parse_bytes(gzip.compress(plain, mtime=0))
    assert rejected.value.code == reason


@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_literal_backslash_escape_zero_null_and_non_bmp_remain_valid(ensure_ascii):
    row = event("legitimate")
    row["eventName"] = r"literal\u0000" + "\U0001f642\t\n"
    row["futureField"] = {r"literal\u0000": [r"\u0000", 0, None, "\U0001f642"]}
    plain = json.dumps(envelope([row]), ensure_ascii=ensure_ascii).encode("utf-8")
    parsed = parse_bytes(gzip.compress(plain, mtime=0))
    assert len(parsed.events) == 1
    assert parsed.events[0].event_name == row["eventName"]
    assert json.loads(parsed.events[0].canonical_record)["futureField"] == row["futureField"]


@pytest.mark.parametrize("command", ["import-synthetic", "detect-synthetic"])
@pytest.mark.parametrize("batch_shape", ["two-files", "two-records"])
def test_standalone_cli_emits_only_fixed_error_for_atomic_nul_batch(
    command, batch_shape, tmp_path, capsys
):
    good = event("private-valid-first")
    bad = event("private-invalid-second")
    bad["futureField"] = {"leaf": "private\x00payload"}
    source = tmp_path / "private-bad.json.gz"
    paths = []
    if batch_shape == "two-files":
        first = tmp_path / "private-good.json.gz"
        first.write_bytes(archive([good]))
        paths.append(str(first))
        source.write_bytes(archive([bad]))
    else:
        source.write_bytes(archive([good, bad]))
    paths.append(str(source))
    assert main([command, *paths]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {
        "error": {
            "code": "NUL_CHARACTER",
            "message": "Operation rejected; no partial result was emitted.",
        },
        "source_kind": "synthetic",
        "authenticated": False,
    }
    assert "private" not in output.err
