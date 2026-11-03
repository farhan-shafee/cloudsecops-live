"""Independent parser expectations, including attacks before normalization."""

import gzip
import hashlib
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from cloudsecops_live.contracts import Limits, Provenance, ProvenanceState
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes, parse_file


def envelope(records: list[object]) -> bytes:
    return json.dumps(
        {"fixture_schema_version": "1.0", "source_kind": "synthetic", "Records": records}
    ).encode()


def record() -> dict[str, object]:
    return {
        "eventID": "event-a",
        "recipientAccountId": "LABACCOUNT_A",
        "awsRegion": "us-east-1",
        "eventTime": "2026-01-01T00:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "readOnly": True,
    }


class ParserTests(unittest.TestCase):
    def test_preserves_distinct_hash_domains_and_exact_bytes(self) -> None:
        content = envelope([record()])
        data = gzip.compress(content, mtime=0)
        result = parse_bytes(data)
        self.assertEqual(result.evidence.archive_bytes, data)
        self.assertEqual(result.evidence.content_bytes, content)
        self.assertEqual(result.evidence.archive_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.evidence.content_sha256, hashlib.sha256(content).hexdigest())
        self.assertNotEqual(result.evidence.archive_sha256, result.evidence.content_sha256)
        self.assertFalse(result.evidence.provenance.authenticated)
        self.assertEqual(result.events[0].references[0].record_index, 0)

    def test_empty_records_is_valid_no_events(self) -> None:
        self.assertEqual(parse_bytes(gzip.compress(envelope([]))).events, ())

    def test_both_size_limits_accept_exact_and_reject_one_over(self) -> None:
        content = envelope([])
        data = gzip.compress(content)
        exact = Limits(max_compressed_bytes=len(data), max_expanded_bytes=len(content))
        self.assertEqual(len(parse_bytes(data, limits=exact).evidence.content_bytes), len(content))
        for limits in [
            replace(exact, max_compressed_bytes=len(data) - 1),
            replace(exact, max_expanded_bytes=len(content) - 1),
        ]:
            with self.subTest(limits=limits), self.assertRaises(EvidenceError):
                parse_bytes(data, limits=limits)

    def test_rejects_truncated_trailing_and_multiple_gzip_members(self) -> None:
        data = gzip.compress(envelope([]))
        for invalid in [data[:-1], data + b"junk", data + data, b"not gzip"]:
            with self.subTest(size=len(invalid)), self.assertRaises(EvidenceError):
                parse_bytes(invalid)

    def test_rejects_duplicate_keys_nonfinite_and_unknown_envelope(self) -> None:
        for content in [
            b'{"a":1,"a":2}',
            b'{"Records":NaN}',
            b"[]",
            b"null",
            b'{"source_kind":"actual_aws","Records":[]}',
        ]:
            with self.subTest(content=content), self.assertRaises(EvidenceError):
                parse_bytes(gzip.compress(content))

    def test_unknown_fields_are_bound_before_normalization(self) -> None:
        a = record()
        b = record()
        b["unknown"] = True
        first = parse_bytes(gzip.compress(envelope([a]))).events[0]
        second = parse_bytes(gzip.compress(envelope([b]))).events[0]
        self.assertEqual(first.identity, second.identity)
        self.assertNotEqual(first.record_sha256, second.record_sha256)

    def test_exact_decimal_not_binary_float_canonicalization(self) -> None:
        content = envelope([record()]).replace(
            b'"readOnly": true', b'"readOnly": true, "n": 1.0000000000000000001'
        )
        content2 = content.replace(b"1.0000000000000000001", b"1.0000000000000000002")
        self.assertNotEqual(
            parse_bytes(gzip.compress(content)).events[0].record_sha256,
            parse_bytes(gzip.compress(content2)).events[0].record_sha256,
        )

    def test_file_reader_rejects_before_reading_whole_large_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json.gz"
            path.write_bytes(b"x" * 100)
            with self.assertRaises(EvidenceError) as caught:
                parse_file(path, limits=Limits(max_compressed_bytes=10))
            self.assertEqual(caught.exception.code, "COMPRESSED_LIMIT")

    def test_immutable_and_no_verified_state(self) -> None:
        with self.assertRaises(ValueError):
            ProvenanceState("verified")
        value = parse_bytes(gzip.compress(envelope([]))).evidence
        with self.assertRaises(FrozenInstanceError):
            value.source_ref = "changed"  # type: ignore[misc]
        self.assertEqual(Provenance().state, ProvenanceState.SYNTHETIC)


if __name__ == "__main__":
    unittest.main()
