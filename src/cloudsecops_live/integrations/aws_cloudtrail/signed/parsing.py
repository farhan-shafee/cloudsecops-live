"""Bounded parsing of original supplied CloudTrail digest and custody bytes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import cast

from cloudsecops_live.contracts import Limits
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import (
    JSONValue,
    _check_tree,
    _constant,
    _expand,
    _number,
    _pairs,
    _preflight,
)
from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_cloudtrail.signed.contracts import AcquiredObject, Reference

LIMITS = Limits(
    max_compressed_bytes=1024 * 1024,
    max_expanded_bytes=4 * 1024 * 1024,
    max_depth=16,
    max_nodes=100_000,
)
_PREVIOUS = (
    "previousDigestS3Bucket",
    "previousDigestS3Object",
    "previousDigestHashValue",
    "previousDigestHashAlgorithm",
    "previousDigestSignature",
)
_REQUIRED = {
    "awsAccountId",
    "digestStartTime",
    "digestEndTime",
    "digestS3Bucket",
    "digestS3Object",
    "digestPublicKeyFingerprint",
    "digestSignatureAlgorithm",
    "logFiles",
    *_PREVIOUS,
}
_EVENT_TIMES = {"oldestEventTime", "newestEventTime"}


def utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EvidenceError("AWS4B_TIME")
    return value


def timestamp(value: object) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
        )
        is None
    ):
        raise EvidenceError("AWS4B_TIME")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("AWS4B_TIME") from None


def hex_text(value: object, *, length: int = 64) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) is None:
        raise EvidenceError("AWS4B_HASH")
    return value


def signature(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in (512, 768, 1024)
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise EvidenceError("AWS4B_SIGNATURE_FORMAT")
    return value


def reference(obj: AcquiredObject) -> Reference:
    return obj.reference.bucket, obj.reference.key, obj.reference.version_id


def safe_key(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or len(value) > 1024
        or not value.endswith(".json.gz")
        or any(
            re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part) is None or ".." in part
            for part in value.split("/")
        )
    ):
        raise EvidenceError("AWS4B_LOCATION")
    return value


def object_content(obj: AcquiredObject) -> bytes:
    """Reconcile retained observations; their AWS provenance is NOT established."""
    if type(obj) is not AcquiredObject or type(obj.reference) is not ObjectVersion:
        raise EvidenceError("AWS4B_CUSTODY")
    ref = obj.reference
    if (
        type(obj.archive) is not bytes
        or len(obj.archive) > LIMITS.max_compressed_bytes
        or type(ref.size) is not int
        or ref.size != len(obj.archive)
        or type(ref.is_latest) is not bool
        or ref.is_latest is not True
        or type(ref.is_delete_marker) is not bool
        or ref.is_delete_marker is not False
        or not isinstance(ref.bucket, str)
        or not isinstance(ref.key, str)
        or not isinstance(ref.version_id, str)
        or ref.version_id == "null"
        or re.fullmatch(r"[A-Za-z0-9._+/-]{1,1024}", ref.version_id) is None
        or type(obj.before) is not ObjectVersion
        or type(obj.after) is not ObjectVersion
        or obj.before != ref
        or obj.after != ref
        or not (
            utc(ref.last_modified)
            <= utc(obj.observed_before)
            <= utc(obj.retrieval_start)
            <= utc(obj.retrieval_end)
            <= utc(obj.observed_after)
        )
        or sha256(obj.archive).hexdigest() != hex_text(obj.archive_sha256)
    ):
        raise EvidenceError("AWS4B_CUSTODY")
    try:
        return _expand(obj.archive, LIMITS)
    except EvidenceError:
        raise EvidenceError("AWS4B_ARCHIVE") from None


@dataclass(frozen=True, slots=True)
class Member:
    bucket: str
    key: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class Digest:
    obj: AcquiredObject
    content: bytes
    content_sha256: str
    kind: str
    start: datetime
    end: datetime
    end_text: str
    key_time: datetime
    fingerprint: str
    signature: str
    previous: tuple[str, str, str, str] | None
    members: tuple[Member, ...]


def _event_times(record: dict[str, JSONValue]) -> None:
    if not _EVENT_TIMES.intersection(record):
        return
    if not _EVENT_TIMES <= record.keys():
        raise EvidenceError("AWS4B_FORMAT")
    old, new = record["oldestEventTime"], record["newestEventTime"]
    if old is None and new is None:
        return
    if timestamp(old) > timestamp(new):
        raise EvidenceError("AWS4B_TIME")


def parse_digest(obj: AcquiredObject, scope: AwsScope) -> Digest:
    content = object_content(obj)
    try:
        text = content.decode("utf-8")
        _preflight(text, LIMITS)
        doc = cast(
            "JSONValue",
            json.loads(
                text,
                object_pairs_hook=_pairs,
                parse_constant=_constant,
                parse_int=lambda x: _number(x, LIMITS, integer=True),
                parse_float=lambda x: _number(x, LIMITS, integer=False),
            ),
        )
        _check_tree(doc, LIMITS)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EvidenceError("AWS4B_JSON") from None
    if (
        not isinstance(doc, dict)
        or not _REQUIRED <= doc.keys()
        or doc.keys() - _REQUIRED - _EVENT_TIMES
    ):
        raise EvidenceError("AWS4B_FORMAT")
    if (
        doc["awsAccountId"] != scope.account
        or doc["digestS3Bucket"] != scope.bucket
        or obj.reference.bucket != scope.bucket
        or doc["digestS3Object"] != obj.reference.key
    ):
        raise EvidenceError("AWS4B_LOCATION")
    key = safe_key(doc["digestS3Object"], scope.digest_prefix)
    if type(obj.metadata) is not tuple or len(obj.metadata) > 3:
        raise EvidenceError("AWS4B_METADATA")
    meta: dict[str, str] = {}
    for pair in obj.metadata:
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or not all(isinstance(x, str) and len(x) <= 2048 for x in pair)
            or pair[0] in meta
        ):
            raise EvidenceError("AWS4B_METADATA")
        meta[pair[0]] = pair[1]
    if (
        set(meta) - {"signature", "signature-algorithm", "backfill-generation-timestamp"}
        or meta.get("signature-algorithm") != "SHA256withRSA"
        or doc["digestSignatureAlgorithm"] != "SHA256withRSA"
    ):
        raise EvidenceError("AWS4B_METADATA")
    sig = signature(meta.get("signature"))
    start, end = timestamp(doc["digestStartTime"]), timestamp(doc["digestEndTime"])
    if not start < end or end > obj.retrieval_end:
        raise EvidenceError("AWS4B_TIME")
    kind = "backfill" if key.endswith("_backfill.json.gz") else "standard"
    trail = scope.trail_arn.rsplit("/", 1)[1]
    suffix = "_backfill" if kind == "backfill" else ""
    expected = (
        scope.digest_prefix
        + end.strftime("%Y/%m/%d/")
        + scope.account
        + "_CloudTrail-Digest_"
        + scope.region
        + "_"
        + trail
        + "_"
        + scope.region
        + "_"
        + end.strftime("%Y%m%dT%H%M%SZ")
        + suffix
        + ".json.gz"
    )
    if key != expected:
        raise EvidenceError("AWS4B_LOCATION")
    key_time = end
    if kind == "backfill":
        key_time = timestamp(meta.get("backfill-generation-timestamp"))
        if key_time < end or key_time > obj.retrieval_end:
            raise EvidenceError("AWS4B_TIME")
    elif "backfill-generation-timestamp" in meta:
        raise EvidenceError("AWS4B_METADATA")
    fingerprint = doc["digestPublicKeyFingerprint"]
    if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{16,128}", fingerprint) is None:
        raise EvidenceError("AWS4B_KEY")
    previous = None
    values = [doc[field] for field in _PREVIOUS]
    if any(value is not None for value in values):
        if values[0] != scope.bucket or values[3] != "SHA-256":
            raise EvidenceError("AWS4B_LINK")
        previous = (
            scope.bucket,
            safe_key(values[1], scope.digest_prefix),
            hex_text(values[2]),
            signature(values[4]),
        )
    _event_times(doc)
    raw_members = doc["logFiles"]
    if not isinstance(raw_members, list) or len(raw_members) > 32:
        raise EvidenceError("AWS4B_MEMBERS")
    members: list[Member] = []
    seen: set[tuple[str, str]] = set()
    for member in raw_members:
        required = {"s3Bucket", "s3Object", "hashValue", "hashAlgorithm"}
        if (
            not isinstance(member, dict)
            or not required <= member.keys()
            or member.keys() - required - _EVENT_TIMES
            or member["s3Bucket"] != scope.bucket
            or member["hashAlgorithm"] != "SHA-256"
        ):
            raise EvidenceError("AWS4B_MEMBERS")
        member_key = safe_key(member["s3Object"], scope.log_prefix)
        identity = scope.bucket, member_key
        if identity in seen:
            raise EvidenceError("AWS4B_MEMBER_CONFLICT")
        seen.add(identity)
        _event_times(member)
        members.append(Member(scope.bucket, member_key, hex_text(member["hashValue"])))
    return Digest(
        obj,
        content,
        sha256(content).hexdigest(),
        kind,
        start,
        end,
        cast(str, doc["digestEndTime"]),
        key_time,
        fingerprint,
        sig,
        previous,
        tuple(members),
    )
