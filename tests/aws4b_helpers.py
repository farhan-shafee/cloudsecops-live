"""Independent AWS-format signatures using ephemeral, never serialized private keys."""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
from cloudsecops_live.integrations.aws_cloudtrail.signed import (
    AcquiredObject,
    ChainSpec,
    SuppliedKey,
    VerificationPlan,
)
from tests.aws_helpers import BASE_TIME, event, scope

START = BASE_TIME
END = BASE_TIME + timedelta(hours=1)


def stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def supplied_key(private, *, fingerprint="a" * 32, region="us-east-1", start=None, end=None):
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return SuppliedKey(
        fingerprint,
        region,
        start or START - timedelta(days=1),
        end or END + timedelta(days=1),
        public,
        sha256(public).hexdigest(),
    )


def acquired(
    content,
    key,
    *,
    metadata=(),
    version="fictional-version-v1",
    expected=None,
    observation_time=END,
):
    expected = expected or scope()
    compressed = gzip.compress(content, mtime=0)
    reference = ObjectVersion(expected.bucket, key, version, len(compressed), observation_time)
    return AcquiredObject(
        reference,
        compressed,
        sha256(compressed).hexdigest(),
        reference,
        reference,
        observation_time + timedelta(seconds=1),
        observation_time + timedelta(seconds=2),
        observation_time + timedelta(seconds=3),
        observation_time + timedelta(seconds=4),
        metadata,
    )


def log_object(records=None, *, name="fictional-log", expected=None, content=None):
    expected = expected or scope()
    if content is None:
        content = json.dumps(
            {"Records": [event()] if records is None else records}, separators=(",", ":")
        ).encode()
    return acquired(
        content,
        expected.log_prefix + "2026/01/01/" + name + ".json.gz",
        expected=expected,
    )


def digest_document(key, *, start=START, end=END, logs=(), previous=None, kind="standard"):
    expected = scope()
    trail = expected.trail_arn.rsplit("/", 1)[-1]
    suffix = "_backfill" if kind == "backfill" else ""
    object_key = (
        expected.digest_prefix
        + end.strftime("%Y/%m/%d/")
        + f"{expected.account}_CloudTrail-Digest_{expected.region}_{trail}_{expected.region}_"
        + end.strftime("%Y%m%dT%H%M%SZ")
        + suffix
        + ".json.gz"
    )
    document = {
        "awsAccountId": expected.account,
        "digestStartTime": stamp(start),
        "digestEndTime": stamp(end),
        "digestS3Bucket": expected.bucket,
        "digestS3Object": object_key,
        "digestPublicKeyFingerprint": key.fingerprint,
        "digestSignatureAlgorithm": "SHA256withRSA",
        "newestEventTime": None,
        "oldestEventTime": None,
        "previousDigestS3Bucket": None,
        "previousDigestS3Object": None,
        "previousDigestHashValue": None,
        "previousDigestHashAlgorithm": None,
        "previousDigestSignature": None,
        "logFiles": [
            {
                "s3Bucket": log.reference.bucket,
                "s3Object": log.reference.key,
                "hashValue": sha256(gzip.decompress(log.archive)).hexdigest(),
                "hashAlgorithm": "SHA-256",
            }
            for log in logs
        ],
    }
    if previous is not None:
        metadata = dict(previous.metadata)
        document.update(
            previousDigestS3Bucket=previous.reference.bucket,
            previousDigestS3Object=previous.reference.key,
            previousDigestHashValue=sha256(gzip.decompress(previous.archive)).hexdigest(),
            previousDigestHashAlgorithm="SHA-256",
            previousDigestSignature=metadata["signature"],
        )
    return document


def sign_document(private, document, *, kind="standard", generation=None, content=None):
    if content is None:
        content = json.dumps(document, separators=(",", ":")).encode("utf-8")
    # This builder deliberately does not import or call production signing helpers.
    previous = document["previousDigestSignature"]
    signing_data = (
        document["digestEndTime"]
        + "\n"
        + document["digestS3Bucket"]
        + "/"
        + document["digestS3Object"]
        + "\n"
        + sha256(content).hexdigest()
        + "\n"
        + ("null" if previous is None else previous)
    ).encode("utf-8")
    signature = private.sign(signing_data, padding.PKCS1v15(), hashes.SHA256()).hex()
    metadata = [("signature", signature), ("signature-algorithm", "SHA256withRSA")]
    if kind == "backfill":
        metadata.append(("backfill-generation-timestamp", stamp(generation or END)))
    digest_end = datetime.fromisoformat(document["digestEndTime"].replace("Z", "+00:00"))
    observation = max(digest_end, generation or digest_end)
    return acquired(
        content,
        document["digestS3Object"],
        metadata=tuple(metadata),
        observation_time=observation,
    )


def ref(obj):
    return obj.reference.bucket, obj.reference.key, obj.reference.version_id


@dataclass(frozen=True)
class Bundle:
    plan: VerificationPlan
    keys: tuple
    digests: tuple
    logs: tuple

    def replace(self, **changes):
        return replace(self, **changes)


def bundle(private, *, records=None, start=START, end=END, kind="standard"):
    key = supplied_key(private)
    log = log_object(records)
    document = digest_document(key, start=start, end=end, logs=(log,), kind=kind)
    digest = sign_document(private, document, kind=kind)
    standard = ChainSpec("standard", ref(digest) if kind == "standard" else None)
    backfill = ChainSpec("backfill", ref(digest) if kind == "backfill" else None)
    plan = VerificationPlan(scope(), start, end, standard, backfill)
    return Bundle(plan, (key,), (digest,), (log,))
