"""Independent malformed-input expectations at the new digest boundary."""

import gzip
from dataclasses import replace
from hashlib import sha256

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
from cloudsecops_live.integrations.aws_cloudtrail.signed import AcquiredObject
from tests.aws_helpers import BASE_TIME, scope


def source(content):
    data = gzip.compress(content, mtime=0)
    expected = scope()
    key = expected.digest_prefix + "2026/01/01/example.json.gz"
    ref = ObjectVersion(expected.bucket, key, "offline-version", len(data), BASE_TIME)
    return AcquiredObject(
        ref,
        data,
        sha256(data).hexdigest(),
        ref,
        ref,
        BASE_TIME,
        BASE_TIME,
        BASE_TIME,
        BASE_TIME,
    )


@pytest.mark.parametrize(
    "content",
    [
        b'{"a":1,"a":2}',
        b'{"unknown":"\\u0000"}',
        b'{"\\u0000":1}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":',
        b"[]",
        b"null",
        b'{"a":"\\ud800"}',
        b"\xff",
        b"{}",
    ],
)
def test_hostile_or_unsupported_digest_rejected_without_payload(content):
    from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import parse_digest

    with pytest.raises(EvidenceError) as caught:
        parse_digest(source(content), scope())
    assert caught.value.code.startswith("AWS4B_")
    assert len(str(caught.value)) < 80
    assert content.decode("utf-8", errors="replace") not in str(caught.value)


def test_mismatched_archive_custody_hash_rejected():
    from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import object_content

    with pytest.raises(EvidenceError, match="AWS4B_CUSTODY"):
        object_content(replace(source(b"{}"), archive_sha256="0" * 64))


def test_expansion_bomb_is_bounded():
    from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import object_content

    with pytest.raises(EvidenceError, match="AWS4B_"):
        object_content(source(b" " * (4 * 1024 * 1024 + 1)))


def test_concatenated_gzip_members_rejected():
    from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import object_content

    obj = source(b"{}")
    data = obj.archive + obj.archive
    ref = replace(obj.reference, size=len(data))
    obj = replace(
        obj,
        archive=data,
        reference=ref,
        before=ref,
        after=ref,
        archive_sha256=sha256(data).hexdigest(),
    )
    with pytest.raises(EvidenceError, match="AWS4B_"):
        object_content(obj)
