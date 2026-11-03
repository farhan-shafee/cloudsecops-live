"""Controlled authenticity-contract checks, never an AWS cryptographic validator."""

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import RetrievedLog


class CheckOutcome(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    PENDING = "pending"


@dataclass(frozen=True, slots=True)
class DigestMember:
    bucket: str
    key: str
    version_id: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class ControlledValidation:
    """Test-only observations in a protocol, not a signed authoritative receipt.

    The supported CLI has no VersionId switch. A future implementation must
    establish version continuity around original-location validation and exact
    signed membership; filling in this dataclass cannot establish either fact.
    """

    tool_version: str
    exit_code: int
    signature: CheckOutcome
    standard_chain: CheckOutcome
    backfill_chain: CheckOutcome
    members: tuple[DigestMember, ...]
    complete: bool
    versions_unchanged: bool


@dataclass(frozen=True, slots=True)
class DigestAssessment:
    state: str
    reason: str
    consistency_passed: bool
    authenticated: Literal[False] = field(default=False, init=False)
    source_kind: Literal["aws_shaped_unverified"] = field(
        default="aws_shaped_unverified", init=False
    )


def assess_digest(obj: RetrievedLog, result: ControlledValidation) -> DigestAssessment:
    """Reject incomplete controlled evidence; consistent test data stays pending."""
    if (
        type(obj) is not RetrievedLog
        or type(result) is not ControlledValidation
        or not isinstance(result.tool_version, str)
        or not 1 <= len(result.tool_version) <= 128
        or type(result.exit_code) is not int
        or any(
            type(v) is not CheckOutcome
            for v in (result.signature, result.standard_chain, result.backfill_chain)
        )
        or type(result.complete) is not bool
        or type(result.versions_unchanged) is not bool
        or type(result.members) is not tuple
        or len(result.members) > 64
    ):
        raise EvidenceError("AWS_VALIDATION_RECEIPT")
    for member in result.members:
        if (
            type(member) is not DigestMember
            or any(
                not isinstance(v, str) or not 1 <= len(v) <= 1024
                for v in (member.bucket, member.key, member.version_id)
            )
            or not isinstance(member.content_sha256, str)
            or len(member.content_sha256) != 64
            or any(c not in "0123456789abcdef" for c in member.content_sha256)
        ):
            raise EvidenceError("AWS_VALIDATION_RECEIPT")

    def rejected(reason: str, *, pending: bool = False) -> DigestAssessment:
        return DigestAssessment(
            "pending_source_authentication" if pending else "invalid", reason, False
        )

    if result.exit_code != 0:
        return rejected("AWS_VALIDATION_COMMAND_FAILED")
    if not result.complete:
        return rejected("AWS_VALIDATION_INCOMPLETE", pending=True)
    if not result.versions_unchanged:
        return rejected("AWS_SOURCE_CHANGED")
    if result.signature is CheckOutcome.INVALID:
        return rejected("AWS_DIGEST_SIGNATURE_INVALID")
    if CheckOutcome.INVALID in (result.standard_chain, result.backfill_chain):
        return rejected("AWS_DIGEST_CHAIN_INVALID")
    if CheckOutcome.PENDING in (result.signature, result.standard_chain, result.backfill_chain):
        return rejected("AWS_DIGEST_PENDING", pending=True)
    if (
        sha256(obj.log.archive_bytes).hexdigest() != obj.log.archive_sha256
        or sha256(obj.log.content_bytes).hexdigest() != obj.log.content_sha256
    ):
        return rejected("AWS_LOCAL_HASH_MISMATCH")
    exact = [
        m
        for m in result.members
        if (m.bucket, m.key, m.version_id)
        == (obj.reference.bucket, obj.reference.key, obj.reference.version_id)
    ]
    if not exact:
        return rejected("AWS_DIGEST_MEMBERSHIP_MISSING", pending=True)
    hashes = {m.content_sha256 for m in exact}
    if len(hashes) != 1:
        return DigestAssessment("conflicting", "AWS_DIGEST_MEMBERSHIP_CONFLICT", False)
    if hashes != {obj.log.content_sha256}:
        return rejected("AWS_DIGEST_CONTENT_MISMATCH")
    return DigestAssessment("pending_source_authentication", "AWS_AUTHENTICATION_UNAVAILABLE", True)
