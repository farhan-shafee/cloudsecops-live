"""Bounded, data-only requests for three fixed offline workers.

The tape is fictional response data, never a client, callable, import or command.
No credential material is accepted or serialized by these request contracts.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Self

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_readiness.permissions import require_operation
from cloudsecops_live.integrations.aws_readiness.sessions import (
    ExpectedIdentity,
    Purpose,
    SessionIssuance,
    StsObservation,
)
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy

MAX_FIXTURE_BYTES = 512 * 1024
_POSTURE = frozenset(
    {
        "sts:GetCallerIdentity",
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "cloudtrail:ListTrails",
        "s3:ListBuckets",
        "s3control:GetPublicAccessBlock",
    }
)
_ARCHIVE = frozenset(
    {
        "sts:GetCallerIdentity",
        "s3:ListObjectVersions",
        "s3:HeadObject",
        "s3:GetObject",
    }
)
_CREDENTIAL_FIELDS = frozenset(
    {
        "credentials",
        "secret_access_key",
        "aws_secret_access_key",
        "secret_key",
        "session_token",
        "aws_session_token",
        "access_key_id",
        "aws_access_key_id",
    }
)


def _string_size(value: str, remaining: int) -> int:
    # json.dumps uses ensure_ascii=True. Count its escaping without producing an
    # intermediate string; even a single scalar must fit the aggregate budget.
    if len(value) + 2 > remaining:
        raise EvidenceError("AWS3_REQUEST")
    size = 2
    for character in value:
        codepoint = ord(character)
        if character in '"\\\b\f\n\r\t':
            size += 2
        elif 32 <= codepoint <= 126:
            size += 1
        else:
            size += 6 if codepoint <= 0xFFFF else 12
        if size > remaining:
            raise EvidenceError("AWS3_REQUEST")
    return size


def encode(value: object) -> bytes:
    """Preflight bounded JSON allocation without invoking serialization hooks.

    Container lengths bound pending stack growth before children are queued.
    Escaped strings and scalar tokens consume one aggregate byte reservation
    before json.dumps can allocate the final, at most 512 KiB, representation.
    """
    issuance = value.get("issuance") if type(value) is dict else None
    stack = [(value, 0)]
    nodes = 0
    remaining = MAX_FIXTURE_BYTES
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 24 or nodes > 30_000:
            raise EvidenceError("AWS3_REQUEST")
        if type(item) is dict or type(item) is list:
            if len(item) > 30_000 - nodes - len(stack):
                raise EvidenceError("AWS3_REQUEST")
            remaining -= 2 + max(0, len(item) - 1)
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise EvidenceError("AWS3_REQUEST")
                remaining -= _string_size(key, remaining) + 1
                if key.casefold() in _CREDENTIAL_FIELDS and not (
                    key == "access_key_id" and item is issuance
                ):
                    raise EvidenceError("AWS3_REQUEST")
                stack.append((child, depth + 1))
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            remaining -= _string_size(item, remaining)
        elif type(item) is int:
            # An upper bound derived from bit_length prevents huge integer
            # decimal conversion before its bounded token is reserved.
            upper = item.bit_length() * 30103 // 100000 + 1 + int(item < 0)
            if upper > remaining:
                raise EvidenceError("AWS3_REQUEST")
            try:
                remaining -= len(str(item))
            except ValueError:
                raise EvidenceError("AWS3_REQUEST") from None
        elif type(item) is float:
            if not math.isfinite(item):
                raise EvidenceError("AWS3_REQUEST")
            remaining -= len(repr(item))
        elif type(item) is bool:
            remaining -= 4 if item else 5
        elif item is None:
            remaining -= 4
        else:
            raise EvidenceError("AWS3_REQUEST")
        if remaining < 0:
            raise EvidenceError("AWS3_REQUEST")
    try:
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
    except (ValueError, TypeError, UnicodeError):
        raise EvidenceError("AWS3_REQUEST") from None
    if len(raw) > MAX_FIXTURE_BYTES:
        raise EvidenceError("AWS3_REQUEST")
    return raw


def utc(value: object) -> datetime:
    if type(value) is not str:
        raise EvidenceError("AWS3_REQUEST")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise EvidenceError("AWS3_REQUEST") from None
    if parsed.utcoffset() != timedelta(0):
        raise EvidenceError("AWS3_REQUEST")
    return parsed


class Fault(StrEnum):
    NONE = "none"
    DENY = "deny"
    RETRY = "retry"
    STALL = "stall"
    SUBSTITUTE = "substitute"


@dataclass(frozen=True, slots=True)
class TapeRecord:
    operation: str
    parameters: bytes = field(repr=False)
    response: bytes = field(repr=False)
    fault: Fault


@dataclass(frozen=True, slots=True)
class Tape:
    records: tuple[TapeRecord, ...] = field(repr=False)

    @classmethod
    def from_metadata(cls, value: object, purpose: Purpose) -> Tape:
        if type(value) is not list or not 1 <= len(value) <= 64:
            raise EvidenceError("AWS3_TAPE")
        allowed = _POSTURE if purpose is Purpose.POSTURE else _ARCHIVE
        records = []
        for item in value:
            if (
                type(item) is not dict
                or set(item) != {"operation", "parameters", "response", "fault"}
                or type(item["operation"]) is not str
                or item["operation"] not in allowed
                or type(item["parameters"]) is not dict
                or type(item["response"]) is not dict
                or type(item["fault"]) is not str
            ):
                raise EvidenceError("AWS3_TAPE")
            try:
                fault = Fault(item["fault"])
            except ValueError:
                raise EvidenceError("AWS3_TAPE") from None
            service, operation = item["operation"].split(":")
            require_operation(purpose.value, service, operation)
            records.append(
                TapeRecord(
                    item["operation"], encode(item["parameters"]), encode(item["response"]), fault
                )
            )
        return cls(tuple(records))


@dataclass(frozen=True, slots=True)
class ParsedRequest:
    expected: ExpectedIdentity = field(repr=False)
    issuance: SessionIssuance = field(repr=False)
    observed: StsObservation = field(repr=False)
    as_of: datetime
    policy: BudgetPolicy
    tape: Tape = field(repr=False)
    inline_policy_names: tuple[str, ...] = ()
    scope: AwsScope | None = field(default=None, repr=False)
    checkpoint: str = ""
    expected_content_hashes: tuple[str, ...] = field(default=(), repr=False)


def parse_request(value: object, purpose: Purpose) -> ParsedRequest:
    encode(value)
    fields = {"expected", "issuance", "observed", "as_of", "budget", "tape"}
    fields |= {"inline_policy_names"} if purpose is Purpose.POSTURE else {"scope", "checkpoint"}
    if purpose is Purpose.VERIFIER:
        fields.add("expected_content_hashes")
    if type(value) is not dict or set(value) != fields or type(value["budget"]) is not dict:
        raise EvidenceError("AWS3_REQUEST")
    if set(value["budget"]) != set(asdict(BudgetPolicy())):
        raise EvidenceError("AWS3_REQUEST")
    expected = ExpectedIdentity.from_metadata(value["expected"])
    if expected.purpose is not purpose:
        raise EvidenceError("AWS3_REQUEST")
    issuance = SessionIssuance.from_metadata(value["issuance"])
    observed = StsObservation.from_metadata(value["observed"])
    policy = BudgetPolicy(**value["budget"])
    tape = Tape.from_metadata(value["tape"], purpose)
    scope, checkpoint, names, hashes = None, "", (), ()
    if purpose is Purpose.POSTURE:
        supplied = value["inline_policy_names"]
        if (
            type(supplied) is not list
            or len(supplied) > 8
            or any(
                type(name) is not str or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", name) is None
                for name in supplied
            )
            or len(set(supplied)) != len(supplied)
        ):
            raise EvidenceError("AWS3_REQUEST")
        names = tuple(supplied)
    else:
        supplied_scope, checkpoint = value["scope"], value["checkpoint"]
        if (
            type(supplied_scope) is not dict
            or set(supplied_scope)
            != {
                "account",
                "region",
                "role_arn",
                "role_id",
                "trail_arn",
                "bucket",
                "log_prefix",
                "digest_prefix",
            }
            or type(checkpoint) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", checkpoint) is None
        ):
            raise EvidenceError("AWS3_REQUEST")
        scope = AwsScope(**supplied_scope)
        if (scope.account, scope.region, scope.role_arn, scope.role_id) != (
            expected.account,
            expected.region,
            expected.role_arn,
            expected.role_id,
        ):
            raise EvidenceError("AWS3_REQUEST")
    if purpose is Purpose.VERIFIER:
        supplied_hashes = value["expected_content_hashes"]
        if (
            type(supplied_hashes) is not list
            or not 1 <= len(supplied_hashes) <= 64
            or any(
                type(item) is not str or re.fullmatch(r"[a-f0-9]{64}", item) is None
                for item in supplied_hashes
            )
        ):
            raise EvidenceError("AWS3_REQUEST")
        hashes = tuple(supplied_hashes)
    return ParsedRequest(
        expected,
        issuance,
        observed,
        utc(value["as_of"]),
        policy,
        tape,
        names,
        scope,
        checkpoint,
        hashes,
    )


@dataclass(frozen=True, slots=True)
class _Request:
    _payload: bytes = field(repr=False)
    PURPOSE: ClassVar[Purpose]

    def __post_init__(self) -> None:
        if type(self._payload) is not bytes or len(self._payload) > MAX_FIXTURE_BYTES:
            raise EvidenceError("AWS3_REQUEST")
        try:
            value = json.loads(self._payload)
        except (ValueError, UnicodeError, RecursionError):
            raise EvidenceError("AWS3_REQUEST") from None
        parse_request(value, self.PURPOSE)
        if encode(value) != self._payload:
            raise EvidenceError("AWS3_REQUEST")

    @classmethod
    def from_metadata(cls, value: object) -> Self:
        return cls(encode(value))

    def to_metadata(self) -> object:
        return json.loads(self._payload)


@dataclass(frozen=True, slots=True)
class PostureRequest(_Request):
    PURPOSE = Purpose.POSTURE


@dataclass(frozen=True, slots=True)
class CollectionRequest(_Request):
    PURPOSE = Purpose.COLLECTOR


@dataclass(frozen=True, slots=True)
class VerificationRequest(_Request):
    PURPOSE = Purpose.VERIFIER
