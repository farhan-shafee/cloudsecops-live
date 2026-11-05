"""Strict reference-only posture requests and pending private owner decisions.

Neither complete-looking metadata nor a matching digest establishes authorization,
effective IAM, credential custody or source authenticity. There is no approved
decision constructor or live activation state in this milestone.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, ClassVar, Literal, cast

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.requests import PostureRequest as PostureRequest
from cloudsecops_live.integrations.aws_readiness.permissions import POSTURE_OPERATIONS
from cloudsecops_live.integrations.aws_readiness.sessions import ExpectedIdentity, Purpose
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy

_FIXED_OPERATIONS = tuple(
    sorted(f"{service}:{operation}" for service, operation in POSTURE_OPERATIONS)
)


def _hex(value: object, size: int, code: str) -> str:
    if type(value) is not str or re.fullmatch(f"[a-f0-9]{{{size}}}", value) is None:
        raise EvidenceError(code)
    return value


def _utc(value: object, code: str) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise EvidenceError(code)
    return value


def _time(value: object) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise EvidenceError("AWS4A_DECISION")
    try:
        return _utc(datetime.fromisoformat(value), "AWS4A_DECISION")
    except ValueError:
        raise EvidenceError("AWS4A_DECISION") from None


def _reference(value: object) -> None:
    if type(value) is not str:
        raise EvidenceError("AWS4A_DECISION")
    if value != "pending":
        _hex(value, 64, "AWS4A_DECISION")


@dataclass(frozen=True, slots=True)
class PolicyBinding:
    name: str = field(repr=False)
    sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", self.name) is None
        ):
            raise EvidenceError("AWS4A_POLICY_BINDING")
        _hex(self.sha256, 64, "AWS4A_POLICY_BINDING")

    def to_metadata(self) -> dict[str, str]:
        return {"name": self.name, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class OwnerDecision:
    """Private binding observations only; a digest is not an approval receipt."""

    record_id: str = field(repr=False)
    expected: ExpectedIdentity = field(repr=False)
    window_start: datetime
    window_end: datetime
    budget: BudgetPolicy
    inline_policies: tuple[PolicyBinding, ...] = field(repr=False)
    source_revision: str = field(repr=False)
    owner_ref: str = field(repr=False)
    custody_ref: str = field(repr=False)
    effective_iam_ref: str = field(repr=False)
    network_ref: str = field(repr=False)
    ca_sha256: str = field(repr=False)
    review_state: Literal["pending"] = "pending"
    SCHEMA_VERSION: ClassVar[str] = "aws4a-owner-decision/1"

    def __post_init__(self) -> None:
        _hex(self.record_id, 64, "AWS4A_DECISION")
        _hex(self.source_revision, 40, "AWS4A_DECISION")
        if (
            type(self.expected) is not ExpectedIdentity
            or self.expected.purpose is not Purpose.POSTURE
            or self.expected.region != "us-east-1"
            or type(self.budget) is not BudgetPolicy
            or type(self.review_state) is not str
            or self.review_state != "pending"
            or type(self.inline_policies) is not tuple
            or not 1 <= len(self.inline_policies) <= 8
            or any(type(item) is not PolicyBinding for item in self.inline_policies)
        ):
            raise EvidenceError("AWS4A_DECISION")
        try:
            ExpectedIdentity.from_metadata(self.expected.to_metadata())
        except (ValueError, TypeError, AttributeError):
            raise EvidenceError("AWS4A_DECISION") from None
        if len({policy.name for policy in self.inline_policies}) != len(self.inline_policies):
            raise EvidenceError("AWS4A_DECISION")
        for reference in (
            self.owner_ref,
            self.custody_ref,
            self.effective_iam_ref,
            self.network_ref,
            self.ca_sha256,
        ):
            _reference(reference)
        start, end = (
            _utc(self.window_start, "AWS4A_DECISION"),
            _utc(self.window_end, "AWS4A_DECISION"),
        )
        if not timedelta(0) < end - start <= timedelta(hours=1):
            raise EvidenceError("AWS4A_DECISION")

    @property
    def digest(self) -> str:
        raw = json.dumps(self.to_metadata(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def check(self, now: datetime) -> None:
        if not self.window_start <= _utc(now, "AWS4A_DECISION") < self.window_end:
            raise EvidenceError("AWS4A_DECISION")

    def to_metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "record_id": self.record_id,
            "expected": self.expected.to_metadata(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "budget": asdict(self.budget),
            "inline_policies": [binding.to_metadata() for binding in self.inline_policies],
            "source_revision": self.source_revision,
            "owner_ref": self.owner_ref,
            "custody_ref": self.custody_ref,
            "effective_iam_ref": self.effective_iam_ref,
            "network_ref": self.network_ref,
            "ca_sha256": self.ca_sha256,
            "review_state": self.review_state,
            "operations": list(_FIXED_OPERATIONS),
        }

    @classmethod
    def from_metadata(cls, value: object) -> OwnerDecision:
        fields = {
            "schema_version",
            "record_id",
            "expected",
            "window_start",
            "window_end",
            "budget",
            "inline_policies",
            "source_revision",
            "owner_ref",
            "custody_ref",
            "effective_iam_ref",
            "network_ref",
            "ca_sha256",
            "review_state",
            "operations",
        }
        if (
            type(value) is not dict
            or len(value) != len(fields)
            or set(value) != fields
            or type(value["schema_version"]) is not str
            or value["schema_version"] != cls.SCHEMA_VERSION
            or type(value["operations"]) is not list
            or any(type(operation) is not str for operation in value["operations"])
            or value["operations"] != list(_FIXED_OPERATIONS)
            or type(value["budget"]) is not dict
            or len(value["budget"]) != len(asdict(BudgetPolicy()))
            or set(value["budget"]) != set(asdict(BudgetPolicy()))
            or type(value["inline_policies"]) is not list
            or not 1 <= len(value["inline_policies"]) <= 8
        ):
            raise EvidenceError("AWS4A_DECISION")
        try:
            bindings = []
            for item in value["inline_policies"]:
                if type(item) is not dict or len(item) != 2 or set(item) != {"name", "sha256"}:
                    raise EvidenceError("AWS4A_DECISION")
                bindings.append(PolicyBinding(item["name"], item["sha256"]))
            return cls(
                record_id=value["record_id"],
                expected=ExpectedIdentity.from_metadata(value["expected"]),
                window_start=_time(value["window_start"]),
                window_end=_time(value["window_end"]),
                budget=BudgetPolicy(**value["budget"]),
                inline_policies=tuple(bindings),
                source_revision=value["source_revision"],
                owner_ref=value["owner_ref"],
                custody_ref=value["custody_ref"],
                effective_iam_ref=value["effective_iam_ref"],
                network_ref=value["network_ref"],
                ca_sha256=value["ca_sha256"],
                review_state=cast(Literal["pending"], value["review_state"]),
            )
        except (ValueError, TypeError, KeyError):
            raise EvidenceError("AWS4A_DECISION") from None

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "state": "pending_owner_review",
            "execution_enabled": False,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


@dataclass(frozen=True, slots=True)
class PostureClients:
    """Trusted-code test/client bundle, never a request or factory selector."""

    sts: Any = field(repr=False)
    iam: Any = field(repr=False)
    cloudtrail: Any = field(repr=False)
    s3: Any = field(repr=False)
    s3control: Any = field(repr=False)
