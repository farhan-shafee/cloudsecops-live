"""Offline supplied-input contracts; no AWS-origin or workflow authority."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope

type Reference = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class SuppliedKey:
    fingerprint: str
    region: str
    valid_from: datetime
    valid_until: datetime
    der: bytes = field(repr=False)
    der_sha256: str


@dataclass(frozen=True, slots=True)
class AcquiredObject:
    reference: ObjectVersion
    archive: bytes = field(repr=False)
    archive_sha256: str
    before: ObjectVersion
    after: ObjectVersion
    observed_before: datetime
    retrieval_start: datetime
    retrieval_end: datetime
    observed_after: datetime
    metadata: tuple[tuple[str, str], ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class ChainAnchor:
    reference: Reference
    content_sha256: str
    signature: str = field(repr=False)
    end: datetime


@dataclass(frozen=True, slots=True)
class ChainSpec:
    kind: Literal["standard", "backfill"]
    head: Reference | None
    anchor: ChainAnchor | None = None


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    scope: AwsScope
    start: datetime
    end: datetime
    standard: ChainSpec
    backfill: ChainSpec


@dataclass(frozen=True, slots=True)
class ObjectBinding:
    reference: Reference
    archive_sha256: str
    content_sha256: str
    record_sha256: tuple[str, ...] = ()
    chain: str = ""
    key_sha256: str = ""
    signature_sha256: str = ""
    key_time: datetime | None = None


@dataclass(frozen=True, slots=True)
class SignedAssessment:
    state: Literal["consistent", "invalid", "incomplete", "conflicting", "unsupported"]
    reason: str
    digests: tuple[ObjectBinding, ...] = field(default=(), repr=False)
    logs: tuple[ObjectBinding, ...] = field(default=(), repr=False)
    unique_events: int = 0
    duplicate_events: int = 0
    backfill_supplied: bool = False
    plan: VerificationPlan | None = field(default=None, repr=False)
    key_bindings: tuple[tuple[str, str, datetime, datetime], ...] = field(default=(), repr=False)
    authenticated: Literal[False] = field(default=False, init=False)
    trusted_findings: Literal[False] = field(default=False, init=False)
    may_close: Literal[False] = field(default=False, init=False)

    def public(self) -> dict[str, str | int | bool]:
        return {
            "schema": "aws-signed-offline/1",
            "checker": "aws4b/1.0.0",
            "scope": "offline_supplied_key_consistency_only",
            "state": self.state,
            "reason": self.reason,
            "digest_count": len(self.digests),
            "log_count": len(self.logs),
            "unique_events": self.unique_events,
            "duplicate_events": self.duplicate_events,
            "backfill_supplied": self.backfill_supplied,
            "aws_origin": "unproven",
            "key_provenance": "supplied_not_authenticated",
            "acquisition_provenance": "supplied_not_authenticated",
            "inventory_completeness": "unproven",
            "authenticated": False,
            "trusted_findings": False,
            "may_close": False,
        }
