"""Offline identity authorization observations and run-wide dispatch reservations.

No credential discovery, client creation or source authentication is provided.
Role-name exclusions are defensive checks, not evidence of effective IAM policy.
The process supervisor must enforce cancellation while a worker is blocked.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import isfinite
from typing import Literal, NoReturn

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import CallerIdentity
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_sdk.transport import SessionLease


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise EvidenceError("AWS_RUN_TIME")
    return value


@dataclass(frozen=True, slots=True)
class IdentityAuthorization:
    scope: AwsScope = field(repr=False)
    lease: SessionLease = field(repr=False)
    provenance: Literal["owner_supplied_temporary_session"]

    def __post_init__(self) -> None:
        if self.provenance != "owner_supplied_temporary_session":
            raise EvidenceError("AWS_RUN_PROVENANCE")
        if type(self.scope) is not AwsScope or type(self.lease) is not SessionLease:
            raise EvidenceError("AWS_RUN_IDENTITY")
        scope, lease = self.scope, self.lease
        issued, expires = _utc(lease.issued_at), _utc(lease.expires_at)
        if not timedelta(0) < expires - issued <= timedelta(hours=1):
            raise EvidenceError("AWS_RUN_LEASE")
        parts = lease.user_id.split(":")
        role_path = scope.role_arn.split(":role/", 1)[-1]
        role_name = role_path.rsplit("/", 1)[-1]
        if (
            scope.region != "us-east-1"
            or any(word in role_path.casefold() for word in ("admin", "root"))
            or len(parts) != 2
            or parts[0] != scope.role_id
            or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", parts[-1]) is None
            or lease.principal_arn
            != f"arn:aws:sts::{scope.account}:assumed-role/{role_name}/{parts[-1]}"
        ):
            raise EvidenceError("AWS_RUN_IDENTITY")

    def check(self, now: datetime) -> None:
        if not self.lease.issued_at <= _utc(now) < self.lease.expires_at:
            raise EvidenceError("AWS_RUN_LEASE")

    def require_identity(self, observed: CallerIdentity, now: datetime) -> None:
        self.check(now)
        if type(observed) is not CallerIdentity:
            raise EvidenceError("AWS_RUN_IDENTITY")
        if (
            observed.account != self.scope.account
            or observed.region != self.scope.region
            or observed.arn != self.lease.principal_arn
            or observed.user_id != self.lease.user_id
            or _utc(observed.expires_at) != self.lease.expires_at
            or not timedelta(0) <= now - _utc(observed.observed_at) <= timedelta(seconds=60)
        ):
            raise EvidenceError("AWS_RUN_IDENTITY")

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "aws-run-authorization/1",
            "state": "offline_authorization_observation",
            "provenance": "owner_supplied_temporary_session",
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    max_calls: int = 64
    max_pages: int = 16
    max_operations: int = 16
    max_wire_bytes: int = 10 * 1024 * 1024
    max_retries: int = 2
    deadline_seconds: float = 30.0

    def __post_init__(self) -> None:
        for value, ceiling, floor in (
            (self.max_calls, 64, 1),
            (self.max_pages, 16, 1),
            (self.max_operations, 16, 1),
            (self.max_wire_bytes, 10 * 1024 * 1024, 1),
            (self.max_retries, 2, 0),
        ):
            if type(value) is not int or not floor <= value <= ceiling:
                raise EvidenceError("AWS_RUN_LIMITS")
        seconds = self.deadline_seconds
        if type(seconds) not in (int, float) or not 0 < seconds <= 30 or not isfinite(seconds):
            raise EvidenceError("AWS_RUN_LIMITS")


_OPERATIONS = frozenset(
    {
        ("sts", "GetCallerIdentity"),
        ("s3", "ListObjectVersions"),
        ("s3", "HeadObject"),
        ("s3", "GetObject"),
        ("cloudtrail", "GetTrail"),
        ("cloudtrail", "GetTrailStatus"),
        ("cloudtrail", "GetEventSelectors"),
        ("cloudtrail", "GetInsightSelectors"),
    }
)


def _version(value: object) -> bool:
    return (
        isinstance(value, str)
        and value != "null"
        and re.fullmatch(r"[A-Za-z0-9._+~=/:-]{1,1024}", value) is not None
    )


def _key(value: object, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", value) is not None
        and "//" not in value
        and not any(part in (".", "..") for part in value.split("/"))
    )


class OperationBudget:
    """Reserve attempts before dispatch; unsuccessful attempts are never refunded.

    A page is a ListObjectVersions attempt, including failed attempts. Operations
    are distinct initial service calls reserved through begin_operation; the
    client wrapper must reserve one before each initial dispatch. Byte
    reservations must precede exposing received data to a consumer. Any rejection
    permanently invalidates this run; raw diagnostics are never retained.
    """

    def __init__(
        self,
        authorization: IdentityAuthorization,
        policy: BudgetPolicy,
        *,
        monotonic: Callable[[], float],
        clock: Callable[[], datetime],
    ) -> None:
        if type(authorization) is not IdentityAuthorization or type(policy) is not BudgetPolicy:
            raise EvidenceError("AWS_RUN_LIMITS")
        if not callable(monotonic) or not callable(clock):
            raise EvidenceError("AWS_RUN_TIME")
        self.authorization, self.policy = authorization, policy
        self._monotonic, self._clock = monotonic, clock
        self._calls = self._pages = self._operations = self._wire_bytes = self._retries = 0
        self._rejected = False
        self._started = self._last_tick = self._tick()
        self.check()

    def _reject(self, code: str) -> NoReturn:
        self.invalidate()
        raise EvidenceError(code)

    def invalidate(self) -> None:
        self._rejected = True

    def _tick(self) -> float:
        try:
            value = self._monotonic()
            if type(value) not in (int, float) or not isfinite(value):
                self._reject("AWS_RUN_DEADLINE")
            return float(value)
        except EvidenceError:
            raise
        except Exception:
            self._reject("AWS_RUN_DEADLINE")

    def check(self) -> None:
        if self._rejected:
            raise EvidenceError("AWS_RUN_REJECTED")
        tick = self._tick()
        if tick < self._last_tick or tick - self._started >= self.policy.deadline_seconds:
            self._reject("AWS_RUN_DEADLINE")
        self._last_tick = tick
        try:
            now = self._clock()
        except Exception:
            self._reject("AWS_RUN_TIME")
        try:
            self.authorization.check(now)
        except EvidenceError:
            self.invalidate()
            raise

    def begin_operation(self) -> None:
        self.check()
        if self._operations >= self.policy.max_operations:
            self._reject("AWS_RUN_OPERATION_LIMIT")
        self._operations += 1

    def _source(self, service: str, operation: str, params: Mapping[str, object]) -> None:
        scope = self.authorization.scope
        if (
            type(service) is not str
            or type(operation) is not str
            or (service, operation) not in _OPERATIONS
            or type(params) is not dict
        ):
            self._reject("AWS_RUN_OPERATION")
        if service == "sts":
            if params:
                self._reject("AWS_RUN_SOURCE")
            return
        if service == "cloudtrail":
            key = "Name" if operation in ("GetTrail", "GetTrailStatus") else "TrailName"
            if params != {key: scope.trail_arn}:
                self._reject("AWS_RUN_SOURCE")
            return
        if (
            params.get("Bucket") != scope.bucket
            or params.get("ExpectedBucketOwner") != scope.account
        ):
            self._reject("AWS_RUN_SOURCE")
        if operation == "ListObjectVersions":
            required = {"Bucket", "ExpectedBucketOwner", "Prefix", "MaxKeys"}
            markers = {"KeyMarker", "VersionIdMarker"}
            prefix = params.get("Prefix")
            maximum = params.get("MaxKeys")
            if (
                set(params) not in (required, required | markers)
                or prefix not in (scope.log_prefix, scope.digest_prefix)
                or type(maximum) is not int
                or not 1 <= maximum <= 64
            ):
                self._reject("AWS_RUN_SOURCE")
            if markers <= set(params) and (
                not _key(params["KeyMarker"], str(prefix))
                or not _version(params["VersionIdMarker"])
            ):
                self._reject("AWS_RUN_SOURCE")
            return
        required = {"Bucket", "ExpectedBucketOwner", "Key"}
        if operation == "GetObject":
            required.add("VersionId")
        object_key = params.get("Key")
        if (
            set(params) != required
            or not any(
                _key(object_key, prefix) for prefix in (scope.log_prefix, scope.digest_prefix)
            )
            or not isinstance(object_key, str)
            or not object_key.endswith(".json.gz")
            or operation == "GetObject"
            and not _version(params.get("VersionId"))
        ):
            self._reject("AWS_RUN_SOURCE")

    def reserve_attempt(
        self,
        service: str,
        operation: str,
        parameters: Mapping[str, object],
        *,
        retry: bool = False,
    ) -> None:
        self.check()
        self._source(service, operation, parameters)
        if type(retry) is not bool:
            self._reject("AWS_RUN_RETRY_LIMIT")
        page = service == "s3" and operation == "ListObjectVersions"
        if self._calls >= self.policy.max_calls:
            self._reject("AWS_RUN_CALL_LIMIT")
        if page and self._pages >= self.policy.max_pages:
            self._reject("AWS_RUN_PAGE_LIMIT")
        if retry and self._retries >= self.policy.max_retries:
            self._reject("AWS_RUN_RETRY_LIMIT")
        self._calls += 1
        self._pages += int(page)
        self._retries += int(retry)

    def consume_wire_bytes(self, count: int) -> None:
        self.check()
        if (
            type(count) is not int
            or count < 0
            or count > self.policy.max_wire_bytes - self._wire_bytes
        ):
            self._reject("AWS_RUN_BYTE_LIMIT")
        self._wire_bytes += count

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "aws-run-budget/1",
            "state": "rejected" if self._rejected else "offline_budget_observation",
            "calls": self._calls,
            "pages": self._pages,
            "operations": self._operations,
            "wire_bytes": self._wire_bytes,
            "retries": self._retries,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }
