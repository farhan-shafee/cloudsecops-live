"""Sticky, aggregate posture-only reservations; no live dispatch authority."""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import NoReturn

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.contracts import OwnerDecision
from cloudsecops_live.integrations.aws_readiness.permissions import POSTURE_OPERATIONS
from cloudsecops_live.integrations.aws_readiness.requests import encode
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession


def _token(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 1024
        and all(32 <= ord(character) < 127 for character in value)
    )


def _encoded(params: dict[str, object]) -> bytes:
    encode(params)  # Bound allocation and exact JSON types before sorting.
    return json.dumps(params, sort_keys=True, separators=(",", ":")).encode()


class PostureBudget:
    """Reserve before API use; no failed attempt or byte reservation is refunded.

    Logical parameter bytes and observed wire bytes share one ceiling. Real wire
    adapters may therefore conservatively charge additional overhead; they must
    never omit actual request bodies or response framing/body bytes.
    """

    def __init__(
        self,
        decision: OwnerDecision,
        session: BoundSession,
        *,
        clock: Callable[[], datetime],
        monotonic: Callable[[], float],
    ) -> None:
        if type(decision) is not OwnerDecision or type(session) is not BoundSession:
            raise EvidenceError("AWS4A_BUDGET_CONTRACT")
        if not callable(clock) or not callable(monotonic):
            raise EvidenceError("AWS4A_CLOCK")
        self.decision, self.session, self.policy = decision, session, decision.budget
        self._clock, self._monotonic = clock, monotonic
        self._failed = False
        self._calls = self._pages = self._operations = self._retries = 0
        self._request_bytes = self._response_bytes = 0
        self._reservation: tuple[str, str, bytes] | None = None
        self._authorized = self._wire_authorized = self._sent = False
        self._last = self._started = self._tick()
        self.check()

    def _reject(self, code: str) -> NoReturn:
        self._failed = True
        raise EvidenceError(code)

    def _tick(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            self._failed = True
            raise EvidenceError("AWS4A_CLOCK") from None
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            self._reject("AWS4A_CLOCK")
        return float(value)

    def check(self) -> None:
        if self._failed:
            raise EvidenceError("AWS4A_REJECTED")
        try:
            tick = self._tick()
            if tick < self._last or tick - self._started >= self.policy.deadline_seconds:
                self._reject("AWS4A_DEADLINE")
            self._last = tick
            try:
                now = self._clock()
            except Exception:
                raise EvidenceError("AWS4A_CLOCK") from None
            self.decision.check(now)
            self.session.check(now)
            if self.session._expected != self.decision.expected:
                self._reject("AWS4A_SESSION_IDENTITY")
        except Exception:
            self._failed = True
            raise

    def invalidate(self) -> None:
        self._failed = True

    def check_signing_time(self, instant: datetime) -> None:
        """Signing time must belong to this current decision and temporary lease."""
        self.check()
        try:
            now = self._clock()
            self.decision.check(now)
            self.session.check(now)
            # SDK signing timestamps have whole-second precision. Actual session
            # and observation validity is checked at now; an observation made in
            # this same fractional second must not appear to be in the future.
            if (
                type(instant) is not datetime
                or instant.utcoffset() != timedelta(0)
                or instant.microsecond != 0
                or not self.decision.window_start.replace(microsecond=0)
                <= instant
                < self.decision.window_end
                or not self.session.lease.issued_at.replace(microsecond=0)
                <= instant
                < self.session.lease.expires_at
                or not timedelta(0) <= now.replace(microsecond=0) - instant <= timedelta(seconds=30)
            ):
                self._reject("AWS4A_SIGNING_TIME")
        except Exception:
            self._failed = True
            raise EvidenceError("AWS4A_SIGNING_TIME") from None

    @property
    def remaining_wire_bytes(self) -> int:
        return max(0, self.policy.max_wire_bytes - self._request_bytes - self._response_bytes)

    def _parameters(self, service: str, operation: str, params: dict[str, object]) -> bytes:
        if (
            type(service) is not str
            or type(operation) is not str
            or (service, operation) not in POSTURE_OPERATIONS
            or type(params) is not dict
        ):
            self._reject("AWS4A_OPERATION")
        encoded = _encoded(params)  # Reject nondata values before any comparison hook.
        name = self.decision.expected.role_arn.rsplit("/", 1)[-1]
        valid = False
        if service == "sts":
            valid = not params
        elif service == "s3control":
            valid = (
                set(params) == {"AccountId"}
                and params["AccountId"] == self.decision.expected.account
            )
        elif service == "cloudtrail":
            valid = not params or set(params) == {"NextToken"} and _token(params["NextToken"])
        elif service == "s3":
            valid = (
                set(params) in ({"MaxBuckets"}, {"MaxBuckets", "ContinuationToken"})
                and type(params.get("MaxBuckets")) is int
                and params["MaxBuckets"] == 64
                and ("ContinuationToken" not in params or _token(params["ContinuationToken"]))
            )
        elif operation == "GetRole":
            valid = set(params) == {"RoleName"} and params["RoleName"] == name
        elif operation == "GetRolePolicy":
            valid = (
                set(params) == {"RoleName", "PolicyName"}
                and params["RoleName"] == name
                and params["PolicyName"] in {item.name for item in self.decision.inline_policies}
            )
        else:
            valid = (
                set(params) in ({"RoleName", "MaxItems"}, {"RoleName", "MaxItems", "Marker"})
                and params.get("RoleName") == name
                and type(params.get("MaxItems")) is int
                and params["MaxItems"] == 64
                and ("Marker" not in params or _token(params["Marker"]))
            )
        if not valid:
            self._reject("AWS4A_PARAMETERS")
        return encoded

    def before_call(
        self,
        service: str,
        operation: str,
        params: dict[str, object],
        retry: bool = False,
    ) -> None:
        self.check()
        try:
            encoded = self._parameters(service, operation, params)
            reservation = (service, operation, encoded)
            page = operation.startswith("List")
            if type(retry) is not bool or retry and reservation != self._reservation:
                self._reject("AWS4A_RETRY")
            if (
                self._calls >= self.policy.max_calls
                or page
                and self._pages >= self.policy.max_pages
                or not retry
                and self._operations >= self.policy.max_operations
                or retry
                and self._retries >= self.policy.max_retries
            ):
                self._reject("AWS4A_BUDGET")
            self.consume_request_bytes(len(encoded))
            self._calls += 1
            self._pages += int(page)
            self._operations += int(not retry)
            self._retries += int(retry)
            self._reservation = reservation
            self._authorized = self._wire_authorized = self._sent = False
        except Exception:
            self._failed = True
            raise

    def authorize_parameters(self, service: str, operation: str, params: dict[str, object]) -> None:
        self.check()
        try:
            if (
                self._authorized
                or (service, operation, self._parameters(service, operation, params))
                != self._reservation
            ):
                self._reject("AWS4A_DISPATCH_BINDING")
            self._authorized = True
        except Exception:
            self._failed = True
            raise

    def before_send(self, service: str) -> None:
        self.check()
        if (
            self._reservation is None
            or self._reservation[0] != service
            or not self._authorized
            or not self._wire_authorized
            or self._sent
        ):
            self._reject("AWS4A_SEND_BINDING")
        self._sent = True

    def wire_reservation(self, service: str) -> tuple[str, dict[str, object]]:
        """Return a fresh reservation snapshot for strict serialized-wire decoding."""
        self.check()
        if (
            type(service) is not str
            or self._reservation is None
            or self._reservation[0] != service
            or not self._authorized
            or self._sent
        ):
            self._reject("AWS4A_WIRE_BINDING")
        return self._reservation[1], json.loads(self._reservation[2])

    def authorize_wire_parameters(
        self, service: str, operation: str, params: dict[str, object]
    ) -> None:
        """Bind the decoded final HTTP request to its one-use logical reservation."""
        try:
            self.wire_reservation(service)
            if (
                self._wire_authorized
                or (service, operation, self._parameters(service, operation, params))
                != self._reservation
            ):
                self._reject("AWS4A_WIRE_BINDING")
            self._wire_authorized = True
        except Exception:
            self._failed = True
            raise

    def _consume(self, count: int, request: bool) -> None:
        self.check()
        if type(count) is not int or count < 0 or count > self.remaining_wire_bytes:
            self._reject("AWS4A_WIRE_BUDGET")
        if request:
            self._request_bytes += count
        else:
            self._response_bytes += count

    def consume_request_bytes(self, count: int) -> None:
        self._consume(count, True)

    def consume_response_bytes(self, count: int) -> None:
        self._consume(count, False)

    def public_dict(self) -> dict[str, object]:
        return {
            "state": "rejected" if self._failed else "offline_budget_observation",
            "calls": self._calls,
            "pages": self._pages,
            "operations": self._operations,
            "retries": self._retries,
            "request_bytes": self._request_bytes,
            "response_bytes": self._response_bytes,
            "wire_bytes": self._request_bytes + self._response_bytes,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }
