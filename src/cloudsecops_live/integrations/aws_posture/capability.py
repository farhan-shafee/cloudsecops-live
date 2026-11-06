"""One-use fictional session capabilities and a non-redeemable broker design.

No production credential broker or cross-process secret-delivery mechanism is
implemented. A CredentialCapabilityRef binds only metadata and cannot enable
execution. OfflineSessionCapability is an in-memory fake-client harness; it must
never be interpreted as evidence of real custody, MFA or IAM authorization.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import NoReturn

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.contracts import OwnerDecision
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession


def _binding(value: object) -> None:
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise EvidenceError("AWS4A_CAPABILITY")


class _NoSerialization:
    __slots__ = ()

    def __reduce__(self) -> NoReturn:
        raise EvidenceError("AWS4A_CAPABILITY_NOT_SERIALIZABLE")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise EvidenceError("AWS4A_CAPABILITY_NOT_SERIALIZABLE")

    def __getstate__(self) -> NoReturn:
        raise EvidenceError("AWS4A_CAPABILITY_NOT_SERIALIZABLE")


@dataclass(frozen=True, slots=True)
class CredentialCapabilityRef(_NoSerialization):
    """Private broker metadata only; deliberately offers no redemption method."""

    capability_id: str = field(repr=False)
    decision_digest: str = field(repr=False)
    nonce: str = field(repr=False)
    owner_pid: int = field(repr=False)
    expires_at: datetime = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.capability_id, self.decision_digest, self.nonce):
            _binding(value)
        if (
            type(self.owner_pid) is not int
            or not 1 <= self.owner_pid < 2**31
            or type(self.expires_at) is not datetime
            or self.expires_at.utcoffset() != timedelta(0)
        ):
            raise EvidenceError("AWS4A_CAPABILITY")

    def __getstate__(self) -> NoReturn:
        # Frozen slot dataclasses otherwise synthesize their own serializer.
        raise EvidenceError("AWS4A_CAPABILITY_NOT_SERIALIZABLE")

    def public_dict(self) -> dict[str, object]:
        return {
            "state": "pending_private_broker_design",
            "execution_enabled": False,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


class OfflineSessionCapability(_NoSerialization):
    """One-use, same-process fictional material for trusted offline test code."""

    __slots__ = ("_session", "_digest", "_nonce", "_pid", "_consumed", "_lock")

    def __init__(self, session: BoundSession, decision_digest: str, nonce: str) -> None:
        if type(session) is not BoundSession:
            raise EvidenceError("AWS4A_CAPABILITY")
        _binding(decision_digest)
        _binding(nonce)
        self._session, self._digest, self._nonce = session, decision_digest, nonce
        self._pid, self._consumed, self._lock = os.getpid(), False, threading.Lock()

    def __repr__(self) -> str:
        return "OfflineSessionCapability()"

    def redeem(self, decision: OwnerDecision, nonce: str, now: datetime) -> BoundSession:
        # A forked process could inherit an already-held mutex. Reject its copied
        # handle before acquiring that mutex; it cannot consume the parent's handle.
        if os.getpid() != self._pid:
            raise EvidenceError("AWS4A_CAPABILITY_PROCESS")
        with self._lock:
            if self._consumed:
                raise EvidenceError("AWS4A_CAPABILITY_CONSUMED")
            # Every attempted redemption consumes the handle, including failures.
            self._consumed = True
            try:
                if (
                    type(decision) is not OwnerDecision
                    or type(nonce) is not str
                    or nonce != self._nonce
                    or decision.digest != self._digest
                    or self._session._expected != decision.expected
                ):
                    raise EvidenceError("AWS4A_CAPABILITY_BINDING")
                decision.check(now)
                self._session.check(now)
            except (ValueError, TypeError, AttributeError):
                raise EvidenceError("AWS4A_CAPABILITY_REJECTED") from None
            return self._session
