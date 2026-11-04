"""Offline, identity-only bindings for explicitly supplied temporary credentials.

No AWS session, credential provider, client, source authenticator or role
assumption is created here. STS identity observations contain only the facts
GetCallerIdentity supplies; region, issue/expiry and MFA are separate supplied
observations. Consistency never proves their authenticity or effective IAM
permissions. All public results remain unverified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, StrEnum
from typing import Any, cast

from botocore.credentials import Credentials  # type: ignore[import-untyped]

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_sdk.transport import SessionLease


class Purpose(StrEnum):
    POSTURE = "posture"
    COLLECTOR = "collector"
    VERIFIER = "verifier"


class CredentialSource(StrEnum):
    OWNER_SUPPLIED_TEMPORARY_SESSION = "owner_supplied_temporary_session"


def _text(value: object) -> str:
    if type(value) is not str:
        raise EvidenceError("AWS3_SESSION_METADATA")
    return value


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise EvidenceError("AWS3_SESSION_TIME")
    return value


def _parse_time(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(_text(value))
    except ValueError:
        raise EvidenceError("AWS3_SESSION_TIME") from None
    return _utc(parsed)


def _shape(value: object, names: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != names:
        raise EvidenceError("AWS3_SESSION_METADATA")
    return cast(dict[str, object], value)


def _enum[EnumT: Enum](kind: type[EnumT], value: object) -> EnumT:
    try:
        return kind(_text(value))
    except ValueError:
        raise EvidenceError("AWS3_SESSION_METADATA") from None


def _provenance(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 256
        or value != value.strip()
        or value.casefold() in {"unknown", "unverified", "false", "none", "null"}
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise EvidenceError("AWS3_SESSION_PROVENANCE")


def _account(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9]{12}", value) is None:
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    return value


def _role_id(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"AROA[A-Z0-9]{17}", value) is None:
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    return value


def _role(value: object) -> tuple[str, str]:
    if type(value) is not str:
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    match = re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@/-]+)", value)
    if match is None:
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    account, path = match.groups()
    if (
        len(path) > 512
        or any(part in ("", ".", "..") for part in path.split("/"))
        or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", path.rsplit("/", 1)[-1]) is None
    ):
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    return account, path


def _assumed_role(value: object) -> tuple[str, str, str]:
    if type(value) is not str:
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    match = re.fullmatch(
        r"arn:aws:sts::([0-9]{12}):assumed-role/([A-Za-z0-9_+=,.@-]{1,64})/"
        r"([A-Za-z0-9_+=,.@-]{2,64})",
        value,
    )
    if match is None or any(word in match.group(2).casefold() for word in ("admin", "root")):
        raise EvidenceError("AWS3_SESSION_IDENTITY")
    return match.group(1), match.group(2), match.group(3)


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """A known role explicitly prohibited from reuse for this purpose."""

    role_arn: str = field(repr=False)
    role_id: str = field(repr=False)
    purpose: Purpose

    def __post_init__(self) -> None:
        _role(self.role_arn)
        _role_id(self.role_id)
        if type(self.purpose) is not Purpose:
            raise EvidenceError("AWS3_SESSION_PEERS")

    def to_metadata(self) -> dict[str, object]:
        return {"role_arn": self.role_arn, "role_id": self.role_id, "purpose": self.purpose.value}

    @classmethod
    def from_metadata(cls, value: object) -> PeerIdentity:
        data = _shape(value, {"role_arn", "role_id", "purpose"})
        return cls(_text(data["role_arn"]), _text(data["role_id"]), _enum(Purpose, data["purpose"]))


@dataclass(frozen=True, slots=True)
class ExpectedIdentity:
    """Identity expectations, independent of any trail or archive resources."""

    account: str = field(repr=False)
    region: str
    role_arn: str = field(repr=False)
    role_id: str = field(repr=False)
    assumed_role_arn: str = field(repr=False)
    purpose: Purpose
    prohibited_peers: tuple[PeerIdentity, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _account(self.account)
        _role_id(self.role_id)
        role_account, path = _role(self.role_arn)
        account, name, _ = _assumed_role(self.assumed_role_arn)
        if (
            self.region != "us-east-1"
            or type(self.region) is not str
            or type(self.purpose) is not Purpose
            or role_account != self.account
            or account != self.account
            or path.rsplit("/", 1)[-1] != name
            or any(word in path.casefold() for word in ("admin", "root"))
            or type(self.prohibited_peers) is not tuple
            or len(self.prohibited_peers) > 16
        ):
            raise EvidenceError("AWS3_SESSION_IDENTITY")
        if self.purpose in (Purpose.COLLECTOR, Purpose.VERIFIER) and not self.prohibited_peers:
            raise EvidenceError("AWS3_SESSION_PEERS")
        arns: set[str] = set()
        ids: set[str] = set()
        purposes: set[Purpose] = set()
        for peer in self.prohibited_peers:
            if type(peer) is not PeerIdentity:
                raise EvidenceError("AWS3_SESSION_PEERS")
            if (
                peer.role_arn == self.role_arn
                or peer.role_id == self.role_id
                or peer.purpose is self.purpose
                or _role(peer.role_arn)[0] != self.account
                or peer.role_arn in arns
                or peer.role_id in ids
                or peer.purpose in purposes
            ):
                raise EvidenceError("AWS3_SESSION_PEERS")
            arns.add(peer.role_arn)
            ids.add(peer.role_id)
            purposes.add(peer.purpose)
        if self.purpose is not Purpose.POSTURE and purposes != set(Purpose) - {self.purpose}:
            raise EvidenceError("AWS3_SESSION_PEERS")

    def to_metadata(self) -> dict[str, object]:
        return {
            "account": self.account,
            "region": self.region,
            "role_arn": self.role_arn,
            "role_id": self.role_id,
            "assumed_role_arn": self.assumed_role_arn,
            "purpose": self.purpose.value,
            "prohibited_peers": [peer.to_metadata() for peer in self.prohibited_peers],
        }

    @classmethod
    def from_metadata(cls, value: object) -> ExpectedIdentity:
        data = _shape(
            value,
            {
                "account",
                "region",
                "role_arn",
                "role_id",
                "assumed_role_arn",
                "purpose",
                "prohibited_peers",
            },
        )
        peers = data["prohibited_peers"]
        if type(peers) is not list or len(peers) > 16:
            raise EvidenceError("AWS3_SESSION_PEERS")
        return cls(
            account=_text(data["account"]),
            region=_text(data["region"]),
            role_arn=_text(data["role_arn"]),
            role_id=_text(data["role_id"]),
            assumed_role_arn=_text(data["assumed_role_arn"]),
            purpose=_enum(Purpose, data["purpose"]),
            prohibited_peers=tuple(PeerIdentity.from_metadata(peer) for peer in peers),
        )


@dataclass(frozen=True, slots=True)
class MfaObservation:
    observed: bool
    provenance: str = field(repr=False)
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.observed is not True:
            raise EvidenceError("AWS3_SESSION_MFA")
        _provenance(self.provenance)
        _utc(self.observed_at)

    def to_metadata(self) -> dict[str, object]:
        return {
            "observed": self.observed,
            "provenance": self.provenance,
            "observed_at": self.observed_at.isoformat(),
        }

    @classmethod
    def from_metadata(cls, value: object) -> MfaObservation:
        data = _shape(value, {"observed", "provenance", "observed_at"})
        if data["observed"] is not True:
            raise EvidenceError("AWS3_SESSION_MFA")
        return cls(True, _text(data["provenance"]), _parse_time(data["observed_at"]))


@dataclass(frozen=True, slots=True)
class SessionIssuance:
    issued_at: datetime
    expires_at: datetime
    source: CredentialSource
    provenance: str = field(repr=False)
    mfa_required: bool
    mfa: MfaObservation
    access_key_id: str = field(repr=False)

    def __post_init__(self) -> None:
        issued, expires = _utc(self.issued_at), _utc(self.expires_at)
        if not timedelta(0) < expires - issued <= timedelta(hours=1):
            raise EvidenceError("AWS3_SESSION_LEASE")
        if type(self.source) is not CredentialSource:
            raise EvidenceError("AWS3_SESSION_SOURCE")
        _provenance(self.provenance)
        if self.mfa_required is not True or type(self.mfa) is not MfaObservation:
            raise EvidenceError("AWS3_SESSION_MFA")
        if (
            type(self.access_key_id) is not str
            or re.fullmatch(r"ASIA[A-Z0-9]{16}", self.access_key_id) is None
        ):
            raise EvidenceError("AWS3_SESSION_CREDENTIALS")

    def to_metadata(self) -> dict[str, object]:
        return {
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "source": self.source.value,
            "provenance": self.provenance,
            "mfa_required": self.mfa_required,
            "mfa": self.mfa.to_metadata(),
            "access_key_id": self.access_key_id,
        }

    @classmethod
    def from_metadata(cls, value: object) -> SessionIssuance:
        data = _shape(
            value,
            {
                "issued_at",
                "expires_at",
                "source",
                "provenance",
                "mfa_required",
                "mfa",
                "access_key_id",
            },
        )
        if data["mfa_required"] is not True:
            raise EvidenceError("AWS3_SESSION_MFA")
        return cls(
            issued_at=_parse_time(data["issued_at"]),
            expires_at=_parse_time(data["expires_at"]),
            source=_enum(CredentialSource, data["source"]),
            provenance=_text(data["provenance"]),
            mfa_required=True,
            mfa=MfaObservation.from_metadata(data["mfa"]),
            access_key_id=_text(data["access_key_id"]),
        )


@dataclass(frozen=True, slots=True)
class StsObservation:
    """Supplied GetCallerIdentity facts plus local observation time only."""

    account: str = field(repr=False)
    arn: str = field(repr=False)
    user_id: str = field(repr=False)
    observed_at: datetime

    def __post_init__(self) -> None:
        _account(self.account)
        account, _, session = _assumed_role(self.arn)
        if type(self.user_id) is not str:
            raise EvidenceError("AWS3_SESSION_IDENTITY")
        parts = self.user_id.split(":")
        if len(parts) != 2 or parts[1] != session or account != self.account:
            raise EvidenceError("AWS3_SESSION_IDENTITY")
        _role_id(parts[0])
        _utc(self.observed_at)

    def to_metadata(self) -> dict[str, object]:
        return {
            "account": self.account,
            "arn": self.arn,
            "user_id": self.user_id,
            "observed_at": self.observed_at.isoformat(),
        }

    @classmethod
    def from_metadata(cls, value: object) -> StsObservation:
        data = _shape(value, {"account", "arn", "user_id", "observed_at"})
        return cls(
            _text(data["account"]),
            _text(data["arn"]),
            _text(data["user_id"]),
            _parse_time(data["observed_at"]),
        )


_CredentialSnapshot = tuple[str, str, str, str, str | None]


def _credential_snapshot(credentials: object, account: str) -> _CredentialSnapshot:
    # Exact static botocore type and shape prevent refresh/provider callbacks or
    # a replaced get_frozen_credentials method from becoming an implicit source.
    if type(credentials) is not Credentials or set(vars(credentials)) != {
        "access_key",
        "secret_key",
        "token",
        "method",
        "account_id",
    }:
        raise EvidenceError("AWS3_SESSION_CREDENTIALS")
    static = cast(Any, credentials)
    access, secret, token, method, credential_account = (
        static.access_key,
        static.secret_key,
        static.token,
        static.method,
        static.account_id,
    )
    if (
        type(access) is not str
        or re.fullmatch(r"ASIA[A-Z0-9]{16}", access) is None
        or type(method) is not str
        or method != "explicit"
        or type(secret) is not str
        or not 1 <= len(secret) <= 4096
        or type(token) is not str
        or not 1 <= len(token) <= 16384
        or any(ord(char) < 33 or ord(char) == 127 for char in secret + token)
        or (
            credential_account is not None
            and (type(credential_account) is not str or credential_account != account)
        )
    ):
        raise EvidenceError("AWS3_SESSION_CREDENTIALS")
    return access, secret, token, method, credential_account


@dataclass(frozen=True, slots=True, init=False)
class BoundSession:
    """An offline consistency binding, with credential snapshots kept private."""

    _expected: ExpectedIdentity = field(repr=False)
    _issuance: SessionIssuance = field(repr=False)
    _observed: StsObservation = field(repr=False)
    _credentials: Credentials = field(repr=False)
    _snapshot: _CredentialSnapshot = field(repr=False)
    _lease: SessionLease = field(repr=False)

    def __init__(self) -> None:
        raise EvidenceError("AWS3_SESSION_ASSEMBLY_REQUIRED")

    @property
    def credentials(self) -> Credentials:
        return self._credentials

    @property
    def lease(self) -> SessionLease:
        return self._lease

    def check(self, now: datetime) -> None:
        instant = _utc(now)
        issuance, observed, expected = self._issuance, self._observed, self._expected
        if not issuance.issued_at <= instant < issuance.expires_at:
            raise EvidenceError("AWS3_SESSION_LEASE")
        # These are recent offline observations, not independently verified STS
        # or MFA evidence. Future, pre-issuance and stale statements fail closed.
        for observed_at in (observed.observed_at, issuance.mfa.observed_at):
            if not (
                issuance.issued_at <= observed_at <= instant
                and instant - observed_at <= timedelta(seconds=60)
            ):
                raise EvidenceError("AWS3_SESSION_OBSERVATION_TIME")
        if (
            observed.account != expected.account
            or observed.arn != expected.assumed_role_arn
            or observed.user_id != self._lease.user_id
        ):
            raise EvidenceError("AWS3_SESSION_IDENTITY")
        if _credential_snapshot(self._credentials, expected.account) != self._snapshot:
            raise EvidenceError("AWS3_SESSION_CREDENTIALS_CHANGED")

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": "aws3-session-observation/1",
            "state": "offline_unverified_session_observation",
            "purpose": self._expected.purpose.value,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


def assemble_session(
    expected: ExpectedIdentity,
    issuance: SessionIssuance,
    observed: StsObservation,
    credentials: object,
    *,
    now: datetime,
) -> BoundSession:
    if (
        type(expected) is not ExpectedIdentity
        or type(issuance) is not SessionIssuance
        or type(observed) is not StsObservation
    ):
        raise EvidenceError("AWS3_SESSION_CONTRACT")
    snapshot = _credential_snapshot(credentials, expected.account)
    if snapshot[0] != issuance.access_key_id:
        raise EvidenceError("AWS3_SESSION_CREDENTIAL_BINDING")
    _, _, session = _assumed_role(expected.assumed_role_arn)
    lease = SessionLease(
        issued_at=issuance.issued_at,
        expires_at=issuance.expires_at,
        principal_arn=expected.assumed_role_arn,
        user_id=f"{expected.role_id}:{session}",
        access_key_id=issuance.access_key_id,
    )
    bound = object.__new__(BoundSession)
    for name, value in (
        ("_expected", expected),
        ("_issuance", issuance),
        ("_observed", observed),
        ("_credentials", credentials),
        ("_snapshot", snapshot),
        ("_lease", lease),
    ):
        object.__setattr__(bound, name, value)
    bound.check(now)
    return bound
