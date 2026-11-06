"""Private final-request verification using pinned SDK SigV4 primitives.

This checks local request/session consistency, never AWS source authenticity.
No signer callback, credential provider or network operation is invoked here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, NoReturn

from botocore.auth import S3SigV4Auth, SigV4Auth  # type: ignore[import-untyped]
from botocore.awsrequest import AWSRequest  # type: ignore[import-untyped]

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession

_SERVICES = {"sts": "sts", "iam": "iam", "cloudtrail": "cloudtrail", "s3": "s3", "s3control": "s3"}
_COMMON = {"host", "x-amz-date", "x-amz-security-token"}
_SIGNED = {
    "sts": _COMMON | {"content-type"},
    "iam": _COMMON | {"content-type"},
    "cloudtrail": _COMMON | {"content-type", "x-amz-target"},
    "s3": _COMMON | {"x-amz-content-sha256"},
    "s3control": _COMMON | {"x-amz-account-id"},
}
_AUTH = re.compile(
    r"AWS4-HMAC-SHA256 Credential=(ASIA[A-Z0-9]{16})/([0-9]{8})/"
    r"([a-z0-9-]+)/([a-z0-9-]+)/aws4_request, "
    r"SignedHeaders=([a-z0-9-]+(?:;[a-z0-9-]+)*), Signature=([0-9a-f]{64})"
)


@dataclass(frozen=True, slots=True, repr=False)
class FrozenHeaders(Mapping[str, str]):
    """Case-insensitive immutable headers; repr never reveals signing material."""

    _values: Mapping[str, str] = field(repr=False)

    def __init__(self, values: dict[str, str]) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __getitem__(self, name: str) -> str:
        return self._values[name.casefold()]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return "FrozenHeaders()"

    def copy(self) -> dict[str, str]:
        # The pinned urllib3 serializer copies headers before adding its empty
        # proxy-header set. Give it a fresh private copy, never the SDK mapping.
        return dict(self._values)


@dataclass(frozen=True, slots=True)
class FrozenRequest:
    method: str = field(repr=False)
    url: str = field(repr=False)
    body: bytes | None = field(repr=False)
    headers: FrozenHeaders = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Secrets:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str = field(repr=False)

    def __getstate__(self) -> NoReturn:
        raise EvidenceError("AWS4A_SIGNING_PRIVATE")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise EvidenceError("AWS4A_SIGNING_PRIVATE")


def _session_state(session: BoundSession) -> bytes:
    lease = session.lease
    return json.dumps(
        {
            "expected": session._expected.to_metadata(),
            "issuance": session._issuance.to_metadata(),
            "observed": session._observed.to_metadata(),
            "lease": {
                "issued": lease.issued_at.isoformat(),
                "expires": lease.expires_at.isoformat(),
                "principal": lease.principal_arn,
                "user": lease.user_id,
                "key": lease.access_key_id,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


class FinalSigningBinding:
    """One fixed client's original static session, checked after all SDK hooks."""

    __slots__ = (
        "_service",
        "_client",
        "_signer",
        "_session",
        "_budget",
        "_credential_object",
        "_secrets",
        "_session_metadata",
        "_decision_digest",
    )

    def __init__(self, service: str, client: Any, session: BoundSession, budget: PostureBudget):
        budget.check()
        if service not in _SERVICES or budget.session is not session:
            raise EvidenceError("AWS4A_SIGNING_BINDING")
        self._service, self._client, self._signer = service, client, client._request_signer
        self._session, self._budget = session, budget
        self._credential_object = session.credentials
        self._secrets = _Secrets(*session._snapshot[:3])
        self._session_metadata = _session_state(session)
        self._decision_digest = budget.decision.digest

    def __getstate__(self) -> NoReturn:
        raise EvidenceError("AWS4A_SIGNING_PRIVATE")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise EvidenceError("AWS4A_SIGNING_PRIVATE")

    def verify(self, request: FrozenRequest) -> None:
        try:
            self._budget.check()
            service, client = self._service, self._client
            if (
                client._request_signer is not self._signer
                or self._signer._credentials is not self._credential_object
                or self._session.credentials is not self._credential_object
                or self._budget.session is not self._session
                or _session_state(self._session) != self._session_metadata
                or self._budget.decision.digest != self._decision_digest
                or client.meta.service_model.signing_name != _SERVICES[service]
                or self._signer._signing_name != _SERVICES[service]
                or self._signer._region_name != "us-east-1"
                or client.meta.config.signature_version != ("s3v4" if service == "s3" else "v4")
            ):
                raise ValueError()
            headers, body = request.headers, request.body or b""
            required = _SIGNED[service]
            if (
                not required | {"authorization"} <= set(headers)
                or not set(headers) <= required | {"authorization", "content-length", "user-agent"}
                or len(headers.get("user-agent", "")) > 512
            ):
                raise ValueError()
            authorization = headers["authorization"]
            match = _AUTH.fullmatch(authorization) if len(authorization) <= 2048 else None
            if match is None:
                raise ValueError()
            key, day, region, signing_service, signed, signature = match.groups()
            timestamp = headers["x-amz-date"]
            if (
                not hmac.compare_digest(key, self._secrets.access_key)
                or key != self._session.lease.access_key_id
                or not hmac.compare_digest(headers["x-amz-security-token"], self._secrets.token)
                or region != "us-east-1"
                or signing_service != _SERVICES[service]
                or signed != ";".join(sorted(required))
                or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", timestamp) is None
                or timestamp[:8] != day
            ):
                raise ValueError()
            instant = datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
            self._budget.check_signing_time(instant)
            if service in {"sts", "iam", "cloudtrail"}:
                content_type = (
                    "application/x-amz-json-1.1"
                    if service == "cloudtrail"
                    else "application/x-www-form-urlencoded; charset=utf-8"
                )
                if headers["content-type"] != content_type:
                    raise ValueError()
            if (
                service == "s3"
                and headers["x-amz-content-sha256"] != hashlib.sha256(body).hexdigest()
            ):
                raise ValueError()
            # Only the exact signed subset enters canonicalization. Content-Length
            # is independently bounded by the wire validator and added by SDK
            # preparation after signing; User-Agent is deliberately unsigned.
            canonical = AWSRequest(
                method=request.method,
                url=request.url,
                data=body,
                headers={name: headers[name] for name in required},
            )
            canonical.context["timestamp"] = timestamp
            kind = S3SigV4Auth if service == "s3" else SigV4Auth
            auth = kind(self._secrets, _SERVICES[service], "us-east-1")
            expected = auth.signature(
                auth.string_to_sign(canonical, auth.canonical_request(canonical)), canonical
            )
            # Low-level SDK primitives do not overwrite dates or debug-log secret
            # headers/signatures. add_auth must never be used for verification.
            if not hmac.compare_digest(signature, expected):
                raise ValueError()
            self._budget.check()
        except Exception:
            self._budget.invalidate()
            raise EvidenceError("AWS4A_SIGNING_BINDING") from None
