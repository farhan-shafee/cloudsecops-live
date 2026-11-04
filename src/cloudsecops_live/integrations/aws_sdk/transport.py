"""Guarded, read-only SDK adapter without credential discovery or client creation.

The caller supplies all three preconfigured clients and an explicit short lease.
This does not authorize AWS access or authenticate CloudTrail evidence. Only the
fixed operations below are exposed; collection and its bounded retries stay in
the existing offline contract. Private SDK fields are pinned compatibility gates,
not a way to construct or refresh credentials.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from io import RawIOBase
from typing import Any, BinaryIO, Literal, NoReturn, Protocol, cast
from urllib.parse import unquote, urlsplit

from botocore.credentials import Credentials  # type: ignore[import-untyped]
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CallerIdentity,
    Marker,
    ObjectBody,
    ObjectVersion,
    RetryableReadError,
    VersionPage,
)
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope


class _Client(Protocol):
    meta: Any
    _request_signer: Any
    _endpoint: Any


class _StsClient(_Client, Protocol):
    def get_caller_identity(self) -> object: ...


class _S3Client(_Client, Protocol):
    def list_object_versions(self, **kwargs: Any) -> object: ...
    def head_object(self, **kwargs: Any) -> object: ...
    def get_object(self, **kwargs: Any) -> object: ...


class _TrailClient(_Client, Protocol):
    def get_trail(self, **kwargs: Any) -> object: ...
    def get_trail_status(self, **kwargs: Any) -> object: ...
    def get_event_selectors(self, **kwargs: Any) -> object: ...
    def get_insight_selectors(self, **kwargs: Any) -> object: ...


class _Stream(Protocol):
    def read(self, size: int = -1) -> object: ...
    def close(self) -> None: ...


class _WireStream(_Stream, Protocol):
    def read1(self, amt: int, *, decode_content: bool) -> object: ...


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise EvidenceError("AWS_SDK_TIME")
    return value.astimezone(UTC)


def _version(value: object) -> str:
    # Version IDs are opaque: preserve their exact bytes-as-text, never decode.
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or value == "null"
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise EvidenceError("AWS_OBJECT_VERSION")
    return value


def _key(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", value) is None
        or "//" in value
        or any(part in (".", "..") for part in value.split("/"))
    ):
        raise EvidenceError("AWS_SOURCE_LOCATION")
    return value


@dataclass(frozen=True, slots=True)
class SessionLease:
    issued_at: datetime
    expires_at: datetime
    principal_arn: str = field(repr=False)
    user_id: str = field(repr=False)
    access_key_id: str = field(repr=False)

    def __post_init__(self) -> None:
        issued, expires = _time(self.issued_at), _time(self.expires_at)
        if (
            not timedelta(0) < expires - issued <= timedelta(hours=1)
            or not isinstance(self.principal_arn, str)
            or not isinstance(self.user_id, str)
            or not isinstance(self.access_key_id, str)
            or re.fullmatch(r"ASIA[A-Z0-9]{16}", self.access_key_id) is None
        ):
            raise EvidenceError("AWS_SDK_LEASE")


@dataclass(frozen=True, slots=True)
class TransportLimits:
    max_object_bytes: int = 10 * 1024 * 1024
    max_page_keys: int = 64
    max_read_calls: int = 1024
    max_control_bytes: int = 1024 * 1024
    max_wire_read_calls: int = 1024

    def __post_init__(self) -> None:
        values = (
            self.max_object_bytes,
            self.max_page_keys,
            self.max_read_calls,
            self.max_control_bytes,
            self.max_wire_read_calls,
        )
        ceilings = (10 * 1024 * 1024, 64, 1024, 1024 * 1024, 1024)
        if any(
            type(v) is not int or not 1 <= v <= c for v, c in zip(values, ceilings, strict=True)
        ):
            raise EvidenceError("AWS_SDK_LIMITS")


@dataclass(frozen=True, slots=True)
class TrailInspection:
    trail: dict[str, object]
    status: dict[str, object]
    event_selectors: tuple[dict[str, object], ...]
    insight_selectors: tuple[dict[str, object], ...]
    insight_state: Literal["empty_selector_observation", "disabled_service_observation"] = (
        "empty_selector_observation"
    )
    source_kind: Literal["aws_shaped_unverified"] = field(
        default="aws_shaped_unverified", init=False
    )
    authenticated: Literal[False] = field(default=False, init=False)


_TRANSIENT_CODES = frozenset(
    {
        "RequestTimeout",
        "RequestTimeoutException",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "InternalError",
        "InternalFailure",
        "InternalServerError",
    }
)
_NETWORK_ERRORS = (
    ConnectTimeoutError,
    ReadTimeoutError,
    EndpointConnectionError,
    ConnectionClosedError,
)


def _response(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError("AWS_SDK_RESPONSE")
    metadata = value.get("ResponseMetadata")
    if type(metadata) is not dict or type(metadata.get("HTTPStatusCode")) is not int:
        raise EvidenceError("AWS_SDK_RESPONSE")
    if metadata["HTTPStatusCode"] != 200 or "Error" in value:
        raise EvidenceError("AWS_SDK_RESPONSE")
    return value


class _InsightsDisabled(EvidenceError):
    def __init__(self) -> None:
        super().__init__("AWS_INSIGHTS_DISABLED_OBSERVATION")


def _client_error(error: ClientError) -> NoReturn:
    response = error.response
    if type(response) is not dict:
        raise EvidenceError("AWS_SDK_RESPONSE") from None
    detail, metadata = response.get("Error"), response.get("ResponseMetadata")
    if (
        type(detail) is not dict
        or not isinstance(detail.get("Code"), str)
        or not 1 <= len(detail["Code"]) <= 128
        or type(metadata) is not dict
        or type(metadata.get("HTTPStatusCode")) is not int
        or not 400 <= metadata["HTTPStatusCode"] <= 599
    ):
        raise EvidenceError("AWS_SDK_RESPONSE") from None
    if detail["Code"] == "InsightNotEnabledException" and metadata["HTTPStatusCode"] == 400:
        raise _InsightsDisabled() from None
    if detail["Code"] in _TRANSIENT_CODES and metadata["HTTPStatusCode"] in (
        400,
        408,
        429,
        500,
        502,
        503,
        504,
    ):
        raise RetryableReadError() from None
    raise EvidenceError("AWS_SDK_SERVICE_DENIED") from None


def _close_response(value: object) -> None:
    if isinstance(value, dict) and "Body" in value:
        try:
            value["Body"].close()
        except Exception:
            pass


class _BoundedBody(RawIOBase):
    def __init__(
        self, raw: _Stream, expected: int, max_calls: int, check: Callable[[], None]
    ) -> None:
        super().__init__()
        self._raw, self._expected, self._max_calls, self._check = raw, expected, max_calls, check
        self._received = self._calls = 0
        self._eof = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._eof:
            return b""
        try:
            self._check()
            if self.closed or type(size) is not int or size < -1:
                raise EvidenceError("AWS_OBJECT_READ")
            if size == 0:
                return b""
            if size == -1:
                staged = bytearray()
                while True:
                    chunk = self.read(self._expected - self._received + 1)
                    staged.extend(chunk)
                    if not chunk:
                        return bytes(staged)
            self._calls += 1
            if self._calls > self._max_calls:
                raise EvidenceError("AWS_OBJECT_READ_LIMIT")
            requested = min(size, self._expected - self._received + 1)
            piece = self._raw.read(requested)
            self._check()
            if not isinstance(piece, bytes) or len(piece) > requested:
                raise EvidenceError("AWS_OBJECT_SIZE")
            self._received += len(piece)
            if self._received > self._expected:
                raise EvidenceError("AWS_OBJECT_SIZE")
            if not piece:
                if self._received != self._expected:
                    raise EvidenceError("AWS_OBJECT_SIZE")
                self._eof = True
                self.close()
            return piece
        except EvidenceError:
            self.close()
            raise
        except Exception:
            self.close()
            raise EvidenceError("AWS_OBJECT_READ") from None

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            except Exception:
                raise EvidenceError("AWS_OBJECT_READ") from None
            finally:
                super().close()


class _GuardedRaw(RawIOBase):
    """Bound raw HTTP bytes before botocore can join or parse a response.

    read1(decode_content=False) avoids urllib3's fill/decode loops. DNS, headers
    and chunk framing can block outside these lease checks. Configured I/O
    timeouts do not provide hard wall-clock cancellation; future live assembly
    requires a separate enforceable operation deadline.
    """

    def __init__(
        self,
        raw: _WireStream,
        cap: int,
        max_calls: int,
        length: int | None,
        check: Callable[[], None],
    ) -> None:
        super().__init__()
        self._raw, self._cap, self._max_calls, self._length = raw, cap, max_calls, length
        self._check, self._received, self._calls, self._eof = check, 0, 0, False

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._received

    def read1(self, size: int = 65536, decode_content: bool | None = None) -> bytes:
        if self._eof:
            return b""
        try:
            self._check()
            if self.closed or type(size) is not int or size < 0 or decode_content:
                raise EvidenceError("AWS_SDK_RESPONSE_READ")
            if size == 0:
                return b""
            self._calls += 1
            if self._calls > self._max_calls:
                raise EvidenceError("AWS_SDK_RESPONSE_READ_LIMIT")
            amount = min(size, 65536, self._cap - self._received + 1)
            piece = self._raw.read1(amount, decode_content=False)
            self._check()
            if not isinstance(piece, bytes) or len(piece) > amount:
                raise EvidenceError("AWS_SDK_RESPONSE_SIZE")
            self._received += len(piece)
            if self._received > self._cap or (
                self._length is not None and self._received > self._length
            ):
                raise EvidenceError("AWS_SDK_RESPONSE_SIZE")
            if not piece:
                if self._length is not None and self._received != self._length:
                    raise EvidenceError("AWS_SDK_RESPONSE_SIZE")
                self._eof = True
                self.close()
            return piece
        except EvidenceError:
            self.close()
            raise
        except Exception:
            self.close()
            raise EvidenceError("AWS_SDK_RESPONSE_READ") from None

    def read(self, size: int | None = -1) -> bytes:
        if size is not None and (type(size) is not int or size < -1):
            self.close()
            raise EvidenceError("AWS_SDK_RESPONSE_READ")
        staged = bytearray()
        while size in (None, -1) or len(staged) < size:
            amount = 65536 if size in (None, -1) else min(65536, size - len(staged))
            piece = self.read1(amount)
            staged.extend(piece)
            if not piece:
                break
        return bytes(staged)

    def stream(
        self, amt: int | None = 65536, decode_content: bool | None = None
    ) -> Iterator[bytes]:
        while True:
            piece = self.read1(65536 if amt is None else amt, decode_content=decode_content)
            if not piece:
                return
            yield piece

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            except Exception:
                raise EvidenceError("AWS_SDK_RESPONSE_READ") from None
            finally:
                super().close()


_DEFAULT_LIMITS = TransportLimits()


class AwsSdkTransport:
    def __init__(
        self,
        scope: AwsScope,
        lease: SessionLease,
        *,
        sts_client: _StsClient,
        s3_client: _S3Client,
        cloudtrail_client: _TrailClient,
        clock: Callable[[], datetime],
        limits: TransportLimits = _DEFAULT_LIMITS,
    ) -> None:
        if type(scope) is not AwsScope or type(lease) is not SessionLease:
            raise EvidenceError("AWS_SDK_SCOPE")
        if type(limits) is not TransportLimits or not callable(clock):
            raise EvidenceError("AWS_SDK_LIMITS")
        self._scope, self._lease, self._clock, self._limits = scope, lease, clock, limits
        self._sts, self._s3, self._trail = sts_client, s3_client, cloudtrail_client
        self._send_bindings: list[tuple[Any, Callable[..., object]]] = []
        self._guards_installed = False
        try:
            self._credentials = sts_client._request_signer._credentials
        except Exception:
            raise EvidenceError("AWS_SDK_CLIENT_CONFIG") from None
        self._check()
        sessions: set[int] = set()
        for service, client in self._clients():
            try:
                session = client._endpoint.http_session
                if id(session) not in sessions:
                    guarded_send = partial(self._send, session.send)
                    session.send = guarded_send
                    self._send_bindings.append((session, guarded_send))
                    sessions.add(id(session))
                client.meta.events.register(
                    f"before-send.{service}", partial(self._before_send, service)
                )
            except Exception:
                raise EvidenceError("AWS_SDK_CLIENT_CONFIG") from None
        self._guards_installed = True
        self._check()

    def _clients(self) -> tuple[tuple[str, _Client], ...]:
        return (("sts", self._sts), ("s3", self._s3), ("cloudtrail", self._trail))

    def _now(self) -> datetime:
        try:
            now = _time(self._clock())
        except Exception:
            raise EvidenceError("AWS_SDK_TIME") from None
        if not self._lease.issued_at <= now < self._lease.expires_at:
            raise EvidenceError("AWS_SDK_LEASE_EXPIRED")
        return now

    def _check(self) -> None:
        lease, scope = self._lease, self._scope
        self._now()
        parts = lease.user_id.split(":")
        if len(parts) != 2 or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", parts[-1]) is None:
            raise EvidenceError("AWS_IDENTITY_MISMATCH")
        expected = (
            f"arn:aws:sts::{scope.account}:assumed-role/"
            f"{scope.role_arn.rsplit('/', 1)[-1]}/{parts[-1]}"
        )
        if parts[0] != scope.role_id or lease.principal_arn != expected:
            raise EvidenceError("AWS_IDENTITY_MISMATCH")
        try:
            credentials = self._credentials
            if (
                type(credentials) is not Credentials
                or credentials.method != "explicit"
                or credentials.access_key != lease.access_key_id
                or not credentials.token
            ):
                raise EvidenceError("AWS_SDK_CREDENTIAL_BINDING")
            for service, client in self._clients():
                meta, config = client.meta, client.meta.config
                endpoint = f"https://{service}.{scope.region}.amazonaws.com"
                if (
                    meta.service_model.service_name != service
                    or meta.region_name != scope.region
                    or meta.endpoint_url != endpoint
                    or client._endpoint.http_session._verify is not True
                    or not callable(client._endpoint.http_session.send)
                    or self._guards_installed
                    and not any(
                        client._endpoint.http_session is session
                        for session, _ in self._send_bindings
                    )
                    or client._request_signer._credentials is not credentials
                    or config.proxies != {}
                    or config.signature_version
                    not in (("v4", "s3v4") if service == "s3" else ("v4",))
                    or config.retries != {"mode": "standard", "total_max_attempts": 1}
                    or any(
                        type(v) not in (int, float) or not 0 < v <= maximum
                        for v, maximum in ((config.connect_timeout, 10), (config.read_timeout, 30))
                    )
                ):
                    raise EvidenceError("AWS_SDK_CLIENT_CONFIG")
            if any(session.send is not guard for session, guard in self._send_bindings):
                raise EvidenceError("AWS_SDK_CLIENT_CONFIG")
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("AWS_SDK_CLIENT_CONFIG") from None

    def _before_send(self, service: str, request: Any, **kwargs: Any) -> None:
        self._check()
        try:
            url = urlsplit(request.url)
            host = f"{service}.{self._scope.region}.amazonaws.com"
            hosts = (host, f"{self._scope.bucket}.{host}") if service == "s3" else (host,)
            if url.scheme != "https" or url.netloc not in hosts or url.fragment:
                raise EvidenceError("AWS_SDK_ENDPOINT")
            if service == "s3":
                owner = request.headers.get("x-amz-expected-bucket-owner")
                if isinstance(owner, bytes):
                    owner = owner.decode("ascii")
                if owner != self._scope.account:
                    raise EvidenceError("AWS_SDK_OWNER_GUARD")
                path = unquote(url.path)
                base = f"/{self._scope.bucket}" if url.netloc == host else ""
                if (
                    re.fullmatch(r"[A-Za-z0-9_./-]*", path) is None
                    or any(part in (".", "..") for part in path.split("/"))
                    or "//" in path
                ):
                    raise EvidenceError("AWS_SOURCE_LOCATION")
                if path not in (base, base + "/") and not any(
                    path.startswith(base + "/" + prefix)
                    for prefix in (self._scope.log_prefix, self._scope.digest_prefix)
                ):
                    raise EvidenceError("AWS_SOURCE_LOCATION")
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("AWS_SDK_ENDPOINT") from None

    def _send(self, delegate: Callable[[Any], Any], request: Any) -> object:
        """Force streamed receipt so the raw guard precedes SDK eager buffering."""
        self._check()
        response: Any = None
        try:
            host = urlsplit(request.url).netloc
            services = [
                service
                for service, _ in self._clients()
                if host == f"{service}.{self._scope.region}.amazonaws.com"
                or service == "s3"
                and host == f"{self._scope.bucket}.s3.{self._scope.region}.amazonaws.com"
            ]
            if len(services) != 1 or type(request.stream_output) is not bool:
                raise EvidenceError("AWS_SDK_ENDPOINT")
            self._before_send(services[0], request)
            streamed = request.stream_output
            try:
                request.stream_output = True
                response = delegate(request)
            finally:
                request.stream_output = streamed
            self._check()
            if response._content is not None or type(response.status_code) is not int:
                raise EvidenceError("AWS_SDK_RESPONSE")
            cap = (
                self._limits.max_object_bytes + 1
                if streamed and response.status_code == 200
                else (self._limits.max_control_bytes)
            )
            length = response.headers.get("content-length", response.headers.get("Content-Length"))
            # A HEAD Content-Length describes the selected object, not a body.
            # Keep the original header for SDK metadata but expect zero wire bytes.
            if request.method == "HEAD":
                cap, length = 0, "0"
            if length is not None and (
                not isinstance(length, str)
                or re.fullmatch(r"[0-9]{1,20}", length) is None
                or int(length) > cap
            ):
                raise EvidenceError("AWS_SDK_RESPONSE_SIZE")
            if not callable(getattr(response.raw, "read1", None)) or not callable(
                getattr(response.raw, "close", None)
            ):
                raise EvidenceError("AWS_SDK_RESPONSE")
            response.raw = _GuardedRaw(
                response.raw,
                cap,
                self._limits.max_wire_read_calls,
                None if length is None else int(length),
                self._check,
            )
            return response
        except Exception as error:
            if response is not None:
                try:
                    response.raw.close()
                except Exception:
                    pass
            if isinstance(error, (EvidenceError, *_NETWORK_ERRORS)):
                raise
            raise EvidenceError("AWS_SDK_RESPONSE_READ") from None

    def _invoke(self, action: Callable[[], object]) -> dict[str, Any]:
        self._check()
        result: object = None
        try:
            result = action()
            self._check()
            return _response(result)
        except ClientError as error:
            _close_response(error.response)
            self._check()
            _client_error(error)
        except _NETWORK_ERRORS:
            self._check()
            raise RetryableReadError() from None
        except EvidenceError:
            _close_response(result)
            raise
        except Exception:
            _close_response(result)
            raise EvidenceError("AWS_SDK_FAILURE") from None

    def _read(self, action: Callable[[], object]) -> dict[str, Any]:
        self.caller_identity()
        return self._invoke(action)

    def caller_identity(self) -> CallerIdentity:
        response = self._invoke(self._sts.get_caller_identity)
        if (
            response.get("Account") != self._scope.account
            or response.get("Arn") != self._lease.principal_arn
            or response.get("UserId") != self._lease.user_id
        ):
            raise EvidenceError("AWS_IDENTITY_MISMATCH")
        return CallerIdentity(
            self._scope.account,
            self._scope.region,
            self._lease.principal_arn,
            self._lease.user_id,
            self._now(),
            self._lease.expires_at,
        )

    def _marker(self, value: object, prefix: str) -> Marker:
        if type(value) is not tuple or len(value) != 2:
            raise EvidenceError("AWS_PAGINATION")
        return (_key(value[0], prefix), _version(value[1]))

    def list_versions(self, expected: AwsScope, prefix: str, marker: Marker | None) -> VersionPage:
        if (
            type(expected) is not AwsScope
            or expected != self._scope
            or prefix not in (self._scope.log_prefix, self._scope.digest_prefix)
        ):
            raise EvidenceError("AWS_SDK_SCOPE")
        params: dict[str, object] = {
            "Bucket": self._scope.bucket,
            "Prefix": prefix,
            "ExpectedBucketOwner": self._scope.account,
            "MaxKeys": self._limits.max_page_keys,
        }
        if marker is not None:
            params["KeyMarker"], params["VersionIdMarker"] = self._marker(marker, prefix)
        response = self._read(partial(self._s3.list_object_versions, **params))
        if (
            response.get("Name") != self._scope.bucket
            or response.get("Prefix") != prefix
            or type(response.get("IsTruncated")) is not bool
            or response.get("CommonPrefixes", []) != []
        ):
            raise EvidenceError("AWS_LISTING_RESPONSE")
        refs: list[ObjectVersion] = []
        for field_name, deleted in (("Versions", False), ("DeleteMarkers", True)):
            entries = response.get(field_name, [])
            if type(entries) is not list or len(entries) + len(refs) > self._limits.max_page_keys:
                raise EvidenceError("AWS_LISTING_LIMIT")
            for entry in entries:
                if type(entry) is not dict or type(entry.get("IsLatest")) is not bool:
                    raise EvidenceError("AWS_SOURCE_METADATA")
                size = 0 if deleted else entry.get("Size")
                if (
                    type(size) is not int
                    or not (0 if deleted else 1) <= size <= self._limits.max_object_bytes
                ):
                    raise EvidenceError("AWS_OBJECT_SIZE")
                refs.append(
                    ObjectVersion(
                        self._scope.bucket,
                        _key(entry.get("Key"), prefix),
                        _version(entry.get("VersionId")),
                        size,
                        _time(entry.get("LastModified")),
                        deleted,
                        entry["IsLatest"],
                    )
                )
        next_marker = None
        if response["IsTruncated"]:
            next_marker = self._marker(
                (response.get("NextKeyMarker"), response.get("NextVersionIdMarker")), prefix
            )
            if (
                not refs
                or next_marker == marker
                or next_marker[0] < max(ref.key for ref in refs)
                or marker is not None
                and next_marker[0] < marker[0]
            ):
                raise EvidenceError("AWS_PAGINATION")
        elif "NextKeyMarker" in response or "NextVersionIdMarker" in response:
            raise EvidenceError("AWS_PAGINATION")
        return VersionPage(True, tuple(refs), response["IsTruncated"], next_marker)

    def _reference(self, ref: ObjectVersion) -> None:
        if (
            type(ref) is not ObjectVersion
            or ref.bucket != self._scope.bucket
            or not isinstance(ref.key, str)
        ):
            raise EvidenceError("AWS_SOURCE_LOCATION")
        prefix = (
            self._scope.log_prefix
            if ref.key.startswith(self._scope.log_prefix)
            else self._scope.digest_prefix
        )
        _key(ref.key, prefix)
        _version(ref.version_id)
        _time(ref.last_modified)
        if (
            type(ref.size) is not int
            or not 1 <= ref.size <= self._limits.max_object_bytes
            or ref.is_delete_marker is not False
            or type(ref.is_latest) is not bool
        ):
            raise EvidenceError("AWS_SOURCE_METADATA")

    def _object_metadata(self, response: dict[str, Any], ref: ObjectVersion) -> str:
        version = _version(response.get("VersionId"))
        size = response.get("ContentLength")
        modified = _time(response.get("LastModified"))
        if (
            type(size) is not int
            or not 1 <= size <= self._limits.max_object_bytes
            or response.get("DeleteMarker", False) is not False
            or "ContentRange" in response
            or version == ref.version_id
            and (size != ref.size or modified != ref.last_modified)
        ):
            raise EvidenceError("AWS_SOURCE_METADATA")
        return version

    def head_current(self, ref: ObjectVersion) -> str:
        self._reference(ref)
        response = self._read(
            partial(
                self._s3.head_object,
                Bucket=self._scope.bucket,
                Key=ref.key,
                ExpectedBucketOwner=self._scope.account,
            )
        )
        return self._object_metadata(response, ref)

    def get_object(self, ref: ObjectVersion, max_bytes: int) -> ObjectBody:
        self._reference(ref)
        if (
            type(max_bytes) is not int
            or not ref.size + 1 <= max_bytes <= self._limits.max_object_bytes + 1
        ):
            raise EvidenceError("AWS_OBJECT_SIZE")
        response = self._read(
            partial(
                self._s3.get_object,
                Bucket=self._scope.bucket,
                Key=ref.key,
                VersionId=ref.version_id,
                ExpectedBucketOwner=self._scope.account,
            )
        )
        try:
            if self._object_metadata(response, ref) != ref.version_id:
                raise EvidenceError("AWS_SOURCE_CHANGED")
            raw = response.get("Body")
            if not callable(getattr(raw, "read", None)) or not callable(
                getattr(raw, "close", None)
            ):
                raise EvidenceError("AWS_OBJECT_RESPONSE")
            body = _BoundedBody(
                cast(_Stream, raw), ref.size, self._limits.max_read_calls, self._check
            )
            return ObjectBody(ref, self._scope.account, cast(BinaryIO, body))
        except Exception:
            _close_response(response)
            raise

    def inspect_trail(self) -> TrailInspection:
        scope = self._scope
        trail = self._read(partial(self._trail.get_trail, Name=scope.trail_arn)).get("Trail")
        suffix = f"AWSLogs/{scope.account}/CloudTrail/{scope.region}/"
        root = scope.log_prefix.removesuffix(suffix).removesuffix("/")
        expected = {
            "TrailARN": scope.trail_arn,
            "HomeRegion": scope.region,
            "S3BucketName": scope.bucket,
            "IncludeGlobalServiceEvents": True,
            "LogFileValidationEnabled": True,
            "IsMultiRegionTrail": False,
            "IsOrganizationTrail": False,
        }
        if (
            type(trail) is not dict
            or trail.get("S3KeyPrefix", "") != root
            or any(
                trail.get(k) != v or isinstance(v, bool) and type(trail.get(k)) is not bool
                for k, v in expected.items()
            )
        ):
            raise EvidenceError("AWS_TRAIL_CONFIGURATION")
        status = self._read(partial(self._trail.get_trail_status, Name=scope.trail_arn))
        if status.get("IsLogging") is not True or any(
            status.get(k) for k in ("LatestDeliveryError", "LatestDigestDeliveryError")
        ):
            raise EvidenceError("AWS_TRAIL_CONFIGURATION")
        selectors = self._read(partial(self._trail.get_event_selectors, TrailName=scope.trail_arn))
        events = selectors.get("EventSelectors")
        if (
            selectors.get("TrailARN") != scope.trail_arn
            or type(events) is not list
            or len(events) != 1
            or selectors.get("AdvancedEventSelectors", []) != []
        ):
            raise EvidenceError("AWS_TRAIL_CONFIGURATION")
        event = events[0]
        if (
            type(event) is not dict
            or event.get("ReadWriteType") != "All"
            or event.get("IncludeManagementEvents") is not True
            or event.get("DataResources", []) != []
            or event.get("ExcludeManagementEventSources", []) != []
        ):
            raise EvidenceError("AWS_TRAIL_CONFIGURATION")
        self.caller_identity()
        try:
            insights = self._invoke(
                partial(self._trail.get_insight_selectors, TrailName=scope.trail_arn)
            )
        except _InsightsDisabled:
            self._check()
            return TrailInspection(trail, status, tuple(events), (), "disabled_service_observation")
        if insights.get("TrailARN") != scope.trail_arn or insights.get("InsightSelectors") != []:
            raise EvidenceError("AWS_TRAIL_CONFIGURATION")
        return TrailInspection(trail, status, tuple(events), ())
