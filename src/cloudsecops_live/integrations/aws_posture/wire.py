"""Fixed HTTPS request shapes and byte bounds before HTTP framing or SDK parsing.

These trusted-code transport components do not enable the disabled public worker.
The independent parent watchdog still bounds blocked DNS/TLS/read/close operations.
"""

from __future__ import annotations

import http.client
import json
import re
from collections.abc import Mapping
from typing import Any, NoReturn, Protocol, cast
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree

from botocore.exceptions import (  # type: ignore[import-untyped]
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.signing import (
    FinalSigningBinding,
    FrozenHeaders,
    FrozenRequest,
)

MAX_LINE_BYTES = 8192
MAX_HEADER_LINES = 64
MAX_REQUEST_BODY = 65536
MAX_REQUEST_HEADERS = 65536
MAX_RESPONSE_BYTES = 1024 * 1024
_OPERATIONS = {
    "sts": frozenset({"GetCallerIdentity"}),
    "iam": frozenset({"GetRole", "ListRolePolicies", "GetRolePolicy", "ListAttachedRolePolicies"}),
}


class WireBudget(Protocol):
    @property
    def remaining_wire_bytes(self) -> int: ...
    def check(self) -> None: ...
    def invalidate(self) -> None: ...
    def authorize_wire_parameters(
        self, service: str, operation: str, params: dict[str, object]
    ) -> None: ...
    def before_send(self, service: str) -> None: ...
    def consume_request_bytes(self, count: int) -> None: ...
    def consume_response_bytes(self, count: int) -> None: ...


class BoundedReader:
    """Charge plaintext status/headers/chunk framing/body before exposing bytes."""

    def __init__(self, raw: Any, budget: WireBudget) -> None:
        self._raw, self._budget = raw, budget
        self._in_headers, self._headers = True, -1
        self._received, self._markup = 0, 0
        self._tail = b""

    def _limit(self, size: object, *, line: bool = False) -> int:
        self._budget.check()
        if type(size) is not int or size < -1:
            self._budget.invalidate()
            raise EvidenceError("AWS4A_WIRE_SHAPE")
        limit = min(self._budget.remaining_wire_bytes + 1, MAX_RESPONSE_BYTES - self._received + 1)
        if line:
            limit = min(limit, MAX_LINE_BYTES + 1)
        return limit if size == -1 else min(size, limit)

    def _take(self, value: object, *, line: bool = False) -> bytes:
        if type(value) is not bytes:
            self._budget.invalidate()
            raise EvidenceError("AWS4A_WIRE_SHAPE")
        self._budget.consume_response_bytes(len(value))
        self._received += len(value)
        self._markup += value.count(b"<")
        scan = (self._tail + value).lower()
        self._tail = scan[-9:]
        if (
            self._received > MAX_RESPONSE_BYTES
            or self._markup > 20_000
            or b"<!doctype" in scan
            or b"<!entity" in scan
            or b"\x00" in value
            or b"\xff" in value
            or b"\xfe" in value
        ):
            self._budget.invalidate()
            raise EvidenceError("AWS4A_RESPONSE_LIMIT")
        if line:
            if len(value) > MAX_LINE_BYTES:
                self._budget.invalidate()
                raise EvidenceError("AWS4A_FRAME_LIMIT")
            if value.startswith(b"HTTP/1."):
                self._in_headers = True
            if self._in_headers:
                if value in (b"\r\n", b"\n"):
                    self._in_headers = False
                else:
                    self._headers += 1
                if self._headers > MAX_HEADER_LINES:
                    self._budget.invalidate()
                    raise EvidenceError("AWS4A_FRAME_LIMIT")
        self._budget.check()
        return value

    def read(self, size: int = -1) -> bytes:
        return self._take(self._raw.read(self._limit(size)))

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def readline(self, size: int = -1) -> bytes:
        return self._take(self._raw.readline(self._limit(size, line=True)), line=True)

    def readinto(self, target: Any) -> int:
        view = memoryview(target)
        value = self.read(len(view))
        view[: len(value)] = value
        return len(value)

    @property
    def closed(self) -> bool:
        return bool(self._raw.closed)

    def close(self) -> None:
        self._raw.close()

    def flush(self) -> None:
        self._raw.flush()


def endpoint_for(service: str, account: str) -> str:
    if type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None:
        raise EvidenceError("AWS4A_ENDPOINT")
    endpoints = {
        "sts": "https://sts.us-east-1.amazonaws.com",
        "iam": "https://iam.amazonaws.com",
        "cloudtrail": "https://cloudtrail.us-east-1.amazonaws.com",
        "s3": "https://s3.us-east-1.amazonaws.com",
        "s3control": f"https://{account}.s3-control.us-east-1.amazonaws.com",
    }
    if type(service) is not str or service not in endpoints:
        raise EvidenceError("AWS4A_ENDPOINT")
    return endpoints[service]


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise EvidenceError("AWS4A_REQUEST_SHAPE")
    result, total = {}, 0
    for key, item in value.items():
        if type(key) is not str or type(item) not in (str, bytes):
            raise EvidenceError("AWS4A_REQUEST_SHAPE")
        try:
            text = item.decode("ascii") if type(item) is bytes else item
            encoded = text.encode("ascii")
        except UnicodeError:
            raise EvidenceError("AWS4A_REQUEST_SHAPE") from None
        name = key.casefold()
        total += len(key) + len(encoded) + 4
        if (
            name in result
            or re.fullmatch(r"[a-z0-9-]{1,64}", name) is None
            or any(ord(char) < 32 or ord(char) == 127 for char in text)
            or name in {"expect", "transfer-encoding", "connection"}
            or name.startswith("proxy-")
            or total > MAX_REQUEST_HEADERS
        ):
            raise EvidenceError("AWS4A_REQUEST_SHAPE")
        result[name] = text
    return result


def _body(value: object) -> bytes:
    if value is None:
        return b""
    if type(value) not in (bytes, str):
        raise EvidenceError("AWS4A_REQUEST_BODY")
    scalar = cast(bytes | str, value)
    if len(scalar) > MAX_REQUEST_BODY:
        raise EvidenceError("AWS4A_REQUEST_BODY")
    try:
        body = scalar.encode("utf-8") if isinstance(scalar, str) else scalar
    except UnicodeError:
        raise EvidenceError("AWS4A_REQUEST_BODY") from None
    if len(body) > MAX_REQUEST_BODY:
        raise EvidenceError("AWS4A_REQUEST_BODY")
    return body


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("AWS4A_REQUEST_BODY")
        result[key] = value
    return result


def _request_parameters(
    service: str, account: str, request: Any
) -> tuple[bytes, str, dict[str, object]]:
    """Reject redirects, URL credentials, buckets, streaming and proxy headers."""
    endpoint = endpoint_for(service, account)
    url, method = request.url, request.method
    if type(url) is not str or len(url) > 8192 or type(method) is not str:
        raise EvidenceError("AWS4A_ENDPOINT")
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != endpoint.removeprefix("https://"):
            raise ValueError()
        if parsed.fragment or parsed.username or parsed.password:
            raise ValueError()
        query = parse_qs(
            parsed.query, keep_blank_values=True, max_num_fields=8, strict_parsing=True
        )
    except ValueError:
        raise EvidenceError("AWS4A_ENDPOINT") from None
    headers, body = _headers(request.headers), _body(request.body)
    if headers.get("host", parsed.netloc) != parsed.netloc:
        raise EvidenceError("AWS4A_ENDPOINT")
    if "content-length" in headers and headers["content-length"] != str(len(body)):
        raise EvidenceError("AWS4A_REQUEST_BODY")
    params: dict[str, object]
    if service == "s3control":
        operation, params = "GetPublicAccessBlock", {"AccountId": headers.get("x-amz-account-id")}
        valid = (
            method == "GET"
            and parsed.path == "/v20180820/configuration/publicAccessBlock"
            and not query
            and not body
            and headers.get("x-amz-account-id") == account
        )
    elif service == "s3":
        operation, params = "ListBuckets", {"MaxBuckets": 64}
        if "continuation-token" in query and len(query["continuation-token"]) == 1:
            params["ContinuationToken"] = query["continuation-token"][0]
        valid = (
            method == "GET"
            and parsed.path == "/"
            and not body
            and set(query) <= {"max-buckets", "continuation-token"}
            and query.get("max-buckets") == ["64"]
            and all(len(values) == 1 and 1 <= len(values[0]) <= 1024 for values in query.values())
            and "x-amz-account-id" not in headers
        )
    elif service == "cloudtrail":
        try:
            decoded = json.loads(body, object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError, RecursionError):
            raise EvidenceError("AWS4A_REQUEST_BODY") from None
        operation, params = "ListTrails", decoded
        valid = (
            method == "POST"
            and parsed.path == "/"
            and not query
            and headers.get("x-amz-target")
            == "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.ListTrails"
            and type(decoded) is dict
            and set(decoded) <= {"NextToken"}
        )
    else:
        try:
            decoded_query = parse_qs(
                body.decode("ascii"),
                keep_blank_values=True,
                max_num_fields=16,
                strict_parsing=True,
            )
        except (UnicodeError, ValueError):
            raise EvidenceError("AWS4A_REQUEST_BODY") from None
        action = decoded_query.get("Action", [])
        operation = action[0] if len(action) == 1 else ""
        params = {
            key: values[0]
            for key, values in decoded_query.items()
            if key not in {"Action", "Version"} and len(values) == 1
        }
        if "MaxItems" in params and params["MaxItems"] == "64":
            params["MaxItems"] = 64
        fields = {
            "GetCallerIdentity": set(),
            "GetRole": {"RoleName"},
            "GetRolePolicy": {"RoleName", "PolicyName"},
            "ListRolePolicies": {"RoleName", "MaxItems"},
            "ListAttachedRolePolicies": {"RoleName", "MaxItems"},
        }
        required = fields.get(operation, set())
        valid = (
            method == "POST"
            and parsed.path == "/"
            and not query
            and operation in _OPERATIONS[service]
            and decoded_query.get("Version")
            == (["2011-06-15"] if service == "sts" else ["2010-05-08"])
            and all(len(values) == 1 for values in decoded_query.values())
            and set(params) in (required, required | {"Marker"})
            and ("Marker" not in params or operation.startswith("List"))
        )
    if not valid:
        raise EvidenceError("AWS4A_REQUEST_SHAPE")
    return body, operation, params


def validate_request(service: str, account: str, request: Any) -> bytes:
    """Validate the closed request shape; actual dispatch also binds reservation."""
    return _request_parameters(service, account, request)[0]


def _bad_response() -> NoReturn:
    raise EvidenceError("AWS4A_RESPONSE_SHAPE")


def _text(value: object, *, token: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > 65536
        or "\x00" in value
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
        or token
        and (not 1 <= len(value) <= 1024 or any(not 32 <= ord(char) < 127 for char in value))
    ):
        _bad_response()
    return value


def _xml_members(
    node: ElementTree.Element, prefix: str, allowed: set[str], required: set[str]
) -> dict[str, ElementTree.Element]:
    if node.attrib or node.text is not None and node.text.strip():
        _bad_response()
    result = {}
    for child in node:
        name = child.tag.removeprefix(prefix)
        if (
            child.tag != prefix + name
            or name not in allowed
            or name in result
            or child.tail is not None
            and child.tail.strip()
        ):
            _bad_response()
        result[name] = child
    if not required <= set(result):
        _bad_response()
    return result


def _xml_text(node: ElementTree.Element, *, token: bool = False) -> str:
    if node.attrib or list(node):
        _bad_response()
    return _text(node.text or "", token=token)


def _xml_list(node: ElementTree.Element, prefix: str, member: str) -> list[ElementTree.Element]:
    if (
        node.attrib
        or node.text is not None
        and node.text.strip()
        or len(node) > 64
        or any(
            child.tag != prefix + member or child.tail is not None and child.tail.strip()
            for child in node
        )
    ):
        _bad_response()
    return list(node)


def _xml_success(service: str, operation: str, value: bytes) -> None:
    if any(marker in value.lower() for marker in (b"<!doctype", b"<!entity", b"\x00")):
        _bad_response()
    try:
        root = ElementTree.fromstring(value.decode("utf-8"))
    except (ValueError, ElementTree.ParseError):
        _bad_response()
    namespaces = {
        "sts": "https://sts.amazonaws.com/doc/2011-06-15/",
        "iam": "https://iam.amazonaws.com/doc/2010-05-08/",
        "s3": "http://s3.amazonaws.com/doc/2006-03-01/",
        "s3control": "http://awss3control.amazonaws.com/doc/2018-08-20/",
    }
    expected_prefix = "{" + namespaces[service] + "}"
    prefix = expected_prefix if root.tag.startswith(expected_prefix) else ""
    if service == "s3control":
        names = {
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        }
        if root.tag != prefix + "PublicAccessBlockConfiguration":
            _bad_response()
        members = _xml_members(root, prefix, names, names)
        if any(_xml_text(child) != "true" for child in members.values()):
            _bad_response()
        return
    if service == "s3":
        if root.tag != prefix + "ListAllMyBucketsResult":
            _bad_response()
        members = _xml_members(root, prefix, {"Buckets", "Owner", "ContinuationToken"}, {"Buckets"})
        for bucket in _xml_list(members["Buckets"], prefix, "Bucket"):
            fields = _xml_members(
                bucket, prefix, {"Name", "CreationDate", "BucketRegion", "BucketArn"}, {"Name"}
            )
            for child in fields.values():
                _xml_text(child)
        if "Owner" in members:
            fields = _xml_members(members["Owner"], prefix, {"DisplayName", "ID"}, set())
            for child in fields.values():
                _xml_text(child)
        if "ContinuationToken" in members:
            _xml_text(members["ContinuationToken"], token=True)
        return
    if root.tag != prefix + operation + "Response":
        _bad_response()
    envelope = _xml_members(
        root, prefix, {operation + "Result", "ResponseMetadata"}, {operation + "Result"}
    )
    if "ResponseMetadata" in envelope:
        metadata = _xml_members(envelope["ResponseMetadata"], prefix, {"RequestId"}, {"RequestId"})
        _xml_text(metadata["RequestId"])
    result = envelope[operation + "Result"]
    if operation == "GetCallerIdentity":
        names = {"Account", "Arn", "UserId"}
        for child in _xml_members(result, prefix, names, names).values():
            _xml_text(child)
    elif operation == "GetRolePolicy":
        names = {"RoleName", "PolicyName", "PolicyDocument"}
        for child in _xml_members(result, prefix, names, names).values():
            _xml_text(child)
    elif operation == "GetRole":
        role = _xml_members(result, prefix, {"Role"}, {"Role"})["Role"]
        fields = _xml_members(
            role,
            prefix,
            {
                "Arn",
                "RoleId",
                "RoleName",
                "Path",
                "CreateDate",
                "AssumeRolePolicyDocument",
                "Description",
                "MaxSessionDuration",
                "Tags",
                "RoleLastUsed",
            },
            {"Arn", "RoleId", "RoleName"},
        )
        for name, child in fields.items():
            if name == "Tags":
                for tag in _xml_list(child, prefix, "member"):
                    for item in _xml_members(tag, prefix, {"Key", "Value"}, {"Key"}).values():
                        _xml_text(item)
            elif name == "RoleLastUsed":
                for item in _xml_members(child, prefix, {"LastUsedDate", "Region"}, set()).values():
                    _xml_text(item)
            else:
                _xml_text(child)
    else:
        field = "PolicyNames" if operation == "ListRolePolicies" else "AttachedPolicies"
        members = _xml_members(
            result, prefix, {field, "IsTruncated", "Marker"}, {field, "IsTruncated"}
        )
        truncated = _xml_text(members["IsTruncated"])
        if truncated not in {"true", "false"} or (truncated == "true") != ("Marker" in members):
            _bad_response()
        if "Marker" in members:
            _xml_text(members["Marker"], token=True)
        for member in _xml_list(members[field], prefix, "member"):
            if field == "PolicyNames":
                _xml_text(member)
            else:
                for child in _xml_members(
                    member, prefix, {"PolicyName", "PolicyArn"}, {"PolicyName", "PolicyArn"}
                ).values():
                    _xml_text(child)


def _json_constant(value: str) -> NoReturn:
    _bad_response()


def _json_success(value: bytes) -> None:
    if value.count(b"{") + value.count(b"[") > 20_000:
        _bad_response()
    try:
        document = json.loads(value, object_pairs_hook=_unique_pairs, parse_constant=_json_constant)
    except (ValueError, RecursionError):
        _bad_response()
    if (
        type(document) is not dict
        or not {"Trails"} <= set(document) <= {"Trails", "NextToken"}
        or type(document["Trails"]) is not list
        or len(document["Trails"]) > 64
    ):
        _bad_response()
    if "NextToken" in document:
        _text(document["NextToken"], token=True)
    for trail in document["Trails"]:
        if type(trail) is not dict or not {"TrailARN"} <= set(trail) <= {
            "TrailARN",
            "Name",
            "HomeRegion",
        }:
            _bad_response()
        for field in trail.values():
            _text(field)


def _validate_success(response: Any, service: str, operation: str, budget: WireBudget) -> None:
    # Validate before the SDK's lossy models erase duplicates or unknown fields.
    body = bytearray()
    for chunk in response.raw.stream(8192, decode_content=False):
        budget.check()
        if type(chunk) is not bytes or len(body) + len(chunk) > MAX_RESPONSE_BYTES:
            raise EvidenceError("AWS4A_RESPONSE_LIMIT")
        body.extend(chunk)
    value = bytes(body)
    if service == "cloudtrail":
        _json_success(value)
    else:
        _xml_success(service, operation, value)
    response._content = value
    budget.check()


class GuardedSession:
    def __init__(
        self,
        service: str,
        account: str,
        transport: Any,
        budget: WireBudget,
        signing: FinalSigningBinding,
    ) -> None:
        if type(signing) is not FinalSigningBinding:
            raise EvidenceError("AWS4A_SIGNING_BINDING")
        self._service, self._account = service, account
        self._transport, self._budget = transport, budget
        self._signing = signing

    def send(self, request: Any) -> Any:
        try:
            self._budget.check()
            # Read the mutable SDK request exactly once. Validate and dispatch only
            # this private immutable copy, never the retained SDK/event object.
            method, url, raw_body, raw_headers = (
                request.method,
                request.url,
                request.body,
                request.headers,
            )
            headers = _headers(raw_headers)
            if type(url) is not str or len(url) > 8192 or type(method) is not str:
                raise EvidenceError("AWS4A_ENDPOINT")
            headers.setdefault("host", urlsplit(url).netloc)
            final = FrozenRequest(
                method, url, None if raw_body is None else _body(raw_body), FrozenHeaders(headers)
            )
            body, operation, params = _request_parameters(self._service, self._account, final)
            self._budget.authorize_wire_parameters(self._service, operation, params)
            self._budget.before_send(self._service)
            self._budget.consume_request_bytes(len(body))
            self._signing.verify(final)
            response = self._transport.send(final)
            self._budget.check()
            if response.status_code == 200:
                _validate_success(response, self._service, operation, self._budget)
            return response
        except EvidenceError:
            self._budget.invalidate()
            raise
        except (
            ConnectionClosedError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        ):
            # A failed attempt stays charged. Only the engine may reserve a
            # bounded explicit retry; no transport/SDK retry occurs here.
            self._budget.check()
            raise
        except Exception:
            self._budget.invalidate()
            raise EvidenceError("AWS4A_TRANSPORT") from None

    def close(self) -> None:
        self._transport.close()


def install_response_bounds(session: Any, budget: WireBudget) -> None:
    """Install on one newly constructed, dedicated botocore HTTPS session."""
    from botocore.awsrequest import (  # type: ignore[import-untyped]
        AWSHTTPSConnection,
        AWSHTTPSConnectionPool,
    )

    class BoundedResponse(http.client.HTTPResponse):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.fp = cast(Any, BoundedReader(self.fp, budget))

    connection = type(
        "PostureHTTPSConnection", (AWSHTTPSConnection,), {"response_class": BoundedResponse}
    )
    pool = type("PostureHTTPSPool", (AWSHTTPSConnectionPool,), {"ConnectionCls": connection})
    session._pool_classes_by_scheme = {"https": pool}
    session._manager.pool_classes_by_scheme = session._pool_classes_by_scheme
