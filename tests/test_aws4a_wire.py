"""Independent pre-framing byte/line bounds and fixed posture endpoints."""

from http.client import IncompleteRead
from io import BytesIO
from types import SimpleNamespace

import pytest
from botocore.exceptions import ConnectTimeoutError

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.signing import FrozenHeaders, FrozenRequest
from cloudsecops_live.integrations.aws_posture.wire import (
    BoundedReader,
    endpoint_for,
    install_response_bounds,
    validate_request,
)

ACCOUNT = "1" * 12


class Budget:
    def __init__(self, remaining=1024 * 1024):
        self.remaining_wire_bytes = remaining
        self.response_bytes = self.request_bytes = self.sent = 0
        self.failed = False

    def check(self):
        if self.failed:
            raise EvidenceError("AWS4A_REJECTED")

    def invalidate(self):
        self.failed = True

    def consume_response_bytes(self, size):
        self.check()
        self.response_bytes += size
        self.remaining_wire_bytes -= size
        if self.remaining_wire_bytes < 0:
            self.invalidate()
            raise EvidenceError("AWS4A_BUDGET")

    def consume_request_bytes(self, size):
        self.check()
        self.request_bytes += size
        self.remaining_wire_bytes -= size
        if self.remaining_wire_bytes < 0:
            self.invalidate()
            raise EvidenceError("AWS4A_BUDGET")

    def before_send(self, service):
        self.check()
        self.sent += 1

    def authorize_wire_parameters(self, service, operation, params):
        self.check()
        assert (service, operation, params) == (
            "s3control",
            "GetPublicAccessBlock",
            {"AccountId": ACCOUNT},
        )


def request(service="s3control", **changes):
    value = dict(
        url=endpoint_for(service, ACCOUNT) + "/v20180820/configuration/publicAccessBlock",
        method="GET",
        headers={"x-amz-account-id": ACCOUNT},
        body=None,
    )
    value.update(changes)
    return SimpleNamespace(**value)


def test_preframing_reader_counts_status_headers_chunks_and_body():
    budget = Budget()
    raw = BytesIO(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
    reader = BoundedReader(raw, budget)
    assert reader.readline() == b"HTTP/1.1 200 OK\r\n"
    assert reader.readline() == b"X-Test: yes\r\n"
    assert reader.readline() == b"\r\n"
    assert reader.read1(3) == b"3\r\n"
    target = bytearray(3)
    assert reader.readinto(target) == 3 and target == b"abc"
    assert reader.read() == b"\r\n0\r\n\r\n"
    assert budget.response_bytes == len(raw.getvalue())
    assert reader.read(0) == b""
    reader.flush()
    reader.close()
    assert raw.closed and reader.closed


@pytest.mark.parametrize("content", [b"x" * 8193, b"0;" + b"x" * 8192 + b"\r\n"])
def test_oversized_header_or_chunk_line_rejects_before_unbounded_read(content):
    budget = Budget()
    raw = BytesIO(content)
    with pytest.raises(EvidenceError):
        BoundedReader(raw, budget).readline()
    assert budget.failed and raw.tell() <= 8193


def test_header_count_and_aggregate_remaining_bytes_reject():
    budget = Budget()
    raw = BytesIO(b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 65 + b"\r\n")
    reader = BoundedReader(raw, budget)
    with pytest.raises(EvidenceError):
        while reader.readline():
            pass
    assert budget.failed
    budget = Budget(8)
    raw = BytesIO(b"0123456789")
    with pytest.raises(EvidenceError):
        BoundedReader(raw, budget).read()
    assert budget.failed and raw.tell() == 9


def test_repeated_status_like_lines_cannot_reset_header_limit():
    budget = Budget()
    reader = BoundedReader(BytesIO(b"HTTP/1.1 200 OK\r\n" * 66), budget)
    with pytest.raises(EvidenceError):
        while reader.readline():
            pass
    assert budget.failed


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_wide_encoded_xml_cannot_hide_entity_declarations(encoding):
    payload = '<!DOCTYPE x [<!ENTITY a "expanded">]><x>&a;</x>'.encode(encoding)
    budget = Budget()
    reader = BoundedReader(BytesIO(payload), budget)
    with pytest.raises(EvidenceError):
        while reader.read(1):
            pass
    assert budget.failed


def test_split_ascii_entity_declaration_rejects_before_parser():
    budget = Budget()
    reader = BoundedReader(BytesIO(b"<!DOC" + b"TYPE x>"), budget)
    assert reader.read(5) == b"<!DOC"
    with pytest.raises(EvidenceError):
        reader.read()
    assert budget.failed


@pytest.mark.parametrize("size", [True, None, "8", -2])
def test_reader_rejects_unsupported_sizes(size):
    budget = Budget()
    with pytest.raises(EvidenceError):
        BoundedReader(BytesIO(b"body"), budget).read(size)
    assert budget.failed


@pytest.mark.parametrize(
    "service,host",
    [
        ("sts", "https://sts.us-east-1.amazonaws.com"),
        ("iam", "https://iam.amazonaws.com"),
        ("cloudtrail", "https://cloudtrail.us-east-1.amazonaws.com"),
        ("s3", "https://s3.us-east-1.amazonaws.com"),
        ("s3control", "https://" + ACCOUNT + ".s3-control.us-east-1.amazonaws.com"),
    ],
)
def test_endpoint_inventory_is_fixed(service, host):
    assert endpoint_for(service, ACCOUNT) == host


@pytest.mark.parametrize("service,account", [("ec2", ACCOUNT), ("s3", "wrong"), ([], ACCOUNT)])
def test_unknown_service_or_account_never_constructs_endpoint(service, account):
    with pytest.raises(EvidenceError):
        endpoint_for(service, account)


@pytest.mark.parametrize(
    "changes",
    [
        {
            "url": "http://"
            + ACCOUNT
            + ".s3-control.us-east-1.amazonaws.com/v20180820/configuration/publicAccessBlock"
        },
        {"url": "https://evil.example/v20180820/configuration/publicAccessBlock"},
        {
            "url": "https://s3-control.us-west-2.amazonaws.com/v20180820/configuration/publicAccessBlock"
        },
        {
            "url": endpoint_for("s3control", ACCOUNT)
            + ":444/v20180820/configuration/publicAccessBlock"
        },
        {"url": endpoint_for("s3control", ACCOUNT) + "/bucket"},
        {
            "url": endpoint_for("s3control", ACCOUNT)
            + "/v20180820/configuration/publicAccessBlock?x=1"
        },
        {"headers": {}},
        {"headers": {"x-amz-account-id": "2" * 12}},
        {"headers": {"x-amz-account-id": ACCOUNT, "Expect": "100-continue"}},
        {"headers": {"x-amz-account-id": ACCOUNT, "Transfer-Encoding": "chunked"}},
        {"headers": {"x-amz-account-id": ACCOUNT, "Proxy-Authorization": "forbidden"}},
        {"method": "PUT"},
        {"body": b"forbidden"},
    ],
)
def test_account_operation_rejects_host_bucket_proxy_body_substitutions(changes):
    with pytest.raises(EvidenceError):
        validate_request("s3control", ACCOUNT, request(**changes))


def signed_fixed_guard(monkeypatch):
    import socket

    import boto3
    import botocore.auth
    import botocore.session
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    from tests.aws4a_helpers import NOW
    from tests.test_aws4a_clients import setup_clients

    def forbidden(*args, **kwargs):
        pytest.fail("fixed signing fixture must not access network or providers")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(botocore.session, "get_session", forbidden)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)
    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda **kwargs: NOW)
    owner, bound, budget, clients = setup_clients()
    params = {"AccountId": owner.expected.account}
    budget.before_call("s3control", "GetPublicAccessBlock", params)
    budget.authorize_parameters("s3control", "GetPublicAccessBlock", params)
    prepared = AWSRequest(
        method="GET",
        url=endpoint_for("s3control", owner.expected.account)
        + "/v20180820/configuration/publicAccessBlock",
        headers={"x-amz-account-id": owner.expected.account},
    )
    # The real pinned S3 Control model signs this account API as service s3.
    SigV4Auth(bound.credentials, "s3", "us-east-1").add_auth(prepared)
    return budget, clients, clients.s3control._endpoint.http_session, prepared.prepare()


def test_session_reserves_actual_body_before_send_and_checks_after(monkeypatch):
    from tests.test_aws4a_clients import close_clients

    budget, clients, wrapped, prepared = signed_fixed_guard(monkeypatch)
    response = SimpleNamespace(status_code=403)
    sends = []
    before = budget.public_dict()["request_bytes"]
    wrapped._transport.send = lambda value: sends.append(True) or response
    try:
        assert wrapped.send(prepared) is response
        # This GET has no body; its logical AccountId reservation is retained,
        # with exactly zero additional body bytes and a single final dispatch.
        assert sends == [True] and budget.public_dict()["request_bytes"] == before
        assert budget.public_dict()["calls"] == 1
    finally:
        close_clients(clients)


def test_transport_failure_is_sticky_and_diagnostics_do_not_include_payload(monkeypatch):
    from tests.test_aws4a_clients import close_clients

    budget, clients, wrapped, prepared = signed_fixed_guard(monkeypatch)

    def fail(value):
        raise RuntimeError("fictional-secret-canary")

    wrapped._transport.send = fail
    try:
        with pytest.raises(EvidenceError) as error:
            wrapped.send(prepared)
        assert budget.public_dict()["state"] == "rejected"
        assert "fictional-secret-canary" not in str(error.value)
    finally:
        close_clients(clients)


def test_transient_transport_timeout_is_charged_for_explicit_engine_retry(monkeypatch):
    from tests.test_aws4a_clients import close_clients

    budget, clients, wrapped, prepared = signed_fixed_guard(monkeypatch)
    sends = []

    def fail(value):
        sends.append(True)
        raise ConnectTimeoutError(endpoint_url="fixed-controlled-endpoint")

    wrapped._transport.send = fail
    try:
        with pytest.raises(ConnectTimeoutError):
            wrapped.send(prepared)
        assert sends == [True] and budget.public_dict()["calls"] == 1
        assert budget.public_dict()["state"] == "offline_budget_observation"
    finally:
        close_clients(clients)


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {1: "x"},
        {"x": 1},
        {"x": "non-ascii-\N{SNOWMAN}"},
        {"x": b"\xff"},
        {"x": "a\r\nb"},
        {"x": "a", "X": "b"},
        {"x": "x" * 65537},
        {str(index): "x" for index in range(33)},
    ],
)
def test_request_header_types_duplicates_controls_and_size_fail_closed(headers):
    with pytest.raises(EvidenceError):
        validate_request("s3control", ACCOUNT, request(headers=headers))


@pytest.mark.parametrize("body", [1, b"x" * 65537, "\ud800", "\N{SNOWMAN}" * 22000])
def test_request_body_is_bounded_before_encode_and_rejects_nonbytes_or_invalid_unicode(body):
    with pytest.raises(EvidenceError):
        validate_request("s3control", ACCOUNT, request(body=body))


@pytest.mark.parametrize(
    "changes",
    [
        {"url": None},
        {"url": "x" * 8193},
        {"url": "https://[invalid"},
        {"url": endpoint_for("s3control", ACCOUNT) + "/#hidden"},
        {
            "url": "https://user:secret@"  # pragma: allowlist secret - rejected fictional URL
            + ACCOUNT
            + ".s3-control.us-east-1.amazonaws.com/"
        },
        {
            "url": endpoint_for("s3control", ACCOUNT)
            + "/?"
            + "&".join(f"x{index}=y" for index in range(9))
        },
        {"headers": {"host": "wrong.invalid", "x-amz-account-id": ACCOUNT}},
        {"headers": {"content-length": "1", "x-amz-account-id": ACCOUNT}},
    ],
)
def test_url_and_length_parser_failures_are_sanitized(changes):
    with pytest.raises(EvidenceError):
        validate_request("s3control", ACCOUNT, request(**changes))


@pytest.mark.parametrize(
    "body", [b"{broken", b'{"NextToken":"a","NextToken":"b"}', b"\xff", b"[" * 1000]
)
def test_cloudtrail_request_malformed_or_duplicate_json_never_sends(body):
    value = request(
        "cloudtrail",
        url=endpoint_for("cloudtrail", ACCOUNT) + "/",
        method="POST",
        headers={
            "x-amz-target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.ListTrails"
        },
        body=body,
    )
    with pytest.raises(EvidenceError):
        validate_request("cloudtrail", ACCOUNT, value)


@pytest.mark.parametrize(
    "body",
    [
        b"\xff",
        b"bad",
        b"Action=GetRole&Action=GetRole&Version=2010-05-08&RoleName=OfflineInspector",
        b"Action=GetRole&Version=2010-05-08&RoleName=OfflineInspector&Extra=forbidden",
    ],
)
def test_query_protocol_request_rejects_malformed_duplicate_and_unknown_parameters(body):
    with pytest.raises(EvidenceError):
        validate_request(
            "iam",
            ACCOUNT,
            request(
                "iam", url=endpoint_for("iam", ACCOUNT) + "/", method="POST", headers={}, body=body
            ),
        )


def test_actual_installed_response_wraps_before_status_headers_and_chunk_framing():
    budget = Budget()
    transport = SimpleNamespace(_manager=SimpleNamespace())
    install_response_bounds(transport, budget)
    response_type = transport._pool_classes_by_scheme["https"].ConnectionCls.response_class
    payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
    sock = SimpleNamespace(makefile=lambda *args: BytesIO(payload))
    response = response_type(sock)
    assert isinstance(response.fp, BoundedReader)
    response.begin()
    assert response.read() == b"abc"
    assert budget.response_bytes == len(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;" + b"x" * 8192,
    ],
)
def test_installed_response_rejects_unbounded_header_or_chunk_line(payload):
    budget = Budget()
    transport = SimpleNamespace(_manager=SimpleNamespace())
    install_response_bounds(transport, budget)
    response_type = transport._pool_classes_by_scheme["https"].ConnectionCls.response_class
    response = response_type(SimpleNamespace(makefile=lambda *args: BytesIO(payload)))
    try:
        with pytest.raises((EvidenceError, IncompleteRead)):
            response.begin()
            response.read()
    finally:
        response.close()
    assert budget.failed


def test_reader_rejects_nonbyte_transport_and_caps_full_response():
    budget = Budget(2 * 1024 * 1024)
    reader = BoundedReader(SimpleNamespace(read=lambda size: "not bytes"), budget)
    with pytest.raises(EvidenceError):
        reader.read()
    assert budget.failed
    budget = Budget(2 * 1024 * 1024)
    reader = BoundedReader(BytesIO(b"x" * (1024 * 1024 + 1)), budget)
    with pytest.raises(EvidenceError):
        reader.read()
    assert budget.failed and budget.response_bytes == 1024 * 1024 + 1


def test_numeric_loopback_tls_uses_installed_bounded_response(tmp_path, monkeypatch):
    import ipaddress
    import socket
    import ssl
    from datetime import UTC, datetime, timedelta
    from threading import Thread

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from cloudsecops_live.integrations.aws_posture.clients import _HTTPSAdapter

    # A disposable test-only CA/SAN and one numeric loopback socket. This
    # private adapter smoke bypasses the production fixed-endpoint wrapper.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline-loopback")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )
    cert_path, key_path = tmp_path / "offline-cert.pem", tmp_path / "offline-key.pem"
    cert_path.write_bytes(certificate)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    listener = socket.socket()
    listener.settimeout(3)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    errors = []
    plaintext = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"

    def serve():
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                with server_context.wrap_socket(connection, server_side=True) as tls:
                    assert tls.recv(4096).startswith(b"GET /")
                    tls.sendall(plaintext)
        except Exception as error:
            errors.append(type(error).__name__)

    original_lookup = socket.getaddrinfo

    def numeric_only(host, *args, **kwargs):
        assert host == "127.0.0.1", "no external address lookup is permitted"
        return original_lookup(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", numeric_only)
    thread = Thread(target=serve, daemon=True)
    thread.start()
    budget = Budget()
    adapter = _HTTPSAdapter(certificate, budget)
    try:
        response = adapter.send(
            FrozenRequest("GET", f"https://127.0.0.1:{port}/", None, FrozenHeaders({}))
        )
        assert response.content == b"hello"
        assert budget.response_bytes == len(plaintext)
    finally:
        adapter.close()
        listener.close()
        thread.join(4)
    assert not thread.is_alive() and errors == []


@pytest.mark.parametrize(
    "service,operation,payload",
    [
        ("sts", "GetCallerIdentity", b"<WrongResponse/>"),
        (
            "sts",
            "GetCallerIdentity",
            b"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>1</Account><Arn>role</Arn><UserId>user</UserId></GetCallerIdentityResult><GetCallerIdentityResult/></GetCallerIdentityResponse>",
        ),
        (
            "iam",
            "ListRolePolicies",
            b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames/><IsTruncated>garbage</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>",
        ),
        (
            "iam",
            "ListRolePolicies",
            b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames/><IsTruncated/></ListRolePoliciesResult></ListRolePoliciesResponse>",
        ),
        (
            "iam",
            "ListRolePolicies",
            b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames/><IsTruncated>true</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>",
        ),
        (
            "iam",
            "ListRolePolicies",
            b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames/><IsTruncated>false</IsTruncated><Marker>hidden</Marker></ListRolePoliciesResult></ListRolePoliciesResponse>",
        ),
        ("s3", "ListBuckets", b"<WrongResult><Buckets/></WrongResult>"),
        (
            "s3",
            "ListBuckets",
            b"<ListAllMyBucketsResult><Buckets/><ContinuationToken/></ListAllMyBucketsResult>",
        ),
        (
            "s3",
            "ListBuckets",
            b"<ListAllMyBucketsResult><Buckets><WrongBucket/></Buckets></ListAllMyBucketsResult>",
        ),
        (
            "s3",
            "ListBuckets",
            b"<ListAllMyBucketsResult><Buckets>hidden<Bucket><Name>name</Name></Bucket></Buckets></ListAllMyBucketsResult>",
        ),
        (
            "s3control",
            "GetPublicAccessBlock",
            b"<PublicAccessBlockConfiguration unexpected='value'/>",
        ),
        (
            "s3control",
            "GetPublicAccessBlock",
            b"<PublicAccessBlockConfiguration><BlockPublicAcls>false</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        ),
        ("s3control", "GetPublicAccessBlock", b"<WrongRoot/>"),
        ("s3control", "GetPublicAccessBlock", b"<PublicAccessBlockConfiguration>"),
        ("s3control", "GetPublicAccessBlock", b'<!DOCTYPE x [<!ENTITY a "expanded">]><x>&a;</x>'),
        (
            "s3control",
            "GetPublicAccessBlock",
            b"<PublicAccessBlockConfiguration>\x00</PublicAccessBlockConfiguration>",
        ),
    ],
)
def test_fixed_xml_shapes_reject_ambiguous_roots_wrappers_boolean_and_continuation(
    service, operation, payload
):
    from cloudsecops_live.integrations.aws_posture.wire import _xml_success

    with pytest.raises(EvidenceError):
        _xml_success(service, operation, payload)


def test_fixed_xml_shapes_accept_bounded_complete_nonempty_pages_and_metadata():
    from cloudsecops_live.integrations.aws_posture.wire import _xml_success

    _xml_success(
        "s3",
        "ListBuckets",
        b"<ListAllMyBucketsResult><Buckets><Bucket><Name>fixture-bucket</Name><CreationDate>2026-11-05T00:00:00Z</CreationDate><BucketRegion>us-east-1</BucketRegion><BucketArn>fixture</BucketArn></Bucket></Buckets><Owner><DisplayName>fixture</DisplayName><ID>fixture</ID></Owner><ContinuationToken>continue</ContinuationToken></ListAllMyBucketsResult>",
    )
    _xml_success(
        "iam",
        "ListRolePolicies",
        b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>first</member></PolicyNames><IsTruncated>true</IsTruncated><Marker>continue</Marker></ListRolePoliciesResult><ResponseMetadata><RequestId>fixture-request</RequestId></ResponseMetadata></ListRolePoliciesResponse>",
    )
    _xml_success(
        "iam",
        "ListAttachedRolePolicies",
        b"<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyName>fixture</PolicyName><PolicyArn>fixture</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>",
    )
    _xml_success(
        "iam",
        "GetRole",
        b"<GetRoleResponse><GetRoleResult><Role><Arn>fixture</Arn><RoleId>fixture</RoleId><RoleName>fixture</RoleName><Tags><member><Key>fixture</Key><Value>fixture</Value></member></Tags><RoleLastUsed><LastUsedDate>2026-11-05T00:00:00Z</LastUsedDate><Region>us-east-1</Region></RoleLastUsed></Role></GetRoleResult></GetRoleResponse>",
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"Trails":[{}]}',
        b'{"Trails":[{"TrailARN":"fixture","Unknown":"x"}]}',
        b'{"Trails":[{"TrailARN":1}]}',
        b'{"Trails":[{"TrailARN":"\\u0000"}]}',
        b'{"Trails":[],"NextToken":""}',
        b'{"Trails":[],"NextToken":"\\n"}',
        b"\xff",
        b"[" * 20001,
    ],
)
def test_fixed_json_shapes_reject_noninventory_or_invalid_scalar_data(payload):
    from cloudsecops_live.integrations.aws_posture.wire import _json_success

    with pytest.raises(EvidenceError):
        _json_success(payload)


def test_fixed_json_shapes_accept_nonempty_inventory_with_exact_continuation():
    from cloudsecops_live.integrations.aws_posture.wire import _json_success

    _json_success(
        b'{"Trails":[{"TrailARN":"fixture","Name":"fixture","HomeRegion":"us-east-1"}],"NextToken":"continue"}'
    )


@pytest.mark.parametrize("chunk", ["nonbyte", b"x" * (1024 * 1024 + 1)])
def test_preparse_body_buffer_rejects_unsupported_or_oversized_chunks(chunk):
    from cloudsecops_live.integrations.aws_posture.wire import _validate_success

    response = SimpleNamespace(raw=SimpleNamespace(stream=lambda *args, **kwargs: iter([chunk])))
    with pytest.raises(EvidenceError, match="AWS4A_RESPONSE_LIMIT"):
        _validate_success(response, "cloudtrail", "ListTrails", Budget())
