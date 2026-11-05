"""Construct and serialize real SDK clients using only fictional private material."""

import json
import logging
import socket
import ssl
from io import BytesIO
from types import SimpleNamespace
from urllib.parse import parse_qs, quote

import pytest
from botocore.awsrequest import AWSResponse

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_posture.clients import (
    build_fixed_clients,
    packaged_ca_sha256,
)
from cloudsecops_live.integrations.aws_posture.engine import inspect_posture
from cloudsecops_live.integrations.aws_posture.wire import BoundedReader, endpoint_for
from tests.aws4a_helpers import NOW, decision, policy_document, session


@pytest.fixture(autouse=True)
def no_external_transport_or_providers(monkeypatch):
    import boto3
    import botocore.session

    def forbidden(*args, **kwargs):
        pytest.fail("no real network or ambient credential/session discovery is allowed")

    previous = logging.root.manager.disable
    levels = {
        name: (logger.level, logger.disabled)
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(botocore.session, "get_session", forbidden)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)
    monkeypatch.setattr(boto3, "Session", forbidden)
    yield
    logging.disable(previous)
    for name, (level, disabled) in levels.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.disabled = disabled


def setup_clients():
    owner = decision(ca_sha256=packaged_ca_sha256())
    bound = session(owner)
    budget = PostureBudget(owner, bound, clock=lambda: NOW, monotonic=lambda: 1.0)
    return owner, bound, budget, build_fixed_clients(owner, bound, budget)


def close_clients(clients):
    for name in ("sts", "iam", "cloudtrail", "s3", "s3control"):
        getattr(clients, name).close()


def test_real_sdk_construction_has_no_provider_chain_or_ambient_configuration(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://wrong.invalid")
    monkeypatch.setenv("AWS_CA_BUNDLE", "nonexistent-hostile-ca")
    monkeypatch.setenv("HTTPS_PROXY", "https://wrong.invalid")
    monkeypatch.setenv("AWS_DATA_PATH", "nonexistent-hostile-models")
    owner, bound, budget, clients = setup_clients()
    for name in ("sts", "iam", "cloudtrail", "s3", "s3control"):
        client = getattr(clients, name)
        expected = (
            "https://s3-control.us-east-1.amazonaws.com"
            if name == "s3control"
            else endpoint_for(name, owner.expected.account)
        )
        assert client.meta.endpoint_url == expected
        assert client.meta.config.region_name == "us-east-1"
        assert client.meta.config.proxies == {}
        assert client.meta.config.retries["total_max_attempts"] == 1
        assert client._request_signer._credentials is bound.credentials
        assert client._endpoint.http_session._transport._verify is True
        context = client._endpoint.http_session._transport._context
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert budget.public_dict()["calls"] == 0
    close_clients(clients)


def test_ca_substitution_fails_before_sdk_construction():
    owner = decision(ca_sha256="0" * 64)
    bound = session(owner)
    budget = PostureBudget(owner, bound, clock=lambda: NOW, monotonic=lambda: 0.0)
    with pytest.raises(EvidenceError):
        build_fixed_clients(owner, bound, budget)


class Raw:
    def __init__(self, data, budget):
        self.reader = BoundedReader(BytesIO(data), budget)

    def stream(self, amt=1024, decode_content=False):
        while value := self.reader.read(amt):
            yield value


def fake_reply(client, body, budget, seen, *, status=200):
    def send(request):
        seen.append((request.url, request.method))
        return AWSResponse(request.url, status, {}, Raw(body, budget))

    client._endpoint.http_session._transport.send = send


@pytest.mark.parametrize("service", ["sts", "iam", "cloudtrail", "s3", "s3control"])
def test_each_fixed_sdk_protocol_serializes_and_parses_offline(service):
    owner, bound, budget, clients = setup_clients()
    seen = []
    if service == "sts":
        operation, params = "GetCallerIdentity", {}
        body = (
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            "<GetCallerIdentityResult>"
            f"<Arn>{owner.expected.assumed_role_arn}</Arn>"
            f"<UserId>{owner.expected.role_id}:offline</UserId>"
            f"<Account>{owner.expected.account}</Account>"
            "</GetCallerIdentityResult></GetCallerIdentityResponse>"
        ).encode()
        call = clients.sts.get_caller_identity
    elif service == "iam":
        operation = "GetRolePolicy"
        params = {"RoleName": "OfflineInspector", "PolicyName": "OfflineInspectionPolicy"}
        encoded = quote(json.dumps(policy_document(), separators=(",", ":")))
        body = (
            '<GetRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            "<GetRolePolicyResult><RoleName>OfflineInspector</RoleName>"
            "<PolicyName>OfflineInspectionPolicy</PolicyName>"
            f"<PolicyDocument>{encoded}</PolicyDocument>"
            "</GetRolePolicyResult></GetRolePolicyResponse>"
        ).encode()
        call = clients.iam.get_role_policy
    elif service == "cloudtrail":
        operation, params, body = "ListTrails", {}, b'{"Trails":[]}'
        call = clients.cloudtrail.list_trails
    elif service == "s3":
        operation, params = "ListBuckets", {"MaxBuckets": 64}
        body = b'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>'
        call = clients.s3.list_buckets
    else:
        operation, params = "GetPublicAccessBlock", {"AccountId": owner.expected.account}
        body = (
            b'<PublicAccessBlockConfiguration xmlns="http://awss3control.amazonaws.com/doc/2018-08-20/">'
            b"<BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"
            b"<BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets>"
            b"</PublicAccessBlockConfiguration>"
        )
        call = clients.s3control.get_public_access_block
    client = getattr(clients, service)
    fake_reply(client, body, budget, seen)
    budget.before_call(service, operation, params)
    result = call(**params)
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert len(seen) == 1 and seen[0][0].startswith(endpoint_for(service, owner.expected.account))
    if service == "iam":
        assert result["PolicyDocument"] == policy_document()
    close_clients(clients)


def test_unsupported_operation_and_missing_dispatch_reservation_cannot_send():
    owner, bound, budget, clients = setup_clients()
    with pytest.raises(EvidenceError):
        clients.s3.get_object(Bucket="forbidden", Key="forbidden")
    close_clients(clients)
    owner, bound, budget, clients = setup_clients()
    with pytest.raises(EvidenceError):
        clients.sts.get_caller_identity()
    close_clients(clients)


def test_credential_object_substitution_rejects_before_signing():
    owner, bound, budget, clients = setup_clients()
    clients.sts._request_signer._credentials = SimpleNamespace(access_key="forbidden")
    budget.before_call("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError):
        clients.sts.get_caller_identity()
    close_clients(clients)


@pytest.mark.parametrize("document", ['{"x":1,"x":2}', '{"x":NaN}', "[]", '"text"'])
def test_raw_iam_policy_duplicate_or_unsupported_json_rejects(document):
    owner, bound, budget, clients = setup_clients()
    encoded = quote(document)
    body = (
        "<GetRolePolicyResponse><GetRolePolicyResult>"
        "<RoleName>OfflineInspector</RoleName><PolicyName>OfflineInspectionPolicy</PolicyName>"
        f"<PolicyDocument>{encoded}</PolicyDocument>"
        "</GetRolePolicyResult></GetRolePolicyResponse>"
    ).encode()
    params = {"RoleName": "OfflineInspector", "PolicyName": "OfflineInspectionPolicy"}
    fake_reply(clients.iam, body, budget, [])
    budget.before_call("iam", "GetRolePolicy", params)
    with pytest.raises(EvidenceError):
        clients.iam.get_role_policy(**params)
    close_clients(clients)


@pytest.mark.parametrize(
    "extra",
    [
        "<Unexpected>true</Unexpected>",
        "<BlockPublicAcls>true</BlockPublicAcls>",
        "<BlockPublicAcls>false</BlockPublicAcls>",
    ],
)
def test_raw_account_bpa_unknown_or_duplicate_fields_are_not_erased_by_sdk(extra):
    owner, bound, budget, clients = setup_clients()
    body = (
        "<PublicAccessBlockConfiguration>"
        "<BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"
        "<BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets>"
        + extra
        + "</PublicAccessBlockConfiguration>"
    ).encode()
    fake_reply(clients.s3control, body, budget, [])
    params = {"AccountId": owner.expected.account}
    budget.before_call("s3control", "GetPublicAccessBlock", params)
    with pytest.raises(EvidenceError):
        clients.s3control.get_public_access_block(**params)
    assert budget.public_dict()["state"] == "rejected"
    close_clients(clients)


def test_actual_serialized_iam_parameters_cannot_replace_reserved_role():
    owner, bound, budget, clients = setup_clients()
    seen = []
    fake_reply(clients.iam, b"<GetRoleResponse><GetRoleResult/></GetRoleResponse>", budget, seen)

    def substitute(request, **kwargs):
        request.body = b"Action=GetRole&Version=2010-05-08&RoleName=UnapprovedRole"
        request.headers["Content-Length"] = str(len(request.body))

    clients.iam.meta.events.register("before-send.iam.GetRole", substitute)
    budget.before_call("iam", "GetRole", {"RoleName": "OfflineInspector"})
    with pytest.raises(EvidenceError):
        clients.iam.get_role(RoleName="OfflineInspector")
    assert seen == []
    close_clients(clients)


def test_complete_engine_accepts_all_fixed_real_sdk_protocols_with_only_fake_sends():
    owner, bound, budget, clients = setup_clients()
    seen = []
    document = quote(json.dumps(policy_document(), separators=(",", ":")))
    replies = {
        "GetCallerIdentity": (
            f"<Account>{owner.expected.account}</Account>"
            f"<Arn>{bound.lease.principal_arn}</Arn><UserId>{bound.lease.user_id}</UserId>"
        ),
        "GetRole": (
            f"<Role><Arn>{owner.expected.role_arn}</Arn><RoleId>{owner.expected.role_id}</RoleId>"
            "<RoleName>OfflineInspector</RoleName>"
            f"<AssumeRolePolicyDocument>{document}</AssumeRolePolicyDocument></Role>"
        ),
        "ListRolePolicies": (
            "<PolicyNames><member>OfflineInspectionPolicy</member></PolicyNames>"
            "<IsTruncated>false</IsTruncated>"
        ),
        "GetRolePolicy": (
            "<RoleName>OfflineInspector</RoleName><PolicyName>OfflineInspectionPolicy</PolicyName>"
            f"<PolicyDocument>{document}</PolicyDocument>"
        ),
        "ListAttachedRolePolicies": "<AttachedPolicies/><IsTruncated>false</IsTruncated>",
    }

    def fake_send(request):
        if request.method == "POST" and "cloudtrail" not in request.url:
            payload = request.body.decode() if isinstance(request.body, bytes) else request.body
            operation = parse_qs(payload)["Action"][0]
            body = (
                f"<{operation}Response><{operation}Result>{replies[operation]}"
                f"</{operation}Result></{operation}Response>"
            ).encode()
        elif "cloudtrail" in request.url:
            operation, body = "ListTrails", b'{"Trails":[]}'
        elif ".s3-control." in request.url:
            operation = "GetPublicAccessBlock"
            body = (
                b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>"
                b"<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy>"
                b"<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
            )
        else:
            operation, body = (
                "ListBuckets",
                b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>",
            )
        seen.append(operation)
        return AWSResponse(request.url, 200, {}, Raw(body, budget))

    for name in ("sts", "iam", "cloudtrail", "s3", "s3control"):
        getattr(clients, name)._endpoint.http_session._transport.send = fake_send
    result = inspect_posture(
        owner, bound, clients, clock=lambda: NOW, monotonic=lambda: 1.0, budget=budget
    )
    assert len(seen) == 13 and len(set(seen)) == 8
    assert seen.count("GetCallerIdentity") == seen.count("GetRole") == 2
    assert result["trail_count"] == result["bucket_count"] == 0
    assert result["authenticated"] is False and result["execution_state"] == "disabled"
    assert result["budget"]["calls"] == 13
    assert owner.expected.account not in json.dumps(result)
    close_clients(clients)


@pytest.mark.parametrize(
    "service,operation,params,replacement",
    [
        (
            "iam",
            "GetRolePolicy",
            {"RoleName": "OfflineInspector", "PolicyName": "OfflineInspectionPolicy"},
            b"Action=GetRolePolicy&Version=2010-05-08&RoleName=OfflineInspector&PolicyName=OtherPolicy",
        ),
        (
            "iam",
            "ListRolePolicies",
            {"RoleName": "OfflineInspector", "MaxItems": 64},
            b"Action=ListRolePolicies&Version=2010-05-08&RoleName=OfflineInspector&MaxItems=63",
        ),
        (
            "iam",
            "ListAttachedRolePolicies",
            {"RoleName": "OfflineInspector", "MaxItems": 64, "Marker": "original"},
            b"Action=ListAttachedRolePolicies&Version=2010-05-08&RoleName=OfflineInspector&MaxItems=64&Marker=replaced",
        ),
        ("cloudtrail", "ListTrails", {"NextToken": "original"}, b'{"NextToken":"replaced"}'),
        (
            "s3",
            "ListBuckets",
            {"MaxBuckets": 64, "ContinuationToken": "original"},
            "?max-buckets=64&continuation-token=replaced",
        ),
    ],
)
def test_final_wire_parameters_are_bound_after_all_sdk_event_handlers(
    service, operation, params, replacement
):
    owner, bound, budget, clients = setup_clients()
    client = getattr(clients, service)
    sent = []
    fake_reply(client, b"{}", budget, sent)

    def substitute(request, **kwargs):
        if service == "s3":
            request.url = endpoint_for(service, owner.expected.account) + "/" + replacement
        else:
            request.body = replacement
            request.headers["Content-Length"] = str(len(replacement))

    client.meta.events.register("before-send", substitute)
    budget.before_call(service, operation, params)
    method = {
        "GetRolePolicy": "get_role_policy",
        "ListRolePolicies": "list_role_policies",
        "ListAttachedRolePolicies": "list_attached_role_policies",
        "ListTrails": "list_trails",
        "ListBuckets": "list_buckets",
    }[operation]
    with pytest.raises(EvidenceError):
        getattr(client, method)(**params)
    assert sent == [] and budget.public_dict()["state"] == "rejected"
    close_clients(clients)


@pytest.mark.parametrize("contents", [None, b"", b"x" * (1024 * 1024 + 1)])
def test_missing_empty_or_oversized_packaged_ca_rejects(monkeypatch, tmp_path, contents):
    import cloudsecops_live.integrations.aws_posture.clients as module

    monkeypatch.setattr(module.botocore, "__file__", str(tmp_path / "__init__.py"))
    if contents is not None:
        (tmp_path / "cacert.pem").write_bytes(contents)
    with pytest.raises(EvidenceError, match="AWS4A_CA_PROVENANCE"):
        packaged_ca_sha256()


def test_invalid_constructor_contract_and_partial_construction_failure_rejects(monkeypatch):
    import cloudsecops_live.integrations.aws_posture.clients as module

    owner = decision(ca_sha256=packaged_ca_sha256())
    bound = session(owner)
    budget = PostureBudget(owner, bound, clock=lambda: NOW, monotonic=lambda: 1.0)
    with pytest.raises(EvidenceError, match="AWS4A_CLIENT_BINDING"):
        build_fixed_clients(object(), bound, budget)
    original = module.ClientCreator.create_client
    built = []

    def fail_second(self, *args, **kwargs):
        if built:
            raise RuntimeError("fictional-private-canary")
        value = original(self, *args, **kwargs)
        built.append(value)
        return value

    monkeypatch.setattr(module.ClientCreator, "create_client", fail_second)
    with pytest.raises(EvidenceError, match="AWS4A_CLIENT_CONSTRUCTION") as error:
        build_fixed_clients(owner, bound, budget)
    assert "fictional-private-canary" not in str(error.value)
    assert budget.public_dict()["state"] == "rejected" and len(built) == 1


def test_tls_configuration_replacement_and_policy_decoder_wrong_shapes_reject():
    from cloudsecops_live.integrations.aws_posture.clients import _decode_policy, _policy

    owner, bound, budget, clients = setup_clients()
    clients.sts._endpoint.http_session._transport._verify = False
    budget.before_call("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError, match="AWS4A_TLS_BINDING"):
        clients.sts.get_caller_identity()
    close_clients(clients)
    for value in (None, 1, "x" * 65537):
        with pytest.raises(EvidenceError, match="AWS4A_POLICY_RESPONSE"):
            _policy(value)
    with pytest.raises(EvidenceError, match="AWS4A_POLICY_RESPONSE"):
        _decode_policy([])
    unchanged = {"Role": {"RoleName": "OfflineInspector"}}
    _decode_policy(unchanged)
    assert unchanged == {"Role": {"RoleName": "OfflineInspector"}}


def test_sdk_logging_cannot_disclose_fictional_signing_material_or_disable_application_logs(caplog):
    root_level, disabled = logging.getLogger().level, logging.root.manager.disable
    logging.getLogger("botocore.auth").setLevel(logging.DEBUG)
    logging.getLogger("botocore.auth").disabled = False
    with caplog.at_level(logging.DEBUG):
        owner, bound, budget, clients = setup_clients()
        body = (
            "<GetCallerIdentityResponse><GetCallerIdentityResult>"
            f"<Account>{owner.expected.account}</Account><Arn>{bound.lease.principal_arn}</Arn>"
            f"<UserId>{bound.lease.user_id}</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
        ).encode()
        fake_reply(clients.sts, body, budget, [])
        budget.before_call("sts", "GetCallerIdentity", {})
        clients.sts.get_caller_identity()
        logging.getLogger("cloudsecops_test").warning("application remains visible")
    assert (
        "fictional-offline-secret" not in caplog.text
        and "fictional-offline-token" not in caplog.text
    )
    assert "application remains visible" in caplog.text
    assert logging.getLogger().level == root_level and logging.root.manager.disable == disabled
    close_clients(clients)


@pytest.mark.parametrize("suffix", ["/", "/?controlled=value"])
def test_private_transport_disables_redirect_and_implicit_retry(suffix):
    owner, bound, budget, clients = setup_clients()
    adapter = clients.sts._endpoint.http_session._transport
    seen = []

    def urlopen(*args, **kwargs):
        seen.append((args, kwargs))
        return SimpleNamespace(status=200, headers={})

    adapter._manager.connection_from_url = lambda url: SimpleNamespace(urlopen=urlopen)
    value = adapter.send(
        SimpleNamespace(
            url=endpoint_for("sts", owner.expected.account) + suffix,
            method="GET",
            body=None,
            headers={},
        )
    )
    assert value.status_code == 200 and len(seen) == 1
    assert seen[0][1]["redirect"] is seen[0][1]["retries"] is False
    assert seen[0][1]["preload_content"] is seen[0][1]["decode_content"] is False
    close_clients(clients)


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("connect", "ConnectTimeoutError"),
        ("new", "EndpointConnectionError"),
        ("read", "ReadTimeoutError"),
        ("protocol", "ConnectionClosedError"),
    ],
)
def test_wire_network_errors_are_classified_without_raw_diagnostics(kind, expected):
    from urllib3.exceptions import (
        ConnectTimeoutError,
        NewConnectionError,
        ProtocolError,
        ReadTimeoutError,
    )

    owner, bound, budget, clients = setup_clients()
    adapter = clients.sts._endpoint.http_session._transport
    errors = {
        "connect": ConnectTimeoutError("private-canary"),
        "new": NewConnectionError(None, "private-canary"),
        "read": ReadTimeoutError(None, "private-canary-url", "private-canary"),
        "protocol": ProtocolError("private-canary"),
    }

    def fail(*args, **kwargs):
        raise errors[kind]

    adapter._manager.connection_from_url = lambda url: SimpleNamespace(urlopen=fail)
    with pytest.raises(Exception) as error:
        adapter.send(
            SimpleNamespace(
                url=endpoint_for("sts", owner.expected.account) + "/",
                method="GET",
                body=None,
                headers={},
            )
        )
    assert type(error.value).__name__ == expected
    assert "private-canary" not in str(error.value)
    close_clients(clients)


@pytest.mark.parametrize(
    "body",
    [
        b'{"Trails":[{"TrailARN":"present"}],"Trails":[]}',
        b'{"Trails":[],"NextToken":"must-continue","NextToken":null}',
        b'{"Trails":[],"Unknown":true}',
        b'{"Trails":[],"NextToken":null}',
        b'{"Trails":[],"NextToken":NaN}',
    ],
)
def test_raw_cloudtrail_ambiguity_cannot_be_erased_into_empty_inventory(body):
    owner, bound, budget, clients = setup_clients()
    fake_reply(clients.cloudtrail, body, budget, [])
    budget.before_call("cloudtrail", "ListTrails", {})
    with pytest.raises(EvidenceError):
        clients.cloudtrail.list_trails()
    assert budget.public_dict()["state"] == "rejected"
    close_clients(clients)


@pytest.mark.parametrize(
    "service,operation,params,body,method",
    [
        (
            "iam",
            "ListRolePolicies",
            {"RoleName": "OfflineInspector", "MaxItems": 64},
            b"<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>hidden</member></PolicyNames><PolicyNames/><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>",
            "list_role_policies",
        ),
        (
            "iam",
            "ListAttachedRolePolicies",
            {"RoleName": "OfflineInspector", "MaxItems": 64},
            b"<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies/><IsTruncated>true</IsTruncated><IsTruncated>false</IsTruncated><Marker>hidden</Marker></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>",
            "list_attached_role_policies",
        ),
        (
            "s3",
            "ListBuckets",
            {"MaxBuckets": 64},
            b"<ListAllMyBucketsResult><Buckets><Bucket><Name>present-bucket</Name></Bucket></Buckets><Buckets/></ListAllMyBucketsResult>",
            "list_buckets",
        ),
        (
            "s3",
            "ListBuckets",
            {"MaxBuckets": 64},
            b"<ListAllMyBucketsResult><Buckets/><Unexpected>true</Unexpected></ListAllMyBucketsResult>",
            "list_buckets",
        ),
    ],
)
def test_raw_xml_list_ambiguity_cannot_be_erased_by_sdk(service, operation, params, body, method):
    owner, bound, budget, clients = setup_clients()
    client = getattr(clients, service)
    fake_reply(client, body, budget, [])
    budget.before_call(service, operation, params)
    with pytest.raises(EvidenceError):
        getattr(client, method)(**params)
    assert budget.public_dict()["state"] == "rejected"
    close_clients(clients)
