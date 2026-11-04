"""Independent, network-denied contracts for the explicitly injected SDK adapter."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from botocore.config import Config
from botocore.credentials import Credentials, RefreshableCredentials
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError, SSLError

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    MemoryLedger,
    RetryableReadError,
    collect,
    require_authenticated,
)
from cloudsecops_live.integrations.aws_sdk.transport import (
    AwsSdkTransport,
    SessionLease,
    TransportLimits,
)
from tests.aws_helpers import BASE_TIME, scope
from tests.aws_sdk_helpers import KEY_ID, SECRET, TOKEN, Body, fixtures


@pytest.fixture(autouse=True)
def network_denied(monkeypatch):
    import socket

    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    def denied(*args, **kwargs):
        pytest.fail("SDK tests must never connect to a socket")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def make(*, clock=None, limits=None, mutate=None, lease_changes=None, scope_changes=None):
    expected, lease, clients, ref, data = fixtures(**(scope_changes or {}))
    if mutate:
        mutate(clients)
    lease.update(lease_changes or {})
    transport = AwsSdkTransport(
        expected,
        SessionLease(**lease),
        sts_client=clients["sts"],
        s3_client=clients["s3"],
        cloudtrail_client=clients["cloudtrail"],
        clock=clock or (lambda: BASE_TIME),
        limits=limits or TransportLimits(),
    )
    return transport, clients, ref, data


def test_receipt_free_sdk_collection_stays_unverified_and_owner_bound():
    transport, clients, ref, _ = make()
    result = collect(transport, scope(), MemoryLedger(), "sdk-test", clock=lambda: BASE_TIME)
    assert result.authenticated is False
    assert result.to_public_dict()["trusted_findings_available"] is False
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)
    assert result.unique_event_count == 1
    for operation, params in clients["s3"].calls:
        assert params["ExpectedBucketOwner"] == scope().account
        assert params["Bucket"] == scope().bucket
        if operation == "get_object":
            assert params["VersionId"] == ref.version_id
        if operation == "list_object_versions":
            assert params["Prefix"] == scope().log_prefix
            assert params["MaxKeys"] == 64


@pytest.mark.parametrize(
    "field,value",
    [
        ("Account", "2" * 12),
        ("Arn", "arn:aws:sts::" + "1" * 12 + ":assumed-role/Other/offline"),
        ("UserId", "AROA" + "Z" * 17 + ":offline"),
        ("UserId", "AROA" + "A" * 17 + ":other-session"),
        ("ResponseMetadata", {"HTTPStatusCode": 403}),
    ],
)
def test_sts_mismatch_has_no_s3_effect(field, value):
    transport, clients, _, _ = make()
    clients["sts"].responses["get_caller_identity"][field] = value
    with pytest.raises(EvidenceError):
        transport.caller_identity()
    assert clients["s3"].calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"expires_at": BASE_TIME},
        {"issued_at": BASE_TIME + timedelta(seconds=1)},
        {"expires_at": BASE_TIME.replace(tzinfo=None)},
        {"access_key_id": "AKIA" + "Q" * 16},
        {"principal_arn": "arn:aws:sts::" + "2" * 12 + ":assumed-role/Other/offline"},
        {"user_id": "AROA" + "A" * 17 + ":different-session"},
    ],
)
def test_invalid_or_expired_lease_fails_before_any_call(changes):
    with pytest.raises(EvidenceError):
        transport, clients, _, _ = make(lease_changes=changes)
        transport.caller_identity()


@pytest.mark.parametrize("service", ["sts", "s3", "cloudtrail"])
@pytest.mark.parametrize("failure", ["region", "tls", "endpoint", "retry", "timeout", "proxy"])
def test_all_clients_require_explicit_region_verified_tls_and_bounded_config(service, failure):
    def corrupt(clients):
        client = clients[service]
        if failure == "region":
            client.meta.region_name = "us-west-2"
        elif failure == "tls":
            client._endpoint.http_session._verify = False
        elif failure == "endpoint":
            client.meta.endpoint_url = "https://unapproved.invalid"
        elif failure == "retry":
            client.meta.config = client.meta.config.merge(
                Config(retries={"mode": "standard", "total_max_attempts": 3})
            )
        elif failure == "timeout":
            client.meta.config = client.meta.config.merge(Config(read_timeout=120))
        else:
            client.meta.config = client.meta.config.merge(Config(proxies={"https": "http://proxy"}))

    with pytest.raises(EvidenceError):
        make(mutate=corrupt)


@pytest.mark.parametrize(
    "kind", ["separate", "no-token", "empty-token", "wrong-key", "refreshable"]
)
def test_clients_cannot_smuggle_a_different_or_refreshing_credential_chain(kind):
    def corrupt(clients):
        if kind == "refreshable":
            credentials = RefreshableCredentials(
                KEY_ID,
                SECRET,
                TOKEN,
                BASE_TIME + timedelta(minutes=5),
                refresh_using=lambda: pytest.fail("credential refresh is forbidden"),
                method="assume-role",
            )
        else:
            credentials = Credentials(
                "ASIA" + "R" * 16 if kind == "wrong-key" else KEY_ID,
                SECRET,
                None if kind == "no-token" else ("" if kind == "empty-token" else TOKEN),
                method="explicit",
            )
        if kind == "separate":
            clients["s3"]._request_signer._credentials = credentials
        else:
            for client in clients.values():
                client._request_signer._credentials = credentials

    with pytest.raises(EvidenceError):
        make(mutate=corrupt)


@pytest.mark.parametrize("field", ["principal_arn", "user_id", "access_key_id"])
def test_lease_repr_and_errors_do_not_disclose_identity(field):
    _, lease, _, _, _ = fixtures()
    assert lease[field] not in repr(SessionLease(**lease))
    transport, clients, _, _ = make()
    clients["sts"].responses["get_caller_identity"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": SECRET + TOKEN + KEY_ID}}, "GetCallerIdentity"
    )
    with pytest.raises(EvidenceError) as error:
        transport.caller_identity()
    for private in (SECRET, TOKEN, KEY_ID, scope().account, scope().role_arn):
        assert private not in str(error.value)


@pytest.mark.parametrize(
    "prefix,marker",
    [
        ("foreign/", None),
        (scope().log_prefix, ("foreign/key.json.gz", "v-one")),
        (scope().log_prefix, (scope().log_prefix + "../a.json.gz", "v-one")),
        (scope().log_prefix, (scope().log_prefix + "a.json.gz", "null")),
        (scope().log_prefix, (scope().log_prefix + "a.json.gz", "bad\nversion")),
        (scope().log_prefix, (scope().log_prefix + "a.json.gz",)),
    ],
)
def test_out_of_scope_listing_and_marker_never_reach_s3(prefix, marker):
    transport, clients, _, _ = make()
    transport.caller_identity()
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), prefix, marker)
    assert clients["s3"].calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"IsTruncated": True},
        {"IsTruncated": False, "NextKeyMarker": "x", "NextVersionIdMarker": "v"},
        {"IsTruncated": "false"},
        {"Name": "foreign-bucket"},
        {"Prefix": "foreign/"},
        {"ResponseMetadata": {"HTTPStatusCode": 403}},
        {"Error": {"Code": "AccessDenied"}},
    ],
)
def test_malformed_or_error_listing_never_becomes_empty_success(change):
    transport, clients, _, _ = make()
    clients["s3"].responses["list_object_versions"].update(change)
    transport.caller_identity()
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)


def test_listing_preserves_delete_markers_and_paired_service_markers():
    transport, clients, ref, _ = make()
    response = clients["s3"].responses["list_object_versions"]
    response.update(
        IsTruncated=True,
        NextKeyMarker=ref.key,
        NextVersionIdMarker="v-next",
        DeleteMarkers=[
            {"Key": ref.key, "VersionId": "v-deleted", "IsLatest": False, "LastModified": BASE_TIME}
        ],
    )
    transport.caller_identity()
    page = transport.list_versions(scope(), scope().log_prefix, None)
    assert page.next_marker == (ref.key, "v-next")
    assert page.truncated is True
    assert len(page.versions) == 2
    assert any(item.is_delete_marker and item.version_id == "v-deleted" for item in page.versions)
    response["IsTruncated"] = False
    response.pop("NextKeyMarker")
    response.pop("NextVersionIdMarker")
    transport.list_versions(scope(), scope().log_prefix, page.next_marker)
    params = clients["s3"].calls[-1][1]
    assert params["KeyMarker"] == ref.key
    assert params["VersionIdMarker"] == "v-next"


@pytest.mark.parametrize(
    "field,value",
    [
        ("bucket", "other-bucket"),
        ("version_id", "null"),
        ("key", "foreign/a.json.gz"),
        ("is_delete_marker", True),
        ("size", 0),
    ],
)
@pytest.mark.parametrize("operation", ["head_current", "get_object"])
def test_bad_object_reference_is_rejected_before_source_call(field, value, operation):
    transport, clients, ref, _ = make()
    transport.caller_identity()
    with pytest.raises(EvidenceError):
        method = getattr(transport, operation)
        if operation == "get_object":
            method(replace(ref, **{field: value}), ref.size + 1)
        else:
            method(replace(ref, **{field: value}))
    assert clients["s3"].calls == []


@pytest.mark.parametrize(
    "changes",
    [
        {"VersionId": "other-version"},
        {"ContentLength": -1},
        {"ContentLength": True},
        {"ResponseMetadata": {"HTTPStatusCode": 206}},
        {"DeleteMarker": True},
        {"ContentRange": "bytes 0-1/300"},
    ],
)
def test_bad_get_metadata_closes_body(changes):
    transport, clients, ref, data = make()
    body = Body(data)
    response = clients["s3"].responses["get_object"]()
    response["Body"] = body
    response.update(changes)
    clients["s3"].responses["get_object"] = response
    transport.caller_identity()
    with pytest.raises(EvidenceError):
        result = transport.get_object(ref, ref.size + 1)
        result.stream.read()
    assert body.closed


@pytest.mark.parametrize("body_kind", ["short", "long", "interrupted", "wrong-type"])
def test_stream_corruption_never_returns_valid_bytes_and_is_closed(body_kind):
    transport, clients, ref, data = make()

    class BrokenBody(Body):
        def read(self, size=-1):
            if body_kind == "interrupted":
                raise OSError(SECRET)
            if body_kind == "wrong-type":
                return "not bytes"
            return super().read(size)

    body = BrokenBody(data[:-1] if body_kind == "short" else data + b"extra")
    response = clients["s3"].responses["get_object"]()
    response["Body"] = body
    clients["s3"].responses["get_object"] = response
    transport.caller_identity()
    with pytest.raises(EvidenceError):
        result = transport.get_object(ref, ref.size + 1)
        result.stream.read()
    assert body.closed


def test_session_expiry_during_stream_read_closes_underlying_body():
    current = [BASE_TIME]
    transport, clients, ref, data = make(clock=lambda: current[0])
    body = Body(data)
    response = clients["s3"].responses["get_object"]()
    response["Body"] = body
    clients["s3"].responses["get_object"] = response
    transport.caller_identity()
    result = transport.get_object(ref, ref.size + 1)
    current[0] += timedelta(minutes=6)
    with pytest.raises(EvidenceError):
        result.stream.read(1)
    assert body.closed


@pytest.mark.parametrize(
    "failure",
    [
        ConnectTimeoutError(endpoint_url="https://test.invalid"),
        ReadTimeoutError(endpoint_url="https://test.invalid"),
        ClientError(
            {"Error": {"Code": "SlowDown"}, "ResponseMetadata": {"HTTPStatusCode": 503}},
            "ListObjectVersions",
        ),
    ],
)
def test_only_classified_transients_are_retryable_without_nested_retries(failure):
    transport, clients, _, _ = make()
    transport.caller_identity()
    clients["s3"].responses["list_object_versions"] = failure
    with pytest.raises(RetryableReadError):
        transport.list_versions(scope(), scope().log_prefix, None)
    assert len(clients["s3"].calls) == 1


def test_tls_failure_is_sanitized_and_not_retryable():
    transport, clients, _, _ = make()
    transport.caller_identity()
    clients["s3"].responses["list_object_versions"] = SSLError(
        endpoint_url="https://test.invalid", error=SECRET
    )
    with pytest.raises(EvidenceError) as error:
        transport.list_versions(scope(), scope().log_prefix, None)
    assert SECRET not in str(error.value)


def test_before_send_guard_rejects_cross_region_and_missing_owner_header():
    transport, clients, _, _ = make()
    transport.caller_identity()
    callbacks = clients["s3"].meta.events.registered
    assert callbacks
    for request in [
        SimpleNamespace(
            url="https://s3.us-west-2.amazonaws.com/" + scope().bucket,
            headers={"x-amz-expected-bucket-owner": scope().account},
        ),
        SimpleNamespace(url="https://s3.us-east-1.amazonaws.com/" + scope().bucket, headers={}),
    ]:
        with pytest.raises(EvidenceError):
            for _, callback in callbacks:
                callback(request=request)


def test_trail_inspection_stays_unverified_and_uses_only_approved_trail():
    transport, clients, _, _ = make()
    result = transport.inspect_trail()
    assert result.authenticated is False
    assert result.source_kind == "aws_shaped_unverified"
    assert result.trail["TrailARN"] == scope().trail_arn
    for operation, params in clients["cloudtrail"].calls:
        assert params == {
            "Name"
            if operation in ("get_trail", "get_trail_status")
            else "TrailName": scope().trail_arn
        }


@pytest.mark.parametrize(
    "operation,changes",
    [
        ("get_trail", {"Trail": {}}),
        ("get_trail_status", {"IsLogging": False}),
        ("get_event_selectors", {"TrailARN": "foreign"}),
        ("get_event_selectors", {"EventSelectors": []}),
        ("get_event_selectors", {"AdvancedEventSelectors": [{"Name": "unapproved"}]}),
        ("get_insight_selectors", {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}),
    ],
)
def test_unready_or_wrong_trail_configuration_fails_closed(operation, changes):
    transport, clients, _, _ = make()
    clients["cloudtrail"].responses[operation].update(changes)
    with pytest.raises(EvidenceError):
        transport.inspect_trail()


def test_official_insights_disabled_exception_is_a_specific_service_observation():
    transport, clients, _, _ = make()
    clients["cloudtrail"].responses["get_insight_selectors"] = ClientError(
        {
            "Error": {"Code": "InsightNotEnabledException"},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        },
        "GetInsightSelectors",
    )
    result = transport.inspect_trail()
    assert result.insight_state == "disabled_service_observation"
    assert result.insight_selectors == ()
    assert result.authenticated is False


@pytest.mark.parametrize(
    "code,status",
    [("AccessDeniedException", 400), ("InsightNotEnabledException", 403), ("InternalFailure", 500)],
)
def test_other_insights_service_failures_are_not_disabled_or_empty_success(code, status):
    transport, clients, _, _ = make()
    clients["cloudtrail"].responses["get_insight_selectors"] = ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "GetInsightSelectors",
    )
    with pytest.raises((EvidenceError, RetryableReadError)):
        transport.inspect_trail()


def test_real_service_models_accept_exact_owner_and_version_bound_contract(tmp_path, monkeypatch):
    """No request leaves Stubber; generated static credentials are set on one local session."""
    import boto3
    from botocore.response import StreamingBody
    from botocore.stub import Stubber

    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "absent-credentials"))
    session = boto3.Session(
        aws_access_key_id=KEY_ID,
        aws_secret_access_key=SECRET,
        aws_session_token=TOKEN,
        region_name=scope().region,
    )
    config = Config(
        connect_timeout=2,
        read_timeout=5,
        retries={"mode": "standard", "total_max_attempts": 1},
        proxies={},
        signature_version="v4",
        s3={"addressing_style": "path"},
    )
    clients = {
        service: session.client(
            service,
            region_name=scope().region,
            endpoint_url=f"https://{service}.{scope().region}.amazonaws.com",
            verify=True,
            config=config,
        )
        for service in ("sts", "s3", "cloudtrail")
    }
    expected, lease, fake, ref, data = fixtures()
    identity = fake["sts"].responses["get_caller_identity"]
    with Stubber(clients["sts"]) as sts, Stubber(clients["s3"]) as s3:
        for _ in range(4):
            sts.add_response("get_caller_identity", identity, {})
        s3.add_response(
            "list_object_versions",
            fake["s3"].responses["list_object_versions"],
            {
                "Bucket": expected.bucket,
                "Prefix": expected.log_prefix,
                "ExpectedBucketOwner": expected.account,
                "MaxKeys": 64,
            },
        )
        s3.add_response(
            "head_object",
            fake["s3"].responses["head_object"],
            {"Bucket": expected.bucket, "Key": ref.key, "ExpectedBucketOwner": expected.account},
        )
        response = fake["s3"].responses["get_object"]()
        response["Body"] = StreamingBody(Body(data), len(data))
        s3.add_response(
            "get_object",
            response,
            {
                "Bucket": expected.bucket,
                "Key": ref.key,
                "VersionId": ref.version_id,
                "ExpectedBucketOwner": expected.account,
            },
        )
        transport = AwsSdkTransport(
            expected,
            SessionLease(**lease),
            sts_client=clients["sts"],
            s3_client=clients["s3"],
            cloudtrail_client=clients["cloudtrail"],
            clock=lambda: BASE_TIME,
        )
        assert transport.caller_identity().account == expected.account
        assert transport.list_versions(expected, expected.log_prefix, None).versions == (ref,)
        assert transport.head_current(ref) == ref.version_id
        body = transport.get_object(ref, ref.size + 1)
        try:
            assert body.stream.read() == data
        finally:
            body.stream.close()
        sts.assert_no_pending_responses()
        s3.assert_no_pending_responses()


def test_unstructured_client_is_rejected_with_sanitized_evidence_error():
    _, lease, clients, _, _ = fixtures()
    with pytest.raises(EvidenceError):
        AwsSdkTransport(
            scope(),
            SessionLease(**lease),
            sts_client=object(),
            s3_client=clients["s3"],
            cloudtrail_client=clients["cloudtrail"],
            clock=lambda: BASE_TIME,
        )


@pytest.mark.parametrize("operation", ["head_current", "get_object"])
def test_nonstring_object_key_is_sanitized_before_source_access(operation):
    transport, clients, ref, _ = make()
    with pytest.raises(EvidenceError):
        if operation == "head_current":
            transport.head_current(replace(ref, key=None))
        else:
            transport.get_object(replace(ref, key=None), ref.size + 1)
    assert clients["s3"].calls == []


def test_send_guard_rejects_encoded_path_traversal_and_foreign_bucket():
    transport, clients, _, _ = make()
    callbacks = clients["s3"].meta.events.registered
    for path in [
        "/other-bucket/" + scope().log_prefix + "a.json.gz",
        "/" + scope().bucket + "/" + scope().log_prefix + "%2e%2e/foreign.json.gz",
        "/" + scope().bucket + "/" + scope().log_prefix + "%252e%252e/foreign.json.gz",
    ]:
        with pytest.raises(EvidenceError):
            for _, callback in callbacks:
                callback(
                    request=SimpleNamespace(
                        url="https://s3.us-east-1.amazonaws.com" + path,
                        headers={"x-amz-expected-bucket-owner": scope().account.encode()},
                    )
                )


@pytest.mark.parametrize(
    "field",
    [
        "max_object_bytes",
        "max_page_keys",
        "max_read_calls",
        "max_control_bytes",
        "max_wire_read_calls",
    ],
)
@pytest.mark.parametrize("value", [0, True, -1, "64", 10 * 1024 * 1024 + 1])
def test_transport_bounds_are_positive_strict_integers_and_cannot_be_raised(field, value):
    with pytest.raises(EvidenceError):
        TransportLimits(**{field: value})


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"ResponseMetadata": {}},
        {"ResponseMetadata": {"HTTPStatusCode": True}},
        {"Error": {"Code": "AccessDenied"}, "ResponseMetadata": {"HTTPStatusCode": 200}},
    ],
)
def test_malformed_service_results_are_rejected_without_raw_exception(value):
    transport, clients, _, _ = make()
    clients["sts"].responses["get_caller_identity"] = value
    with pytest.raises(EvidenceError):
        transport.caller_identity()


def test_mutated_client_binding_is_rejected_again_before_source_action():
    transport, clients, _, _ = make()
    transport.caller_identity()
    clients["s3"].meta.region_name = "us-west-2"
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)
    assert clients["s3"].calls == []


def test_one_byte_stream_exhausts_independent_read_count_and_closes():
    transport, clients, ref, data = make(limits=TransportLimits(max_read_calls=2))

    class OneByteBody(Body):
        def read(self, size=-1):
            return super().read(min(size, 1))

    body = OneByteBody(data)
    response = clients["s3"].responses["get_object"]()
    response["Body"] = body
    clients["s3"].responses["get_object"] = response
    with pytest.raises(EvidenceError, match="READ_LIMIT"):
        transport.get_object(ref, ref.size + 1).stream.read()
    assert body.closed


def test_successful_stream_enforces_requested_piece_size_and_eof_closure():
    transport, _, ref, data = make()
    result = transport.get_object(ref, ref.size + 1)
    assert result.stream.read(0) == b""
    assert result.stream.read(1) == data[:1]
    assert result.stream.read() == data[1:]
    assert result.stream.read(1) == b""
    assert result.stream.closed


def test_stream_close_error_is_sanitized():
    transport, clients, ref, data = make()

    class FailingClose(Body):
        def close(self):
            super().close()
            raise OSError(SECRET)

    response = clients["s3"].responses["get_object"]()
    response["Body"] = FailingClose(data)
    clients["s3"].responses["get_object"] = response
    result = transport.get_object(ref, ref.size + 1)
    with pytest.raises(EvidenceError) as error:
        result.stream.close()
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("value", [0, True, -1, "100", 20 * 1024 * 1024])
def test_get_bound_is_checked_before_any_s3_call(value):
    transport, clients, ref, _ = make()
    with pytest.raises(EvidenceError):
        transport.get_object(ref, value)
    assert clients["s3"].calls == []


def test_sts_failure_cannot_impersonate_disabled_insights_observation():
    transport, clients, _, _ = make()
    identity = clients["sts"].responses["get_caller_identity"]
    count = [0]

    def sts_identity():
        count[0] += 1
        if count[0] == 4:
            raise ClientError(
                {
                    "Error": {"Code": "InsightNotEnabledException"},
                    "ResponseMetadata": {"HTTPStatusCode": 400},
                },
                "GetCallerIdentity",
            )
        return identity

    clients["sts"].responses["get_caller_identity"] = sts_identity
    with pytest.raises(EvidenceError):
        transport.inspect_trail()
    assert not any(
        operation == "get_insight_selectors" for operation, _ in clients["cloudtrail"].calls
    )


def test_s3_send_guard_accepts_only_approved_regional_paths_with_expected_owner():
    _, clients, ref, _ = make()
    callbacks = clients["s3"].meta.events.registered
    for url in [
        "https://s3.us-east-1.amazonaws.com/" + scope().bucket + "/" + ref.key,
        "https://" + scope().bucket + ".s3.us-east-1.amazonaws.com/" + ref.key,
        "https://s3.us-east-1.amazonaws.com/" + scope().bucket,
    ]:
        for _, callback in callbacks:
            callback(
                request=SimpleNamespace(
                    url=url, headers={"x-amz-expected-bucket-owner": scope().account.encode()}
                )
            )


def test_get_budget_covers_the_extra_eof_probe_before_any_source_access():
    transport, clients, ref, _ = make()
    with pytest.raises(EvidenceError):
        transport.get_object(ref, ref.size)
    assert clients["s3"].calls == []


def test_clock_failure_is_sanitized_before_identity_or_source_access():
    def failed_clock():
        raise OSError(SECRET)

    with pytest.raises(EvidenceError) as error:
        make(clock=failed_clock)
    assert SECRET not in str(error.value)


def test_expiry_at_identity_observation_cannot_return_a_valid_lease():
    calls = [0]

    def advancing_clock():
        calls[0] += 1
        return BASE_TIME if calls[0] <= 3 else BASE_TIME + timedelta(minutes=6)

    transport, _, _, _ = make(clock=advancing_clock)
    with pytest.raises(EvidenceError):
        transport.caller_identity()


@pytest.mark.parametrize("root", ["", "AWSLogs/team/"])
def test_legal_trail_prefix_roots_are_derived_from_the_exact_scope_suffix(root):
    expected = scope()
    changes = {
        "log_prefix": root + f"AWSLogs/{expected.account}/CloudTrail/{expected.region}/",
        "digest_prefix": root + f"AWSLogs/{expected.account}/CloudTrail-Digest/{expected.region}/",
    }
    transport, _, _, _ = make(scope_changes=changes)
    result = transport.inspect_trail()
    assert result.trail["S3KeyPrefix"] == root.removesuffix("/")


def test_trail_with_no_optional_prefix_field_matches_an_explicit_empty_root():
    expected = scope()
    changes = {
        "log_prefix": f"AWSLogs/{expected.account}/CloudTrail/{expected.region}/",
        "digest_prefix": f"AWSLogs/{expected.account}/CloudTrail-Digest/{expected.region}/",
    }
    transport, clients, _, _ = make(scope_changes=changes)
    clients["cloudtrail"].responses["get_trail"]["Trail"].pop("S3KeyPrefix")
    assert transport.inspect_trail().authenticated is False


def test_session_expiry_during_network_failure_is_fatal_before_retry_classification():
    current = [BASE_TIME]
    transport, clients, _, _ = make(clock=lambda: current[0])

    def expires_during_request():
        current[0] += timedelta(minutes=6)
        raise ConnectTimeoutError(endpoint_url="https://s3.us-east-1.amazonaws.com")

    clients["s3"].responses["list_object_versions"] = expires_during_request
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)


@pytest.mark.parametrize("service", ["sts", "cloudtrail"])
def test_non_s3_send_guards_enforce_the_same_explicit_regional_endpoint(service):
    _, clients, _, _ = make()
    callbacks = clients[service].meta.events.registered
    assert callbacks
    for _, callback in callbacks:
        callback(
            request=SimpleNamespace(
                url=f"https://{service}.{scope().region}.amazonaws.com/", headers={}
            )
        )
        with pytest.raises(EvidenceError):
            callback(
                request=SimpleNamespace(
                    url=f"https://{service}.us-west-2.amazonaws.com/", headers={}
                )
            )


@pytest.mark.parametrize("kind", ["non-list", "missing-latest", "negative-size", "page-overflow"])
def test_malformed_version_rows_and_configured_page_overflow_fail_closed(kind):
    transport, clients, _, _ = make()
    response = clients["s3"].responses["list_object_versions"]
    if kind == "non-list":
        response["Versions"] = tuple(response["Versions"])
    elif kind == "missing-latest":
        response["Versions"][0].pop("IsLatest")
    elif kind == "negative-size":
        response["Versions"][0]["Size"] = -1
    else:
        response["Versions"] *= 65
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)
    assert len(clients["s3"].calls) == 1


class ScriptedHttpRaw:
    """No socket: each read1 is exactly one independently observable wire operation."""

    def __init__(self, data=b"{}", *, piece=None, on_read=None, failure=None):
        self.data = data
        self.piece = piece
        self.on_read = on_read
        self.failure = failure
        self.read_sizes = []
        self.decode_flags = []
        self.stream_calls = 0
        self.closed = False

    def read1(self, amt=None, **kwargs):
        self.read_sizes.append(amt)
        self.decode_flags.append(kwargs.get("decode_content"))
        if self.on_read:
            self.on_read()
        if self.failure:
            raise self.failure
        if self.piece is not None:
            return self.piece
        count = len(self.data) if amt is None else amt
        value, self.data = self.data[:count], self.data[count:]
        return value

    def read(self, amt=None, **kwargs):
        raise AssertionError("raw.read can perform unbounded trickle-filling before returning")

    def stream(self, amt=65536, **kwargs):
        self.stream_calls += 1
        raise AssertionError("raw.stream must be guarded before AWSResponse.content joins chunks")

    def close(self):
        self.closed = True


def http_case(
    raw,
    *,
    service="sts",
    clock=None,
    limits=None,
    headers=None,
    status=200,
    stream_output=False,
    cached_content=None,
):
    from botocore.awsrequest import AWSResponse

    observed_flags = []

    def setup(clients):
        def delegate(request):
            observed_flags.append(request.stream_output)
            assert request.stream_output is True, "underlying send must not prebuffer the response"
            response = AWSResponse(request.url, status, headers or {}, raw)
            if cached_content is not None:
                response._content = cached_content
            return response

        clients[service]._endpoint.http_session.send = delegate

    transport, clients, _, _ = make(mutate=setup, clock=clock, limits=limits)
    request = SimpleNamespace(
        url=f"https://{service}.{scope().region}.amazonaws.com/",
        method="POST",
        headers={"x-amz-expected-bucket-owner": scope().account},
        body=None,
        stream_output=stream_output,
    )
    if service == "s3":
        request.url += scope().bucket
    return clients[service]._endpoint.http_session.send, request, observed_flags, transport


@pytest.mark.parametrize("service", ["sts", "s3", "cloudtrail"])
def test_http_control_body_is_guarded_before_botocore_content_prebuffering(service):
    raw = ScriptedHttpRaw()
    send, request, flags, _ = http_case(raw, service=service)
    response = send(request)
    assert response.content == b"{}"
    assert flags == [True]
    assert request.stream_output is False
    assert raw.closed
    assert raw.stream_calls == 0
    assert raw.read_sizes and all(type(size) is int and size > 0 for size in raw.read_sizes)
    assert raw.decode_flags and all(flag is False for flag in raw.decode_flags)


@pytest.mark.parametrize("service", ["sts", "s3", "cloudtrail"])
def test_oversized_nonstream_http_body_is_stopped_before_unbounded_content_join(service):
    raw = ScriptedHttpRaw(b"x" * 9)
    send, request, _, _ = http_case(
        raw, service=service, limits=TransportLimits(max_control_bytes=8, max_wire_read_calls=4)
    )
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed
    assert raw.stream_calls == 0
    assert len(raw.read_sizes) <= 4


def test_endless_one_byte_control_response_exhausts_wire_read_count_and_closes():
    raw = ScriptedHttpRaw(piece=b"x")
    send, request, _, _ = http_case(
        raw, limits=TransportLimits(max_control_bytes=64, max_wire_read_calls=3)
    )
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed
    assert len(raw.read_sizes) == 3


def test_wire_lease_expiry_is_checked_after_one_read_before_content_accumulation():
    current = [BASE_TIME]

    def expire():
        current[0] += timedelta(minutes=6)

    raw = ScriptedHttpRaw(b"{}", on_read=expire)
    send, request, _, _ = http_case(raw, clock=lambda: current[0])
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed
    assert len(raw.read_sizes) == 1


@pytest.mark.parametrize("kind", ["non-bytes", "read-error", "oversized-piece"])
def test_malformed_wire_stream_is_closed_and_error_sanitized(kind):
    if kind == "non-bytes":
        raw = ScriptedHttpRaw(piece="private-invalid-wire-piece")
    elif kind == "read-error":
        raw = ScriptedHttpRaw(failure=OSError(SECRET))
    else:
        raw = ScriptedHttpRaw(piece=b"x" * 10)
    send, request, _, _ = http_case(
        raw, limits=TransportLimits(max_control_bytes=8, max_wire_read_calls=4)
    )
    with pytest.raises(EvidenceError) as error:
        _ = send(request).content
    assert raw.closed
    assert SECRET not in str(error.value)


def test_s3_error_http_body_uses_control_bound_even_for_streaming_get_request():
    raw = ScriptedHttpRaw(b"x" * 9)
    send, request, _, _ = http_case(
        raw,
        service="s3",
        status=403,
        stream_output=True,
        limits=TransportLimits(max_control_bytes=8, max_wire_read_calls=4),
    )
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed
    assert request.stream_output is True


def test_replacing_installed_http_guard_is_rejected_before_any_source_action():
    transport, clients, _, _ = make()
    clients["s3"]._endpoint.http_session.send = lambda request: None
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)
    assert clients["s3"].calls == []


def test_guarded_send_restores_request_mode_when_delegate_fails():
    def setup(clients):
        def failed_delegate(request):
            assert request.stream_output is True
            raise OSError(SECRET)

        clients["sts"]._endpoint.http_session.send = failed_delegate

    _, clients, _, _ = make(mutate=setup)
    request = SimpleNamespace(
        url="https://sts.us-east-1.amazonaws.com/",
        method="POST",
        headers={},
        body=None,
        stream_output=False,
    )
    with pytest.raises(EvidenceError) as error:
        clients["sts"]._endpoint.http_session.send(request)
    assert request.stream_output is False
    assert SECRET not in str(error.value)


def test_prebuffered_response_cannot_bypass_installed_raw_byte_guard():
    raw = ScriptedHttpRaw()
    send, request, _, _ = http_case(raw, cached_content=b"unbounded-preloaded-private-response")
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed
    assert raw.read_sizes == []


def test_head_object_content_length_describes_the_object_without_a_wire_body():
    raw = ScriptedHttpRaw(b"")
    send, request, _, _ = http_case(
        raw,
        service="s3",
        headers={"content-length": "1024"},
        limits=TransportLimits(max_control_bytes=8),
    )
    request.method = "HEAD"
    response = send(request)
    assert response.content == b""
    assert response.headers["content-length"] == "1024"
    assert raw.closed


@pytest.mark.parametrize("object_size", [128, 2 * 1024 * 1024])
def test_official_head_parser_preserves_large_object_metadata_with_empty_http_body(object_size):
    from botocore.endpoint import convert_to_response_dict
    from botocore.loaders import Loader
    from botocore.model import ServiceModel
    from botocore.parsers import ResponseParserFactory

    raw = ScriptedHttpRaw(b"")
    send, request, _, _ = http_case(
        raw,
        service="s3",
        headers={
            "content-length": str(object_size),
            "x-amz-version-id": "v-one",
            "last-modified": "Thu, 01 Jan 2026 00:00:00 GMT",
        },
    )
    request.method = "HEAD"
    response = send(request)
    model = ServiceModel(Loader().load_service_model("s3", "service-2"), service_name="s3")
    operation = model.operation_model("HeadObject")
    converted = convert_to_response_dict(response, operation)
    parser = ResponseParserFactory().create_parser(model.metadata["protocol"])
    parsed = parser.parse(converted, operation.output_shape)
    assert parsed["ContentLength"] == object_size
    assert parsed["VersionId"] == "v-one"
    assert converted["body"] == b""
    assert raw.closed
    assert len(raw.read_sizes) == 1


@pytest.mark.parametrize("declared,actual", [("3", b"{}"), ("1", b"{}"), ("2", b"")])
def test_get_http_content_length_must_equal_complete_wire_body(declared, actual):
    raw = ScriptedHttpRaw(actual)
    send, request, _, _ = http_case(
        raw, service="s3", headers={"content-length": declared}, stream_output=True
    )
    request.method = "GET"
    with pytest.raises(EvidenceError):
        _ = send(request).content
    assert raw.closed


def test_replacing_entire_http_session_cannot_bypass_installed_send_guard():
    transport, clients, _, _ = make()
    clients["s3"]._endpoint.http_session = SimpleNamespace(_verify=True, send=lambda request: None)
    with pytest.raises(EvidenceError):
        transport.list_versions(scope(), scope().log_prefix, None)
    assert clients["s3"].calls == []


@pytest.mark.parametrize("length", ["bad-length", "-1", "9", "1" * 21, True])
def test_invalid_or_oversized_http_length_is_rejected_before_reading(length):
    raw = ScriptedHttpRaw()
    send, request, _, _ = http_case(
        raw, headers={"content-length": length}, limits=TransportLimits(max_control_bytes=8)
    )
    with pytest.raises(EvidenceError):
        send(request)
    assert raw.closed
    assert raw.read_sizes == []


def test_wire_stream_without_single_io_read1_cannot_fall_back_to_filling_read():
    raw = ScriptedHttpRaw()
    raw.read1 = None
    send, request, _, _ = http_case(raw)
    with pytest.raises(EvidenceError):
        send(request)
    assert raw.closed
    assert raw.stream_calls == 0


def test_official_get_streaming_body_uses_guarded_reads_and_preserves_metadata():
    from botocore.endpoint import convert_to_response_dict
    from botocore.loaders import Loader
    from botocore.model import ServiceModel
    from botocore.parsers import ResponseParserFactory

    data = b"generated-stream-payload"
    raw = ScriptedHttpRaw(data)
    send, request, _, _ = http_case(
        raw,
        service="s3",
        stream_output=True,
        headers={"content-length": str(len(data)), "x-amz-version-id": "v-one"},
        limits=TransportLimits(max_control_bytes=8),
    )
    request.method = "GET"
    request.url += "/" + scope().log_prefix + "log.json.gz"
    response = send(request)
    model = ServiceModel(Loader().load_service_model("s3", "service-2"), service_name="s3")
    operation = model.operation_model("GetObject")
    converted = convert_to_response_dict(response, operation)
    parsed = (
        ResponseParserFactory()
        .create_parser(model.metadata["protocol"])
        .parse(converted, operation.output_shape)
    )
    assert parsed["ContentLength"] == len(data)
    assert parsed["VersionId"] == "v-one"
    body = parsed["Body"]
    try:
        assert body.read(1) == data[:1]
        assert body.read() == data[1:]
        assert body.read() == b""
        assert body.tell() == len(data)
    finally:
        body.close()
    assert raw.closed
    assert all(flag is False for flag in raw.decode_flags)
