"""Independent final-wire session-binding regressions; no actual AWS access."""

import json
import logging
import socket

import pytest

from cloudsecops_live.errors import EvidenceError
from tests.aws4a_helpers import NOW
from tests.aws4a_signing_helpers import (
    SERVICES,
    SigningCase,
    alternative_credentials,
    header_text,
    resign,
)


@pytest.fixture(autouse=True)
def deny_network_and_ambient_providers(monkeypatch):
    import boto3
    import botocore.auth
    import botocore.session

    def forbidden(*args, **kwargs):
        pytest.fail("signing regression must not access network or providers")

    previous = {
        name: (logger.level, logger.disabled)
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(botocore.session, "get_session", forbidden)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)
    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda **kwargs: NOW)
    yield
    for name, (level, disabled) in previous.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.disabled = disabled


@pytest.fixture
def signing_case(request):
    case = SigningCase(request.param)
    yield case
    case.close()


def assert_final_rejected(case, *, sent_before=0, retry=False):
    with pytest.raises(EvidenceError) as caught:
        case.call(retry=retry)
    assert case.sent == sent_before, "invalid signing must never reach fake HTTP transport"
    public = case.budget.public_dict()
    assert public["state"] == "rejected"
    assert public["authenticated"] is False
    assert public["trusted_findings_available"] is False
    assert public["closure_available"] is False
    receipt = json.dumps(public) + str(caught.value)
    assert "fictional-" not in receipt and "ASIA" not in receipt
    with pytest.raises(EvidenceError):
        case.budget.check()


@pytest.mark.parametrize("signing_case", SERVICES, indirect=True)
def test_late_alternative_sigv4_identity_is_rejected_before_fake_http(signing_case):
    case = signing_case
    original = case.bound.credentials
    snapshot = original.get_frozen_credentials()
    alternate = alternative_credentials()

    def replace(request, **kwargs):
        resign(request, alternate, case.service)

    case.handler(replace)
    assert_final_rejected(case)
    assert case.bound.credentials is original
    assert case.client._request_signer._credentials is original
    assert original.get_frozen_credentials() == snapshot


@pytest.mark.parametrize("signing_case", SERVICES, indirect=True)
def test_valid_real_sdk_signatures_keep_exact_pinned_model_scope(signing_case):
    case = signing_case
    result = case.call()
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200 and case.sent == 1
    expected = {
        "sts": "sts",
        "iam": "iam",
        "cloudtrail": "cloudtrail",
        "s3": "s3",
        "s3control": "s3",
    }
    assert case.signing_service == expected[case.service]
    assert case.budget.public_dict()["state"] == "offline_budget_observation"
    assert case.budget.public_dict()["authenticated"] is False


@pytest.mark.parametrize("signing_case", SERVICES, indirect=True)
def test_same_access_key_cannot_authorize_an_alternative_token(signing_case):
    case = signing_case
    alternate = alternative_credentials(same_key=True)

    def replace(request, **kwargs):
        resign(request, alternate, case.service)

    case.handler(replace)
    assert_final_rejected(case)


def mutate_headers(request, variant):
    headers = {name: header_text(value) for name, value in request.headers.items()}
    auth = headers.get("Authorization", "")
    token_name = next(name for name in headers if name.casefold() == "x-amz-security-token")
    date_name = next(name for name in headers if name.casefold() == "x-amz-date")
    if variant == "missing_auth":
        del headers["Authorization"]
    elif variant == "missing_token":
        del headers[token_name]
    elif variant == "missing_date":
        del headers[date_name]
    elif variant == "duplicate_auth":
        headers["authorization"] = auth
    elif variant == "duplicate_token":
        headers["x-amz-security-token"] = headers[token_name]
    elif variant == "duplicate_date":
        headers["x-amz-date"] = headers[date_name]
    elif variant == "malformed_auth":
        headers["Authorization"] = "not-a-signature"
    elif variant == "unsupported_algorithm":
        headers["Authorization"] = auth.replace("AWS4-HMAC-SHA256", "AWS4-ECDSA-P256-SHA256")
    elif variant == "foreign_key":
        headers["Authorization"] = auth.replace("ASIA" + "Q" * 16, "ASIA" + "Z" * 16)
    elif variant == "wrong_region":
        headers["Authorization"] = auth.replace("/us-east-1/", "/us-west-2/")
    elif variant == "wrong_service":
        headers["Authorization"] = auth.replace("/iam/", "/ec2/")
    elif variant == "wrong_scope_date":
        headers["Authorization"] = auth.replace("/20261105/", "/20261104/")
    elif variant == "wrong_scope_termination":
        headers["Authorization"] = auth.replace("/aws4_request", "/unapproved_request")
    elif variant == "missing_signature":
        headers["Authorization"] = auth.split(", Signature=", 1)[0]
    elif variant == "missing_signed_headers":
        left, right = auth.split(", SignedHeaders=", 1)
        headers["Authorization"] = left + ", Signature=" + right.split(", Signature=", 1)[1]
    elif variant == "duplicate_credential_field":
        credential = auth.split("Credential=", 1)[1].split(",", 1)[0]
        headers["Authorization"] = auth + ", Credential=" + credential
    elif variant == "malformed_signature":
        headers["Authorization"] = auth.rsplit("Signature=", 1)[0] + "Signature=invalid"
    elif variant == "changed_signature":
        headers["Authorization"] = auth.rsplit("Signature=", 1)[0] + "Signature=" + "0" * 64
    elif variant == "signed_header_omits_host":
        headers["Authorization"] = auth.replace(";host;", ";")
    elif variant == "signed_header_omits_token":
        headers["Authorization"] = auth.replace(";x-amz-security-token", "")
    elif variant == "signed_header_omits_date":
        headers["Authorization"] = auth.replace(";x-amz-date", "")
    elif variant == "signed_header_repeated":
        headers["Authorization"] = auth.replace(";host;", ";host;host;")
    elif variant == "signed_header_noncanonical_case":
        headers["Authorization"] = auth.replace(";host;", ";Host;")
    elif variant == "signed_header_unsorted":
        headers["Authorization"] = auth.replace("content-type;host;", "host;content-type;")
    elif variant == "signed_header_extra":
        headers["Authorization"] = auth.replace(";host;", ";host;x-unapproved;")
    elif variant == "signed_header_empty":
        headers["Authorization"] = auth.replace(";host;", ";;host;")
    elif variant == "altered_token":
        headers[token_name] = "fictional-signing-alternative-token-never-valid"
    elif variant == "malformed_date":
        headers[date_name] = "not-a-timestamp"
    elif variant == "stale_date":
        headers[date_name] = "20261104T120000Z"
    elif variant == "future_date":
        headers[date_name] = "20261106T120000Z"
    elif variant == "impossible_date":
        headers[date_name] = "20261340T250000Z"
    elif variant == "foreign_host":
        headers["Host"] = "unapproved.invalid"
    elif variant == "changed_content_type":
        name = next(name for name in headers if name.casefold() == "content-type")
        headers[name] = "application/changed"
    else:
        raise AssertionError("unknown independently specified signing mutation")
    request.headers = headers


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
@pytest.mark.parametrize(
    "variant",
    [
        "missing_auth",
        "missing_token",
        "missing_date",
        "duplicate_auth",
        "duplicate_token",
        "duplicate_date",
        "malformed_auth",
        "unsupported_algorithm",
        "foreign_key",
        "wrong_region",
        "wrong_service",
        "wrong_scope_date",
        "wrong_scope_termination",
        "missing_signature",
        "missing_signed_headers",
        "duplicate_credential_field",
        "malformed_signature",
        "changed_signature",
        "signed_header_omits_host",
        "signed_header_omits_token",
        "signed_header_omits_date",
        "signed_header_repeated",
        "signed_header_noncanonical_case",
        "signed_header_unsorted",
        "signed_header_extra",
        "signed_header_empty",
        "altered_token",
        "malformed_date",
        "stale_date",
        "future_date",
        "impossible_date",
        "foreign_host",
        "changed_content_type",
    ],
)
def test_final_signing_header_variants_fail_closed(signing_case, variant):
    case = signing_case

    def replace(request, **kwargs):
        mutate_headers(request, variant)

    case.handler(replace)
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_semantically_equal_body_reorder_cannot_reuse_original_signature(signing_case):
    case = signing_case

    def replace(request, **kwargs):
        body = header_text(request.body)
        request.body = "&".join(reversed(body.split("&")))
        request.headers["Content-Length"] = str(len(request.body.encode()))

    case.handler(replace)
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_late_signer_credential_object_substitution_fails_even_with_retained_headers(signing_case):
    case = signing_case

    def replace(request, **kwargs):
        case.client._request_signer._credentials = alternative_credentials()

    case.handler(replace)
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
@pytest.mark.parametrize("variant", ["callback", "token", "identity", "expiry"])
def test_late_bound_session_mutation_is_rejected_before_transport(signing_case, variant):
    from dataclasses import replace

    case = signing_case

    def mutate(request, **kwargs):
        if variant == "callback":
            case.bound.credentials._refresh_using = lambda: None
        elif variant == "token":
            case.bound.credentials.token = "fictional-alternative-token-never-valid"
        elif variant == "identity":
            object.__setattr__(
                case.bound, "_expected", replace(case.bound._expected, role_id="AROA" + "Z" * 17)
            )
        else:
            object.__setattr__(
                case.bound, "_issuance", replace(case.bound._issuance, expires_at=NOW)
            )

    case.handler(mutate)
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_late_budget_cancellation_cannot_dispatch_a_retained_signature(signing_case):
    case = signing_case
    case.handler(lambda request, **kwargs: case.budget.invalidate())
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_explicit_retry_requires_a_fresh_bound_signature_and_cannot_substitute(signing_case):
    from botocore.exceptions import ConnectTimeoutError

    case = signing_case

    def timeout(request):
        case.sent += 1
        raise ConnectTimeoutError(endpoint_url="approved-posture-endpoint")

    case.client._endpoint.http_session._transport.send = timeout
    with pytest.raises(ConnectTimeoutError):
        case.call()
    assert case.sent == 1
    case.client._endpoint.http_session._transport.send = case.fake_send
    case.handler(lambda request, **kwargs: resign(request, alternative_credentials(), case.service))
    assert_final_rejected(case, sent_before=1, retry=True)


@pytest.mark.parametrize("signing_case", SERVICES, indirect=True)
def test_same_access_key_and_token_do_not_hide_an_alternative_secret(signing_case):
    from botocore.credentials import Credentials

    case = signing_case
    original = case.bound.credentials.get_frozen_credentials()
    alternate = Credentials(
        original.access_key,
        "fictional-signing-different-secret-never-valid",
        original.token,
        method="explicit",
    )
    case.handler(lambda request, **kwargs: resign(request, alternate, case.service))
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["s3"], indirect=True)
@pytest.mark.parametrize("payload_hash", [None, "UNSIGNED-PAYLOAD", "0" * 64, "malformed"])
def test_s3_payload_hash_cannot_be_missing_unsigned_or_conflict_with_body(
    signing_case, payload_hash
):
    case = signing_case

    def replace(request, **kwargs):
        headers = {name: header_text(value) for name, value in request.headers.items()}
        name = next(name for name in headers if name.casefold() == "x-amz-content-sha256")
        if payload_hash is None:
            del headers[name]
        else:
            headers[name] = payload_hash
        request.headers = headers

    case.handler(replace)
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", SERVICES, indirect=True)
def test_final_transport_receives_a_frozen_copy_that_retained_sdk_request_cannot_change(
    signing_case,
):
    case = signing_case
    retained = []
    case.handler(lambda request, **kwargs: retained.append(request))
    inspected = []

    def inspect_snapshot(snapshot):
        original = retained[0]
        assert snapshot is not original
        before_auth = header_text(snapshot.headers["Authorization"])
        before_token = header_text(snapshot.headers["X-Amz-Security-Token"])
        before_url, before_body = snapshot.url, snapshot.body
        original.url = "https://unapproved.invalid/"
        original.body = b"unapproved"
        original.headers["Authorization"] = "unapproved"
        original.headers["X-Amz-Security-Token"] = "unapproved"
        assert snapshot.url == before_url and snapshot.body == before_body
        assert header_text(snapshot.headers["Authorization"]) == before_auth
        assert header_text(snapshot.headers["X-Amz-Security-Token"]) == before_token
        with pytest.raises((AttributeError, TypeError)):
            snapshot.body = b"unapproved"
        with pytest.raises((AttributeError, TypeError)):
            snapshot.headers["Authorization"] = "unapproved"
        with pytest.raises((AttributeError, TypeError)):
            snapshot.headers._values = {}
        assert "ASIA" not in repr(snapshot) and "fictional-" not in repr(snapshot)
        assert repr(snapshot.headers) == "FrozenHeaders()"
        inspected.append(True)
        return case.fake_send(snapshot)

    case.client._endpoint.http_session._transport.send = inspect_snapshot
    result = case.call()
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert inspected == [True] and case.sent == 1


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_valid_explicit_retry_revalidates_bound_signing_material(signing_case):
    from botocore.exceptions import ConnectTimeoutError

    case = signing_case

    def timeout(request):
        case.sent += 1
        raise ConnectTimeoutError(endpoint_url="approved-posture-endpoint")

    case.client._endpoint.http_session._transport.send = timeout
    with pytest.raises(ConnectTimeoutError):
        case.call()
    case.client._endpoint.http_session._transport.send = case.fake_send
    result = case.call(retry=True)
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200 and case.sent == 2
    assert case.budget.public_dict()["retries"] == 1
    assert case.budget.public_dict()["calls"] == 2


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_presigned_query_cannot_bypass_fixed_header_signing(signing_case):
    case = signing_case

    def replace(request, **kwargs):
        request.url += "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=unapproved"

    case.handler(replace)
    assert_final_rejected(case)


@pytest.mark.parametrize("service", SERVICES)
@pytest.mark.parametrize("fractional_start", [False, True])
def test_valid_subsecond_observations_and_issuance_keep_sigv4_second_precision(
    service, fractional_start, monkeypatch
):
    from datetime import timedelta

    import botocore.auth

    observed = NOW + timedelta(microseconds=500_000)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda **kwargs: observed)
    case = SigningCase(service, now=observed, fractional_start=fractional_start)
    try:
        result = case.call()
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert case.sent == 1 and case.budget.public_dict()["authenticated"] is False
    finally:
        case.close()


@pytest.mark.parametrize("offset", [-1, 1, 31])
def test_real_sigv4_time_outside_fractional_issuance_window_is_rejected(offset, monkeypatch):
    from datetime import timedelta

    import botocore.auth

    observed = NOW + timedelta(microseconds=500_000)
    signed = NOW + timedelta(seconds=offset)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda **kwargs: signed)
    case = SigningCase("iam", now=observed, fractional_start=True)
    try:
        assert_final_rejected(case)
    finally:
        case.close()


@pytest.mark.parametrize("signing_case", ["iam", "cloudtrail"], indirect=True)
def test_actual_nonempty_request_body_is_charged_exactly_once(signing_case):
    case = signing_case
    lengths = []

    def measured_send(request):
        lengths.append(len(request.body))
        return case.fake_send(request)

    case.client._endpoint.http_session._transport.send = measured_send
    case.call()
    logical = len(json.dumps(case.params, sort_keys=True, separators=(",", ":")).encode())
    assert len(lengths) == 1 and lengths[0] > 0
    assert case.budget.public_dict()["request_bytes"] == logical + lengths[0]


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
def test_missing_or_wrong_final_signing_configuration_has_no_authless_fallback(signing_case):
    from cloudsecops_live.integrations.aws_posture.signing import FinalSigningBinding
    from cloudsecops_live.integrations.aws_posture.wire import GuardedSession

    case = signing_case
    with pytest.raises(EvidenceError, match="AWS4A_SIGNING_BINDING"):
        GuardedSession("iam", case.owner.expected.account, object(), case.budget, None)
    with pytest.raises(EvidenceError, match="AWS4A_SIGNING_BINDING"):
        FinalSigningBinding("unapproved", case.client, case.bound, case.budget)
    assert case.sent == 0


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
@pytest.mark.parametrize("boundary", ["deadline", "session_expiry"])
def test_deadline_or_expiry_during_final_hmac_never_reaches_transport(
    signing_case, boundary, monkeypatch
):
    from datetime import timedelta

    from botocore.auth import SigV4Auth

    case = signing_case
    original = SigV4Auth.signature

    def advancing_hmac(self, string_to_sign, request):
        signature = original(self, string_to_sign, request)
        if boundary == "deadline":
            case.budget._monotonic = lambda: 32.0
        else:
            expired = case.bound.lease.expires_at + timedelta(microseconds=1)
            case.budget._clock = lambda: expired
        return signature

    # Install after real SDK signing. Only the final verification HMAC advances
    # time, reproducing a deadline/lease transition inside verification itself.
    case.handler(
        lambda request, **kwargs: monkeypatch.setattr(SigV4Auth, "signature", advancing_hmac)
    )
    assert_final_rejected(case)


@pytest.mark.parametrize("signing_case", ["iam"], indirect=True)
@pytest.mark.parametrize("target", ["secrets", "binding"])
def test_private_final_signing_state_cannot_enter_pickled_receipts(signing_case, target):
    import pickle

    case = signing_case
    binding = case.client._endpoint.http_session._signing
    private = binding._secrets if target == "secrets" else binding
    with pytest.raises(EvidenceError, match="^AWS4A_SIGNING_PRIVATE$") as caught:
        pickle.dumps(private)
    assert "fictional-" not in str(caught.value) and "ASIA" not in str(caught.value)
    assert case.sent == 0
