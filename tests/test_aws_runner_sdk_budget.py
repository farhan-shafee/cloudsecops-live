"""Independent expectations for aggregate budgets at the injected SDK boundary."""

import time
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_runner.contracts import (
    BudgetPolicy,
    IdentityAuthorization,
    OperationBudget,
)
from cloudsecops_live.integrations.aws_runner.sdk_budget import BudgetedClients
from cloudsecops_live.integrations.aws_sdk.transport import AwsSdkTransport, SessionLease
from tests.aws_helpers import BASE_TIME
from tests.aws_sdk_helpers import fixtures


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("budget tests must not use a real network")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def prepared(**limits):
    expected, lease, clients, ref, data = fixtures()
    authorization = IdentityAuthorization(
        expected, SessionLease(**lease), "owner_supplied_temporary_session"
    )
    budget = OperationBudget(
        authorization, BudgetPolicy(**limits), monotonic=time.monotonic, clock=lambda: BASE_TIME
    )
    wrapped = BudgetedClients(clients, budget)
    transport = AwsSdkTransport(
        expected,
        authorization.lease,
        sts_client=wrapped.sts,
        s3_client=wrapped.s3,
        cloudtrail_client=wrapped.cloudtrail,
        clock=lambda: BASE_TIME,
    )
    return expected, clients, wrapped, budget, transport


def test_sts_and_failed_source_attempt_consume_global_call_budget():
    expected, clients, wrapped, _, transport = prepared(max_calls=1)
    with pytest.raises(EvidenceError):
        transport.list_versions(expected, expected.log_prefix, None)
    assert len(clients["sts"].calls) == 1
    assert clients["s3"].calls == []
    with pytest.raises(EvidenceError):
        wrapped.sts.get_caller_identity()


def test_mutating_or_unknown_operation_never_reaches_injected_client():
    _, clients, wrapped, _, _ = prepared()
    with pytest.raises(EvidenceError):
        wrapped.s3.delete_object(Bucket="forged")
    assert clients["s3"].calls == []
    with pytest.raises(EvidenceError):
        wrapped.sts.get_caller_identity()


def test_total_operation_limit_is_enforced_at_dispatch():
    _, clients, wrapped, budget, _ = prepared(max_operations=1)
    wrapped.sts.get_caller_identity()
    with pytest.raises(EvidenceError, match="AWS_RUN_OPERATION_LIMIT"):
        wrapped.sts.get_caller_identity()
    assert len(clients["sts"].calls) == 1
    assert budget.to_public_dict()["operations"] == 1


def test_retry_budget_cannot_be_refunded_by_repeated_client_failures():
    _, clients, wrapped, _, _ = prepared(max_retries=1)
    clients["sts"].responses["get_caller_identity"] = ReadTimeoutError(endpoint_url="private")
    for _ in range(2):
        with pytest.raises(ReadTimeoutError):
            wrapped.sts.get_caller_identity()
    with pytest.raises(EvidenceError):
        wrapped.sts.get_caller_identity()
    assert len(clients["sts"].calls) == 2


def test_byte_limit_is_aggregate_and_sticky_after_excess():
    _, _, _, budget, _ = prepared(max_wire_bytes=5)
    budget.consume_wire_bytes(3)
    with pytest.raises(EvidenceError):
        budget.consume_wire_bytes(3)
    with pytest.raises(EvidenceError):
        budget.check()


def test_supported_disabled_insights_observation_does_not_reject_run():
    expected, clients, _, budget, transport = prepared()
    clients["cloudtrail"].responses["get_insight_selectors"] = ClientError(
        {
            "Error": {"Code": "InsightNotEnabledException"},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        },
        "GetInsightSelectors",
    )
    result = transport.inspect_trail()
    assert result.insight_state == "disabled_service_observation"
    budget.check()
    assert budget.to_public_dict()["state"] != "rejected"


def test_actual_guarded_http_reads_share_one_body_byte_budget():
    from botocore.awsrequest import AWSResponse

    from tests.test_aws_sdk_transport import ScriptedHttpRaw

    expected, lease, clients, _, _ = fixtures()
    raws = [ScriptedHttpRaw(b"{}"), ScriptedHttpRaw(b"{}")]
    pending = list(raws)
    clients["sts"]._endpoint.http_session.send = lambda request: AWSResponse(
        request.url, 200, {}, pending.pop(0)
    )
    authorization = IdentityAuthorization(
        expected, SessionLease(**lease), "owner_supplied_temporary_session"
    )
    budget = OperationBudget(
        authorization,
        BudgetPolicy(max_wire_bytes=3),
        monotonic=time.monotonic,
        clock=lambda: BASE_TIME,
    )
    wrapped = BudgetedClients(clients, budget)
    AwsSdkTransport(
        expected,
        authorization.lease,
        sts_client=wrapped.sts,
        s3_client=wrapped.s3,
        cloudtrail_client=wrapped.cloudtrail,
        clock=lambda: BASE_TIME,
    )
    request = SimpleNamespace(
        url=f"https://sts.{expected.region}.amazonaws.com/",
        method="POST",
        headers={},
        body=None,
        stream_output=False,
    )
    send = clients["sts"]._endpoint.http_session.send
    assert send(request).content == b"{}"
    assert budget.to_public_dict()["wire_bytes"] == 2
    with pytest.raises(EvidenceError, match="AWS_RUN_BYTE_LIMIT"):
        _ = send(request).content
    assert raws[1].closed
    assert budget.to_public_dict()["state"] == "rejected"


@pytest.mark.parametrize(
    "field,value",
    [
        ("Error", []),
        ("ResponseMetadata", []),
        ("Error", {"Code": []}),
        ("ResponseMetadata", {"HTTPStatusCode": 429.0}),
    ],
)
def test_malformed_client_error_permanently_rejects_budget(field, value):
    _, clients, wrapped, budget, _ = prepared()
    error = ClientError(
        {"Error": {"Code": "Throttling"}, "ResponseMetadata": {"HTTPStatusCode": 429}},
        "GetCallerIdentity",
    )
    error.response[field] = value
    clients["sts"].responses["get_caller_identity"] = error
    with pytest.raises(ClientError):
        wrapped.sts.get_caller_identity()
    with pytest.raises(EvidenceError, match="AWS_RUN_REJECTED"):
        budget.check()


def test_bad_parameter_shape_and_missing_client_set_fail_before_call():
    _, clients, wrapped, budget, _ = prepared()
    with pytest.raises(EvidenceError, match="AWS_RUN_PARAMETERS"):
        wrapped.s3.get_object(Key=[])
    assert clients["s3"].calls == []
    with pytest.raises(EvidenceError, match="AWS_RUN_CLIENTS"):
        BudgetedClients({}, budget)


def test_retryable_service_error_is_bounded_and_retried_without_refund():
    _, clients, wrapped, budget, _ = prepared(max_retries=0)
    clients["sts"].responses["get_caller_identity"] = ClientError(
        {"Error": {"Code": "Throttling"}, "ResponseMetadata": {"HTTPStatusCode": 429}},
        "GetCallerIdentity",
    )
    with pytest.raises(ClientError):
        wrapped.sts.get_caller_identity()
    with pytest.raises(EvidenceError, match="AWS_RUN_RETRY_LIMIT"):
        wrapped.sts.get_caller_identity()
    assert len(clients["sts"].calls) == 1
    assert budget.to_public_dict()["calls"] == 1
