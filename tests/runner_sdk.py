"""Trusted integration worker: fictional injected clients, no network factory."""

import time

from cloudsecops_live.integrations.aws_runner.contracts import (
    BudgetPolicy,
    IdentityAuthorization,
    OperationBudget,
)
from cloudsecops_live.integrations.aws_runner.sdk_budget import BudgetedClients
from cloudsecops_live.integrations.aws_sdk.transport import AwsSdkTransport, SessionLease
from tests.aws_helpers import BASE_TIME
from tests.aws_sdk_helpers import fixtures


def inspect_fixture(request: object) -> object:
    assert isinstance(request, dict)
    expected, lease, clients, _, _ = fixtures()
    if request.get("substitute"):
        clients["sts"].responses["get_caller_identity"]["UserId"] = "AROA" + "Z" * 17 + ":offline"
    authorization = IdentityAuthorization(
        expected, SessionLease(**lease), "owner_supplied_temporary_session"
    )
    budget = OperationBudget(
        authorization,
        BudgetPolicy(max_calls=request.get("calls", 64)),
        monotonic=time.monotonic,
        clock=lambda: BASE_TIME,
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
    if request.get("mutate"):
        wrapped.s3.delete_object(Bucket=expected.bucket, Key="forged")
    observation = transport.inspect_trail()
    budget.check()
    return {"budget": budget.to_public_dict(), "authenticated": observation.authenticated}
