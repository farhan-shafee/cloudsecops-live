"""Independent ceilings and request-scope expectations for posture-only calls."""

from dataclasses import replace

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy
from tests.aws4a_helpers import NOW, decision, session


def make(*, policy=None):
    expected = decision(**({"budget": policy} if policy is not None else {}))
    clock = {"utc": NOW, "tick": 10.0}
    meter = PostureBudget(
        expected,
        session(expected),
        clock=lambda: clock["utc"],
        monotonic=lambda: clock["tick"],
    )
    return meter, clock


def test_account_operation_and_send_are_bound_to_one_exact_reservation():
    meter, _ = make()
    params = {"AccountId": meter.decision.expected.account}
    meter.before_call("s3control", "GetPublicAccessBlock", params)
    meter.authorize_parameters("s3control", "GetPublicAccessBlock", dict(params))
    meter.authorize_wire_parameters("s3control", "GetPublicAccessBlock", dict(params))
    meter.before_send("s3control")
    meter.consume_request_bytes(17)
    meter.consume_response_bytes(29)
    result = meter.public_dict()
    assert result["calls"] == 1 and result["operations"] == 1 and result["pages"] == 0
    assert result["request_bytes"] >= 17 and result["response_bytes"] == 29
    assert result["authenticated"] is False and result["closure_available"] is False
    with pytest.raises(EvidenceError):
        meter.before_send("s3control")
    assert meter.public_dict()["state"] == "rejected"


@pytest.mark.parametrize(
    "service,operation,params",
    [
        ("s3", "GetPublicAccessBlock", {"Bucket": "other"}),
        ("s3", "GetObject", {"Bucket": "other", "Key": "evidence"}),
        ("sts", "AssumeRole", {}),
        ("iam", "CreateRole", {}),
        ("s3control", "GetPublicAccessBlock", {"AccountId": "2" * 12}),
        ("s3control", "GetPublicAccessBlock", {"AccountId": "1" * 12, "Bucket": "other"}),
        ("sts", "GetCallerIdentity", {"region": "us-east-1"}),
        ("cloudtrail", "ListTrails", {"MaxResults": 64}),
        ("cloudtrail", "ListTrails", {"NextToken": ""}),
        ("cloudtrail", "ListTrails", {"NextToken": "a" * 1025}),
        ("cloudtrail", "ListTrails", {"NextToken": "a\x00b"}),
        ("s3", "ListBuckets", {}),
        ("s3", "ListBuckets", {"MaxBuckets": True}),
        ("s3", "ListBuckets", {"MaxBuckets": 65}),
        ("s3", "ListBuckets", {"MaxBuckets": 64, "BucketRegion": "us-east-1"}),
        ("s3", "ListBuckets", {"MaxBuckets": 64, "Prefix": "filter"}),
        ("s3", "ListBuckets", {"MaxBuckets": 64, "ContinuationToken": None}),
        ("iam", "GetRole", {"RoleName": "Other"}),
        ("iam", "GetRolePolicy", {"RoleName": "OfflineInspector", "PolicyName": "Other"}),
        ("iam", "ListRolePolicies", {"RoleName": "OfflineInspector"}),
        (
            "iam",
            "ListAttachedRolePolicies",
            {"RoleName": "OfflineInspector", "MaxItems": 64, "Marker": 1},
        ),
    ],
)
def test_unauthorized_or_ambiguous_operation_never_reserves_dispatch(service, operation, params):
    meter, _ = make()
    with pytest.raises(EvidenceError):
        meter.before_call(service, operation, params)
    assert meter.public_dict()["calls"] == 0
    with pytest.raises(EvidenceError):
        meter.before_call("sts", "GetCallerIdentity", {})


@pytest.mark.parametrize("mutation", ["params", "service", "operation", "replay", "send_first"])
def test_low_level_dispatch_cannot_substitute_or_replay_a_permit(mutation):
    meter, _ = make()
    meter.before_call("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError):
        if mutation == "send_first":
            meter.before_send("sts")
        elif mutation == "params":
            meter.authorize_parameters("sts", "GetCallerIdentity", {"unexpected": True})
        elif mutation == "service":
            meter.authorize_parameters("s3", "GetCallerIdentity", {})
        elif mutation == "operation":
            meter.authorize_parameters("sts", "AssumeRole", {})
        else:
            meter.authorize_parameters("sts", "GetCallerIdentity", {})
            meter.authorize_parameters("sts", "GetCallerIdentity", {})


def test_missing_reservation_and_wrong_send_service_fail_closed():
    meter, _ = make()
    with pytest.raises(EvidenceError):
        meter.authorize_parameters("sts", "GetCallerIdentity", {})
    meter, _ = make()
    meter.before_call("sts", "GetCallerIdentity", {})
    meter.authorize_parameters("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError):
        meter.before_send("s3")


@pytest.mark.parametrize(
    "policy,first,second",
    [
        (
            BudgetPolicy(max_calls=1),
            ("sts", "GetCallerIdentity", {}),
            ("sts", "GetCallerIdentity", {}),
        ),
        (
            BudgetPolicy(max_operations=1),
            ("sts", "GetCallerIdentity", {}),
            ("sts", "GetCallerIdentity", {}),
        ),
        (
            BudgetPolicy(max_pages=1),
            ("s3", "ListBuckets", {"MaxBuckets": 64}),
            ("s3", "ListBuckets", {"MaxBuckets": 64}),
        ),
    ],
)
def test_global_caps_reject_before_one_over_limit_dispatch(policy, first, second):
    meter, _ = make(policy=policy)
    meter.before_call(*first)
    with pytest.raises(EvidenceError):
        meter.before_call(*second)
    assert meter.public_dict()["calls"] == 1


def test_explicit_retry_counts_failed_attempt_and_page_without_new_operation():
    meter, _ = make(policy=BudgetPolicy(max_retries=1))
    meter.before_call("s3", "ListBuckets", {"MaxBuckets": 64})
    meter.before_call("s3", "ListBuckets", {"MaxBuckets": 64}, retry=True)
    assert meter.public_dict()["calls"] == 2
    assert meter.public_dict()["pages"] == 2
    assert meter.public_dict()["operations"] == 1
    assert meter.public_dict()["retries"] == 1
    with pytest.raises(EvidenceError):
        meter.before_call("s3", "ListBuckets", {"MaxBuckets": 64}, retry=True)


def test_retry_requires_exact_previous_failed_operation_and_boolean_marker():
    for service, operation, params, retry in [
        ("sts", "GetCallerIdentity", {}, True),
        ("sts", "GetCallerIdentity", {}, "true"),
    ]:
        meter, _ = make()
        with pytest.raises(EvidenceError):
            meter.before_call(service, operation, params, retry=retry)
    meter, _ = make()
    meter.before_call("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError):
        meter.before_call("cloudtrail", "ListTrails", {}, retry=True)


def test_request_and_response_bytes_share_one_non_refundable_ceiling():
    meter, _ = make(policy=BudgetPolicy(max_wire_bytes=10))
    meter.consume_request_bytes(4)
    meter.consume_response_bytes(6)
    assert meter.public_dict()["wire_bytes"] == 10
    with pytest.raises(EvidenceError):
        meter.consume_response_bytes(1)
    assert meter.public_dict()["wire_bytes"] == 10
    with pytest.raises(EvidenceError):
        meter.consume_request_bytes(0)


@pytest.mark.parametrize("value", [-1, True, 1.5, "1", None])
def test_invalid_byte_counters_invalidate(value):
    meter, _ = make()
    with pytest.raises(EvidenceError):
        meter.consume_request_bytes(value)


@pytest.mark.parametrize("tick", [float("nan"), float("inf"), -1.0, True, "bad"])
def test_untrustworthy_clock_measurement_rejects(tick):
    meter, clock = make()
    clock["tick"] = tick
    with pytest.raises(EvidenceError):
        meter.check()


def test_deadline_clock_rollback_expiry_and_identity_substitution_fail_closed():
    from datetime import timedelta

    for change in ("deadline", "rollback", "expiry", "credential"):
        meter, clock = make()
        if change == "deadline":
            clock["tick"] += meter.policy.deadline_seconds
        elif change == "rollback":
            clock["tick"] -= 1
        elif change == "expiry":
            clock["utc"] += timedelta(hours=1)
        else:
            meter.session.credentials.token = "fictional-replacement"
        with pytest.raises(EvidenceError):
            meter.check()
        assert meter.public_dict()["state"] == "rejected"


def test_wrong_decision_identity_and_bad_contracts_reject_before_use():
    expected = decision()
    from tests.aws4a_helpers import identity

    wrong = replace(expected, expected=replace(identity(), role_id="AROA" + "V" * 17))
    for supplied_decision, supplied_session in (
        (wrong, session(expected)),
        (None, session(expected)),
        (expected, None),
    ):
        with pytest.raises(EvidenceError):
            PostureBudget(
                supplied_decision, supplied_session, clock=lambda: NOW, monotonic=lambda: 1.0
            )


def test_nondata_parameter_cannot_invoke_comparison_callbacks():
    meter, _ = make()

    class Untrusted:
        def __eq__(self, other):
            pytest.fail("parameter comparison invoked untrusted code")

    with pytest.raises(EvidenceError):
        meter.before_call("s3control", "GetPublicAccessBlock", {"AccountId": Untrusted()})
    assert meter.public_dict()["calls"] == 0


def test_clock_dependencies_must_be_explicit_callables():
    owner = decision()
    with pytest.raises(EvidenceError):
        PostureBudget(owner, session(owner), clock=None, monotonic=lambda: 1.0)


@pytest.mark.parametrize("broken", ["monotonic", "clock"])
def test_clock_dependency_failure_is_sanitized_and_sticky(broken):
    owner = decision()

    def fail():
        raise RuntimeError("private-clock-canary")

    with pytest.raises(EvidenceError) as failure:
        PostureBudget(
            owner,
            session(owner),
            clock=fail if broken == "clock" else lambda: NOW,
            monotonic=fail if broken == "monotonic" else lambda: 1.0,
        )
    assert "private-clock-canary" not in str(failure.value)


def test_wire_reservation_is_a_checked_independent_snapshot():
    meter, _ = make()
    meter.before_call("s3", "ListBuckets", {"MaxBuckets": 64})
    meter.authorize_parameters("s3", "ListBuckets", {"MaxBuckets": 64})
    operation, parameters = meter.wire_reservation("s3")
    assert operation == "ListBuckets" and parameters == {"MaxBuckets": 64}
    parameters["MaxBuckets"] = 1
    assert meter.wire_reservation("s3")[1] == {"MaxBuckets": 64}
    meter.authorize_wire_parameters("s3", "ListBuckets", {"MaxBuckets": 64})
    meter.before_send("s3")
    with pytest.raises(EvidenceError):
        meter.wire_reservation("s3")


@pytest.mark.parametrize(
    "mutation", ["missing", "early", "wrong_service", "wrong_params", "replay"]
)
def test_final_wire_binding_is_required_and_one_use(mutation):
    meter, _ = make()
    params = {"RoleName": "OfflineInspector"}
    meter.before_call("iam", "GetRole", params)
    if mutation != "early":
        meter.authorize_parameters("iam", "GetRole", params)
    with pytest.raises(EvidenceError):
        if mutation == "missing":
            meter.before_send("iam")
        elif mutation == "wrong_service":
            meter.wire_reservation("s3")
        elif mutation == "wrong_params":
            meter.authorize_wire_parameters("iam", "GetRole", {"RoleName": "Other"})
        elif mutation == "replay":
            meter.authorize_wire_parameters("iam", "GetRole", params)
            meter.authorize_wire_parameters("iam", "GetRole", params)
        else:
            meter.wire_reservation("iam")
    assert meter.public_dict()["state"] == "rejected"


def test_missing_wire_reservation_fails_closed():
    meter, _ = make()
    with pytest.raises(EvidenceError):
        meter.wire_reservation("sts")
