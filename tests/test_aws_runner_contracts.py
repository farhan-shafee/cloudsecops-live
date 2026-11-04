"""Run authorization and aggregate budgets use fictional offline observations only."""

from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import CallerIdentity
from cloudsecops_live.integrations.aws_runner.contracts import (
    BudgetPolicy,
    IdentityAuthorization,
    OperationBudget,
)
from cloudsecops_live.integrations.aws_sdk.transport import SessionLease
from tests.aws_helpers import BASE_TIME, scope


def authorization(**changes):
    expected = scope()
    values = {
        "scope": expected,
        "lease": SessionLease(
            BASE_TIME - timedelta(minutes=1),
            BASE_TIME + timedelta(minutes=5),
            f"arn:aws:sts::{expected.account}:assumed-role/OfflineCollector/offline",
            expected.role_id + ":offline",
            "ASIA" + "Q" * 16,
        ),
        "provenance": "owner_supplied_temporary_session",
    }
    values.update(changes)
    return IdentityAuthorization(**values)


def budget(policy=None, *, ticks=None, clock=None):
    ticks = [10.0] if ticks is None else ticks
    return OperationBudget(
        authorization(),
        policy or BudgetPolicy(),
        monotonic=lambda: ticks[0],
        clock=clock or (lambda: BASE_TIME),
    )


def listing(**changes):
    expected = scope()
    params = {
        "Bucket": expected.bucket,
        "Prefix": expected.log_prefix,
        "ExpectedBucketOwner": expected.account,
        "MaxKeys": 16,
    }
    params.update(changes)
    return params


def test_authorization_binds_immutable_identity_without_granting_source_trust():
    allowed = authorization()
    allowed.check(BASE_TIME)
    allowed.require_identity(
        CallerIdentity(
            scope().account,
            "us-east-1",
            allowed.lease.principal_arn,
            allowed.lease.user_id,
            BASE_TIME,
            allowed.lease.expires_at,
        ),
        BASE_TIME,
    )
    assert allowed.to_public_dict() == {
        "schema_version": "aws-run-authorization/1",
        "state": "offline_authorization_observation",
        "provenance": "owner_supplied_temporary_session",
        "authenticated": False,
        "trusted_findings_available": False,
        "closure_available": False,
    }
    with pytest.raises(FrozenInstanceError):
        allowed.provenance = "ambient"
    for private in (scope().account, "arn:aws:", "AROA", "ASIA"):
        assert private not in repr(allowed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal_arn", f"arn:aws:sts::{scope().account}:assumed-role/OfflineCollector/other"),
        ("user_id", "AROA" + "B" * 17 + ":offline"),
        ("user_id", "AROA" + "A" * 17 + ":x"),
        ("principal_arn", f"arn:aws:iam::{scope().account}:root"),
    ],
)
def test_unapproved_assumed_role_binding_is_rejected(field, value):
    allowed = authorization()
    with pytest.raises(EvidenceError, match="AWS_RUN_IDENTITY"):
        authorization(lease=replace(allowed.lease, **{field: value}))


@pytest.mark.parametrize("provenance", ["ambient", "default", "profile", None, True])
def test_only_owner_supplied_temporary_provenance_is_supported(provenance):
    with pytest.raises(EvidenceError, match="AWS_RUN_PROVENANCE"):
        authorization(provenance=provenance)


def test_authorization_requires_an_explicit_provenance_argument():
    allowed = authorization()
    with pytest.raises(TypeError):
        IdentityAuthorization(allowed.scope, allowed.lease)


@pytest.mark.parametrize("name", ["Administrator", "admin", "Root", "SecurityAdmin"])
def test_administrative_role_identifiers_are_rejected_defensively(name):
    expected = scope(role_arn=f"arn:aws:iam::{scope().account}:role/{name}")
    with pytest.raises(EvidenceError, match="AWS_RUN_IDENTITY"):
        authorization(scope=expected)


def test_region_and_lease_observation_are_explicit_and_bounded():
    expected = scope(
        region="us-west-2",
        trail_arn=f"arn:aws:cloudtrail:us-west-2:{scope().account}:trail/offline-lab",
        log_prefix=f"AWSLogs/{scope().account}/CloudTrail/us-west-2/",
        digest_prefix=f"AWSLogs/{scope().account}/CloudTrail-Digest/us-west-2/",
    )
    with pytest.raises(EvidenceError, match="AWS_RUN_IDENTITY"):
        authorization(scope=expected)
    allowed = authorization()
    for now in (allowed.lease.expires_at, allowed.lease.issued_at - timedelta(seconds=1)):
        with pytest.raises(EvidenceError, match="AWS_RUN_LEASE"):
            allowed.check(now)
    with pytest.raises(EvidenceError, match="AWS_RUN_TIME"):
        allowed.check(BASE_TIME.replace(tzinfo=None))
    with pytest.raises(EvidenceError, match="AWS_RUN_TIME"):
        allowed.check("private")


@pytest.mark.parametrize(
    "change",
    [
        {"account": "2" * 12},
        {"region": "us-west-2"},
        {"user_id": "forged"},
        {"arn": f"arn:aws:iam::{scope().account}:root"},
        {"observed_at": BASE_TIME - timedelta(seconds=61)},
        {"observed_at": BASE_TIME + timedelta(seconds=1)},
        {"expires_at": BASE_TIME + timedelta(hours=1)},
    ],
)
def test_identity_observation_cannot_change_approved_lease_or_identity(change):
    allowed = authorization()
    observed = CallerIdentity(
        scope().account,
        "us-east-1",
        allowed.lease.principal_arn,
        allowed.lease.user_id,
        BASE_TIME,
        allowed.lease.expires_at,
    )
    with pytest.raises(EvidenceError, match="AWS_RUN_IDENTITY"):
        allowed.require_identity(replace(observed, **change), BASE_TIME)


@pytest.mark.parametrize(
    "field,limit",
    [
        ("max_calls", 64),
        ("max_pages", 16),
        ("max_operations", 16),
        ("max_wire_bytes", 10 * 1024 * 1024),
        ("max_retries", 2),
    ],
)
@pytest.mark.parametrize("kind", ["bool", "float", "negative", "overflow"])
def test_budget_policy_has_strict_caps(field, limit, kind):
    value = {"bool": True, "float": 1.0, "negative": -1, "overflow": limit + 1}[kind]
    with pytest.raises(EvidenceError, match="AWS_RUN_LIMITS"):
        BudgetPolicy(**{field: value})


@pytest.mark.parametrize("seconds", [True, 0, -1, 30.01, float("nan"), float("inf"), "30"])
def test_hard_deadline_cannot_be_missing_nonfinite_or_extended(seconds):
    with pytest.raises(EvidenceError, match="AWS_RUN_LIMITS"):
        BudgetPolicy(deadline_seconds=seconds)


def test_huge_deadline_and_unstructured_dispatch_are_sanitized():
    with pytest.raises(EvidenceError, match="AWS_RUN_LIMITS"):
        BudgetPolicy(deadline_seconds=10**1000)
    run = budget()
    with pytest.raises(EvidenceError, match="AWS_RUN_OPERATION"):
        run.reserve_attempt([], "GetCallerIdentity", {})


def test_sts_and_failed_source_attempts_consume_shared_call_budget():
    run = budget(BudgetPolicy(max_calls=2))
    run.reserve_attempt("sts", "GetCallerIdentity", {})
    run.reserve_attempt("s3", "ListObjectVersions", listing())
    with pytest.raises(EvidenceError, match="AWS_RUN_CALL_LIMIT"):
        run.reserve_attempt("sts", "GetCallerIdentity", {})
    assert run.to_public_dict()["calls"] == 2
    assert run.to_public_dict()["pages"] == 1


def test_operations_pages_retries_and_wire_bytes_have_aggregate_limits():
    run = budget(BudgetPolicy(max_operations=1))
    run.begin_operation()
    with pytest.raises(EvidenceError, match="AWS_RUN_OPERATION_LIMIT"):
        run.begin_operation()
    run = budget(BudgetPolicy(max_pages=1))
    run.reserve_attempt("s3", "ListObjectVersions", listing(), retry=True)
    with pytest.raises(EvidenceError, match="AWS_RUN_PAGE_LIMIT"):
        run.reserve_attempt("s3", "ListObjectVersions", listing())
    run = budget(BudgetPolicy(max_retries=1))
    run.reserve_attempt("sts", "GetCallerIdentity", {}, retry=True)
    with pytest.raises(EvidenceError, match="AWS_RUN_RETRY_LIMIT"):
        run.reserve_attempt("sts", "GetCallerIdentity", {}, retry=True)
    run = budget(BudgetPolicy(max_wire_bytes=7))
    run.consume_wire_bytes(3)
    run.consume_wire_bytes(4)
    with pytest.raises(EvidenceError, match="AWS_RUN_BYTE_LIMIT"):
        run.consume_wire_bytes(1)
    assert run.to_public_dict()["wire_bytes"] == 7


def test_rejection_and_explicit_invalidation_prevent_reusing_the_run():
    run = budget(BudgetPolicy(max_calls=1))
    run.reserve_attempt("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError, match="AWS_RUN_CALL_LIMIT"):
        run.reserve_attempt("sts", "GetCallerIdentity", {})
    with pytest.raises(EvidenceError, match="AWS_RUN_REJECTED"):
        run.consume_wire_bytes(1)
    clean = budget()
    clean.invalidate()
    with pytest.raises(EvidenceError, match="AWS_RUN_REJECTED"):
        clean.begin_operation()
    assert clean.to_public_dict()["state"] == "rejected"


@pytest.mark.parametrize("count", [True, 1.0, -1, "1"])
def test_wire_byte_accounting_rejects_invalid_counts(count):
    with pytest.raises(EvidenceError, match="AWS_RUN_BYTE_LIMIT"):
        budget().consume_wire_bytes(count)


@pytest.mark.parametrize(
    "service,operation,params",
    [
        ("sts", "AssumeRole", {}),
        ("iam", "GetRole", {}),
        ("s3", "DeleteObject", {}),
        ("sts", "GetCallerIdentity", {"extra": "private"}),
        ("s3", "ListObjectVersions", listing(Bucket="foreign-bucket")),
        ("s3", "ListObjectVersions", listing(ExpectedBucketOwner="2" * 12)),
        ("s3", "ListObjectVersions", listing(Prefix="")),
        ("s3", "ListObjectVersions", listing(MaxKeys=65)),
        ("s3", "ListObjectVersions", listing(KeyMarker="orphan")),
        ("cloudtrail", "GetTrail", {"Name": "foreign"}),
        ("cloudtrail", "GetTrailStatus", {"Name": scope().trail_arn, "extra": True}),
    ],
)
def test_only_exact_source_scoped_read_operations_can_reserve_dispatch(service, operation, params):
    run = budget()
    with pytest.raises(EvidenceError):
        run.reserve_attempt(service, operation, params)
    assert run.to_public_dict()["calls"] == 0


@pytest.mark.parametrize(
    "operation,params",
    [
        ("GetTrail", {"Name": scope().trail_arn}),
        ("GetTrailStatus", {"Name": scope().trail_arn}),
        ("GetEventSelectors", {"TrailName": scope().trail_arn}),
        ("GetInsightSelectors", {"TrailName": scope().trail_arn}),
    ],
)
def test_approved_trail_reads_use_exact_trail(operation, params):
    run = budget()
    run.reserve_attempt("cloudtrail", operation, params)
    assert run.to_public_dict()["calls"] == 1


@pytest.mark.parametrize("operation", ["HeadObject", "GetObject"])
def test_object_reads_require_exact_owner_prefix_and_version_contract(operation):
    params = {
        "Bucket": scope().bucket,
        "ExpectedBucketOwner": scope().account,
        "Key": scope().log_prefix + "2026/01/01/log.json.gz",
    }
    if operation == "GetObject":
        params["VersionId"] = "v-one"
    run = budget()
    run.reserve_attempt("s3", operation, params)
    for change in (
        {"Key": scope().log_prefix + "../log.json.gz"},
        {"Key": "foreign/log.json.gz"},
        {"VersionId": "null"},
    ):
        with pytest.raises(EvidenceError):
            run.reserve_attempt("s3", operation, {**params, **change})
    if operation == "GetObject":
        params.pop("VersionId")
        with pytest.raises(EvidenceError):
            run.reserve_attempt("s3", operation, params)


@pytest.mark.parametrize("next_tick", [9.0, 40.0, float("nan"), float("inf"), True, "11"])
def test_monotonic_deadline_rejects_regression_expiry_and_invalid_clock(next_tick):
    ticks = [10.0]
    run = budget(ticks=ticks)
    ticks[0] = next_tick
    with pytest.raises(EvidenceError, match="AWS_RUN_DEADLINE"):
        run.reserve_attempt("sts", "GetCallerIdentity", {})
    assert run.to_public_dict()["calls"] == 0


def test_budget_checks_temporary_session_expiry_on_each_accounting_boundary():
    now = [BASE_TIME]
    run = budget(clock=lambda: now[0])
    now[0] += timedelta(minutes=6)
    with pytest.raises(EvidenceError, match="AWS_RUN_LEASE"):
        run.consume_wire_bytes(1)
    assert run.to_public_dict()["wire_bytes"] == 0
