"""Literal expected posture outcomes; no real clients, credentials or AWS calls."""

import copy
import hashlib
import json
from dataclasses import replace
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.contracts import PostureClients
from cloudsecops_live.integrations.aws_posture.engine import inspect_posture
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy
from tests.aws4a_helpers import NOW, decision, policy_document, session


def response(**values):
    return {**values, "ResponseMetadata": {"HTTPStatusCode": 200, "RetryAttempts": 0}}


class FakeService:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def _read(self, method, params):
        self.calls.append((method, dict(params)))
        value = self.responses[method]
        if type(value) is list:
            value = value.pop(0)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def get_caller_identity(self, **params):
        return self._read("get_caller_identity", params)

    def get_role(self, **params):
        return self._read("get_role", params)

    def list_role_policies(self, **params):
        return self._read("list_role_policies", params)

    def get_role_policy(self, **params):
        return self._read("get_role_policy", params)

    def list_attached_role_policies(self, **params):
        return self._read("list_attached_role_policies", params)

    def list_trails(self, **params):
        return self._read("list_trails", params)

    def list_buckets(self, **params):
        return self._read("list_buckets", params)

    def get_public_access_block(self, **params):
        return self._read("get_public_access_block", params)


def make():
    owner = decision()
    bound = session(owner)
    role = owner.expected.role_arn.rsplit("/", 1)[-1]
    sts = FakeService(
        {
            "get_caller_identity": response(
                Account=owner.expected.account,
                Arn=bound.lease.principal_arn,
                UserId=bound.lease.user_id,
            )
        }
    )
    iam = FakeService(
        {
            "get_role": response(
                Role={
                    "Arn": owner.expected.role_arn,
                    "RoleId": owner.expected.role_id,
                    "RoleName": role,
                }
            ),
            "list_role_policies": response(
                PolicyNames=[owner.inline_policies[0].name], IsTruncated=False
            ),
            "get_role_policy": response(
                RoleName=role,
                PolicyName=owner.inline_policies[0].name,
                PolicyDocument=policy_document(),
            ),
            "list_attached_role_policies": response(AttachedPolicies=[], IsTruncated=False),
        }
    )
    trail = FakeService({"list_trails": response(Trails=[])})
    s3 = FakeService({"list_buckets": response(Buckets=[])})
    control = FakeService(
        {
            "get_public_access_block": response(
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            )
        }
    )
    return owner, bound, PostureClients(sts, iam, trail, s3, control)


def run(owner, bound, clients, **options):
    return inspect_posture(
        owner, bound, clients, clock=lambda: NOW, monotonic=lambda: 1.0, **options
    )


def test_empty_inventory_is_an_unverified_observation_and_account_call_is_exact():
    owner, bound, clients = make()
    observed = run(owner, bound, clients)
    assert observed["trail_count"] == 0 and observed["bucket_count"] == 0
    assert observed["authenticated"] is False
    assert observed["trusted_findings_available"] is False
    assert observed["closure_available"] is False
    assert observed["effective_permissions_verified"] is False
    assert observed["execution_state"] == "disabled"
    assert clients.s3control.calls == [
        ("get_public_access_block", {"AccountId": owner.expected.account})
    ]
    assert clients.s3.calls == [("list_buckets", {"MaxBuckets": 64})]
    public = json.dumps(observed)
    assert owner.expected.account not in public
    assert owner.expected.role_id not in public
    assert owner.expected.role_arn not in public
    assert "PolicyDocument" not in public
    assert observed["budget"]["calls"] == 13


@pytest.mark.parametrize("field", ["Account", "Arn", "UserId"])
@pytest.mark.parametrize("late", [False, True])
def test_wrong_sts_identity_including_late_substitution_is_rejected(field, late):
    owner, bound, clients = make()
    good = clients.sts.responses["get_caller_identity"]
    bad = copy.deepcopy(good)
    bad[field] = "wrong-private-identity"
    clients.sts.responses["get_caller_identity"] = [good, bad] if late else bad
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


@pytest.mark.parametrize("field", ["Arn", "RoleId", "RoleName", "PermissionsBoundary"])
@pytest.mark.parametrize("late", [False, True])
def test_role_recreation_or_boundary_drift_rejects(field, late):
    owner, bound, clients = make()
    good = clients.iam.responses["get_role"]
    bad = copy.deepcopy(good)
    bad["Role"][field] = "changed-private-role"
    clients.iam.responses["get_role"] = [good, bad] if late else bad
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


@pytest.mark.parametrize(
    "change",
    ["missing", "all_false", "partial_false", "nonbool", "extra", "error", "status", "no_metadata"],
)
def test_account_bpa_never_falls_back_or_accepts_ambiguous_configuration(change):
    owner, bound, clients = make()
    result = clients.s3control.responses["get_public_access_block"]
    value = result["PublicAccessBlockConfiguration"]
    if change == "missing":
        del value["BlockPublicAcls"]
    elif change == "all_false":
        result["PublicAccessBlockConfiguration"] = dict.fromkeys(value, False)
    elif change == "partial_false":
        value["BlockPublicAcls"] = False
    elif change == "nonbool":
        value["BlockPublicAcls"] = 1
    elif change == "extra":
        value["verified"] = True
    elif change == "error":
        result["Error"] = {"Code": "AccessDenied"}
    elif change == "status":
        result["ResponseMetadata"]["HTTPStatusCode"] = 403
    else:
        del result["ResponseMetadata"]
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
    assert len(clients.s3control.calls) == 1
    assert all(name == "list_buckets" for name, _ in clients.s3.calls)


def test_access_denied_is_permanent_and_payload_text_never_becomes_error_receipt():
    owner, bound, clients = make()
    clients.s3control.responses["get_public_access_block"] = ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": "private-canary-do-not-print"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        "GetPublicAccessBlock",
    )
    with pytest.raises(EvidenceError) as failure:
        run(owner, bound, clients)
    assert "private-canary" not in str(failure.value)
    assert len(clients.s3control.calls) == 1


def test_explicit_throttle_retry_is_counted_once_and_internal_retries_reject():
    owner, bound, clients = make()
    good = clients.cloudtrail.responses["list_trails"]
    clients.cloudtrail.responses["list_trails"] = [
        ClientError(
            {"Error": {"Code": "ThrottlingException"}, "ResponseMetadata": {"HTTPStatusCode": 400}},
            "ListTrails",
        ),
        good,
    ]
    observed = run(owner, bound, clients)
    assert observed["budget"]["retries"] == 1
    assert observed["budget"]["calls"] == 14
    owner, bound, clients = make()
    clients.sts.responses["get_caller_identity"]["ResponseMetadata"]["RetryAttempts"] = 1
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


@pytest.mark.parametrize(
    "change",
    [
        "new_name",
        "missing_name",
        "changed_document",
        "late_document",
        "wrong_role",
        "wrong_name",
        "attached",
    ],
)
def test_unknown_or_forged_policy_observation_rejects_without_widening_reads(change):
    owner, bound, clients = make()
    if change == "new_name":
        clients.iam.responses["list_role_policies"]["PolicyNames"].append("Unapproved")
    elif change == "missing_name":
        clients.iam.responses["list_role_policies"]["PolicyNames"] = []
    elif change in ("changed_document", "late_document"):
        good = clients.iam.responses["get_role_policy"]
        bad = copy.deepcopy(good)
        bad["PolicyDocument"]["UnknownSourceField"] = True
        clients.iam.responses["get_role_policy"] = [good, bad] if change == "late_document" else bad
    elif change == "wrong_role":
        clients.iam.responses["get_role_policy"]["RoleName"] = "Other"
    elif change == "wrong_name":
        clients.iam.responses["get_role_policy"]["PolicyName"] = "Other"
    else:
        clients.iam.responses["list_attached_role_policies"]["AttachedPolicies"] = [
            {"PolicyName": "Admin", "PolicyArn": "unused"}
        ]
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
    assert all(params.get("PolicyName") != "Unapproved" for _, params in clients.iam.calls)


def test_complete_bounded_pagination_uses_correct_service_tokens():
    owner, bound, clients = make()
    first = response(Buckets=[], ContinuationToken="page-two")
    clients.s3.responses["list_buckets"] = [
        first,
        response(Buckets=[{"Name": "fictional-lab-bucket"}]),
    ]
    clients.cloudtrail.responses["list_trails"] = [
        response(Trails=[], NextToken="trail-page"),
        response(Trails=[]),
    ]
    value = run(owner, bound, clients)
    assert value["bucket_count"] == 1
    assert clients.s3.calls == [
        ("list_buckets", {"MaxBuckets": 64}),
        ("list_buckets", {"MaxBuckets": 64, "ContinuationToken": "page-two"}),
    ]
    assert clients.cloudtrail.calls == [
        ("list_trails", {}),
        ("list_trails", {"NextToken": "trail-page"}),
    ]


@pytest.mark.parametrize("bad", [None, "", 12, "a" * 1025, "bad\x00token"])
def test_truncated_or_invalid_iam_page_never_means_empty_success(bad):
    owner, bound, clients = make()
    clients.iam.responses["list_role_policies"] = response(
        PolicyNames=[], IsTruncated=True, Marker=bad
    )
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


@pytest.mark.parametrize(
    "kind", ["cycle", "duplicate", "overflow", "wrong_type", "missing_inventory"]
)
def test_inventory_incompleteness_conflicts_and_limits_reject(kind):
    owner, bound, clients = make()
    if kind == "cycle":
        clients.s3.responses["list_buckets"] = response(Buckets=[], ContinuationToken="again")
    elif kind == "duplicate":
        clients.s3.responses["list_buckets"] = response(
            Buckets=[{"Name": "same-bucket"}, {"Name": "same-bucket"}]
        )
    elif kind == "overflow":
        clients.s3.responses["list_buckets"] = response(
            Buckets=[{"Name": f"lab-bucket-{i}"} for i in range(65)]
        )
    elif kind == "wrong_type":
        clients.cloudtrail.responses["list_trails"] = response(Trails=["not-a-trail"])
    else:
        clients.s3.responses["list_buckets"] = response()
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_elapsed_identity_expiry_and_oversized_response_cannot_succeed():
    owner, bound, clients = make()
    with pytest.raises(EvidenceError):
        inspect_posture(
            owner, bound, clients, clock=lambda: NOW + timedelta(hours=1), monotonic=lambda: 1.0
        )
    owner, bound, clients = make()
    owner = replace(owner, budget=BudgetPolicy(max_wire_bytes=50))
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_bucket_permission_or_forged_approval_in_expected_policy_never_promotes_authority():
    owner, bound, clients = make()
    forged = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetBucketPublicAccessBlock", "Resource": "*"}
        ],
        "verified": True,
    }
    clients.iam.responses["get_role_policy"]["PolicyDocument"] = forged
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
    assert (
        hashlib.sha256(
            json.dumps(forged, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        != owner.inline_policies[0].sha256
    )


@pytest.mark.parametrize(
    "value",
    [
        object(),
        {1: "bad"},
        {"nul\x00key": True},
        "\ud800",
        "\x00",
        float("inf"),
        1 << 20_000,
        [None] * 30_001,
    ],
    ids=["object", "key_type", "nul_key", "surrogate", "nul", "nonfinite", "integer", "fanout"],
)
def test_unsupported_or_unbounded_sdk_values_are_rejected(value):
    from cloudsecops_live.integrations.aws_posture.engine import _json_value

    with pytest.raises(EvidenceError):
        _json_value(value)


def test_large_escaped_sdk_response_rejects_before_json_encoder_allocation(monkeypatch):
    from cloudsecops_live.integrations.aws_posture.engine import _json_value

    def forbidden(*args, **kwargs):
        pytest.fail("unbounded SDK response reached JSON encoder")

    monkeypatch.setattr("cloudsecops_live.integrations.aws_posture.engine.json.dumps", forbidden)
    with pytest.raises(EvidenceError):
        _json_value({"value": "\u2603" * 100_000})


def test_real_sdk_datetime_metadata_and_nonempty_inventory_are_supported():
    owner, bound, clients = make()
    clients.iam.responses["get_role"]["Role"]["CreateDate"] = NOW
    clients.cloudtrail.responses["list_trails"] = response(
        Trails=[
            {
                "TrailARN": (
                    f"arn:aws:cloudtrail:us-east-1:{owner.expected.account}:trail/offline-trail"
                ),
                "Name": "offline-trail",
                "HomeRegion": "us-east-1",
            }
        ]
    )
    clients.s3.responses["list_buckets"] = response(
        Buckets=[{"Name": "fictional-bucket", "CreationDate": NOW, "BucketRegion": "us-west-2"}],
        Owner={"ID": "fictional-owner"},
    )
    result = run(owner, bound, clients)
    assert result["trail_count"] == result["bucket_count"] == 1


@pytest.mark.parametrize(
    "change",
    [
        "foreign_trail",
        "trail_duplicate",
        "bad_trail",
        "bad_bucket",
        "unexpected_bucket",
        "bad_metadata",
        "bad_topfield",
        "bad_body",
    ],
)
def test_malformed_or_conflicting_inventory_and_response_shape_fail_closed(change):
    owner, bound, clients = make()
    if change == "foreign_trail":
        clients.cloudtrail.responses["list_trails"] = response(
            Trails=[{"TrailARN": "arn:aws:cloudtrail:us-east-1:" + "2" * 12 + ":trail/other"}]
        )
    elif change == "trail_duplicate":
        trail = {"TrailARN": f"arn:aws:cloudtrail:us-east-1:{owner.expected.account}:trail/same"}
        clients.cloudtrail.responses["list_trails"] = response(Trails=[trail, trail])
    elif change == "bad_trail":
        clients.cloudtrail.responses["list_trails"] = response(Trails=[{"unexpected": True}])
    elif change == "bad_bucket":
        clients.s3.responses["list_buckets"] = response(Buckets=["not-a-bucket"])
    elif change == "unexpected_bucket":
        clients.s3.responses["list_buckets"] = response(
            Buckets=[{"Name": "fictional-bucket", "verified": True}]
        )
    elif change == "bad_metadata":
        clients.sts.responses["get_caller_identity"]["ResponseMetadata"] = None
    elif change == "bad_topfield":
        clients.sts.responses["get_caller_identity"]["verified"] = True
    else:
        clients.sts.responses["get_caller_identity"] = []
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_generic_service_exception_is_sanitized_and_network_retry_is_bounded():
    from botocore.exceptions import ReadTimeoutError

    owner, bound, clients = make()
    clients.sts.responses["get_caller_identity"] = RuntimeError("private-canary")
    with pytest.raises(EvidenceError) as failure:
        run(owner, bound, clients)
    assert "private-canary" not in str(failure.value)
    owner, bound, clients = make()
    clients.sts.responses["get_caller_identity"] = ReadTimeoutError(
        endpoint_url="https://offline.invalid"
    )
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
    assert len(clients.sts.calls) == 3


def test_foreign_budget_or_client_bundle_cannot_be_substituted():
    from cloudsecops_live.integrations.aws_posture.budget import PostureBudget

    owner, bound, clients = make()
    with pytest.raises(EvidenceError):
        run(owner, bound, object())
    foreign = decision()
    meter = PostureBudget(foreign, session(foreign), clock=lambda: NOW, monotonic=lambda: 1.0)
    with pytest.raises(EvidenceError):
        run(owner, bound, clients, budget=meter)


def test_iam_false_truncation_with_marker_and_s3_explicit_null_token_reject():
    owner, bound, clients = make()
    clients.iam.responses["list_role_policies"]["Marker"] = "unjustified"
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
    owner, bound, clients = make()
    clients.s3.responses["list_buckets"]["ContinuationToken"] = None
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_response_container_depth_and_dictionary_fanout_are_bounded():
    from cloudsecops_live.integrations.aws_posture.engine import _json_value

    value = None
    for _ in range(26):
        value = [value]
    for supplied in (value, {str(i): None for i in range(30_001)}):
        with pytest.raises(EvidenceError):
            _json_value(supplied)


def test_explicit_null_iam_marker_is_ambiguous_even_when_not_truncated():
    owner, bound, clients = make()
    clients.iam.responses["list_role_policies"]["Marker"] = None
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_pinned_sdk_no_retry_metadata_is_accepted():
    owner, bound, clients = make()
    clients.sts.responses["get_caller_identity"]["ResponseMetadata"]["MaxAttemptsReached"] = True
    assert run(owner, bound, clients)["authenticated"] is False


@pytest.mark.parametrize("value", [1, "true", None])
def test_non_boolean_sdk_max_attempts_metadata_is_rejected(value):
    owner, bound, clients = make()
    clients.sts.responses["get_caller_identity"]["ResponseMetadata"]["MaxAttemptsReached"] = value
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)


def test_missing_sdk_retry_observation_cannot_establish_no_internal_retry():
    owner, bound, clients = make()
    del clients.sts.responses["get_caller_identity"]["ResponseMetadata"]["RetryAttempts"]
    with pytest.raises(EvidenceError):
        run(owner, bound, clients)
