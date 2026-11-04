"""Data-only fixture execution preserves identity, source and purpose boundaries."""

from copy import deepcopy

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_readiness.requests import (
    CollectionRequest,
    PostureRequest,
    VerificationRequest,
    encode,
    utc,
)
from cloudsecops_live.integrations.aws_readiness.sessions import Purpose
from cloudsecops_live.integrations.aws_readiness.transport import ArchiveTransport
from cloudsecops_live.integrations.aws_readiness.workers import (
    _start,
    collect_archive,
    inspect_posture,
    verify_archive,
)
from tests.aws3_helpers import archive_metadata, posture_metadata


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("offline AWS3 fixture attempted network")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def test_empty_inventory_is_an_observation_without_invented_archive():
    result = inspect_posture(PostureRequest.from_metadata(posture_metadata()).to_metadata())
    assert result["trail_count"] == result["bucket_count"] == 0
    assert result["budget"]["calls"] == 8
    assert result["effective_permissions_verified"] is False
    assert result["policy_contents_verified"] is False
    assert result["requested_inline_policy_count"] == 1
    assert result["unrequested_inline_policy_count"] == 0
    assert result["identity_policy_review_required"] is False


def test_archive_collection_and_independent_verifier_recompute_hashes():
    result = collect_archive(CollectionRequest.from_metadata(archive_metadata()).to_metadata())
    assert result["object_count"] == 1
    assert result["unique_event_count"] == 1
    result = verify_archive(
        VerificationRequest.from_metadata(archive_metadata("verifier")).to_metadata()
    )
    assert result["controlled_fixture_consistency"] is True
    assert result["authenticated"] is False


def test_collector_preserves_conflicting_complete_record_variants():
    import base64

    from tests.aws_helpers import archive, event

    data = archive_metadata()
    raw = archive([event(), {**event(), "unknownCompleteRecordField": True}])
    data["tape"][1]["response"]["versions"][0]["size"] = len(raw)
    data["tape"][3]["response"]["reference"]["size"] = len(raw)
    data["tape"][3]["response"]["body_base64"] = base64.b64encode(raw).decode()
    result = collect_archive(data)
    assert result["conflict_count"] == 1
    assert result["state"] == "conflicting"
    assert result["authenticated"] is False


@pytest.mark.parametrize(
    "extra",
    [
        "worker",
        "module",
        "function",
        "path",
        "factory",
        "client",
        "endpoint",
        "command",
        "credentials",
        "authenticated",
    ],
)
def test_request_cannot_select_code_or_accept_raw_credentials(extra):
    data = posture_metadata()
    data[extra] = "forbidden"
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        PostureRequest.from_metadata(data)


@pytest.mark.parametrize(
    "operation",
    ["sts:AssumeRole", "s3:GetObject", "s3:HeadObject", "iam:PutRolePolicy", "custom:callback"],
)
def test_inspection_rejects_forbidden_operation_anywhere_before_execution(operation):
    data = posture_metadata()
    data["tape"][-1]["operation"] = operation
    with pytest.raises(EvidenceError, match="AWS3_TAPE"):
        PostureRequest.from_metadata(data)


@pytest.mark.parametrize(
    "change", ["deny", "wrong_identity", "extra_record", "wrong_parameters", "http_error"]
)
def test_denial_or_malformed_tape_cannot_become_empty_inventory(change):
    data = posture_metadata()
    if change == "deny":
        data["tape"][5]["fault"] = "deny"
    elif change == "wrong_identity":
        data["tape"][0]["response"]["UserId"] = "AROA" + "Z" * 17 + ":offline"
    elif change == "extra_record":
        data["tape"].append(deepcopy(data["tape"][-1]))
    elif change == "wrong_parameters":
        data["tape"][1]["parameters"]["RoleName"] = "Other"
    else:
        data["tape"][5]["response"]["ResponseMetadata"]["HTTPStatusCode"] = 403
    with pytest.raises(EvidenceError):
        inspect_posture(PostureRequest.from_metadata(data).to_metadata())


def test_changed_current_object_and_independent_hash_mismatch_fail_closed():
    data = archive_metadata()
    data["tape"][-1]["response"]["version_id"] = "replacement"
    with pytest.raises(EvidenceError, match="AWS_SOURCE_CHANGED"):
        collect_archive(CollectionRequest.from_metadata(data).to_metadata())
    data = archive_metadata("verifier")
    data["expected_content_hashes"] = ["0" * 64]
    with pytest.raises(EvidenceError, match="AWS3_CONSISTENCY"):
        verify_archive(VerificationRequest.from_metadata(data).to_metadata())


@pytest.mark.parametrize(
    "value",
    [
        object(),
        {1: "key"},
        {"secret_key": "forbidden"},  # pragma: allowlist secret - literal denial-test marker
        float("nan"),
        float("inf"),
        "x" * (512 * 1024),
        [None] * 30_001,
        10**5000,
    ],
    ids=["object", "nonstring-key", "secret", "nan", "inf", "size", "nodes", "huge-int"],
)
def test_exact_json_contract_rejects_unbounded_or_nondata_values(value):
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        encode(value)


def test_json_depth_and_utc_are_checked_before_worker_execution():
    value = []
    for _ in range(26):
        value = [value]
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        encode(value)
    for value in (None, "bad", "2026-01-01T00:00:00", "2026-01-01T00:00:00-05:00"):
        with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
            utc(value)


@pytest.mark.parametrize("kind", ["scalar", "aggregate", "fanout", "integer", "escaped"])
def test_json_preflight_rejects_large_input_before_encoder_allocation(monkeypatch, kind):
    if kind == "scalar":
        value = "x" * (512 * 1024 + 1)
    elif kind == "aggregate":
        value = ["x" * 200_000, "y" * 200_000, "z" * 200_000]
    elif kind == "fanout":
        value = {str(index): None for index in range(30_001)}
    elif kind == "integer":
        value = 1 << (512 * 1024 * 4)
    else:
        value = "\u2603" * 100_000

    def forbidden_encoder(*args, **kwargs):
        pytest.fail("JSON allocation occurred before bounded preflight rejection")

    monkeypatch.setattr(
        "cloudsecops_live.integrations.aws_readiness.requests.json.dumps", forbidden_encoder
    )
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        encode(value)


def test_json_preflight_preserves_escaping_scalar_types_and_exact_limit():
    import json

    value = {'escaped"key': ["\u2603\U0001f600\n\x00", None, True, False, -12, 1.5]}
    assert json.loads(encode(value)) == value
    assert len(encode("x" * (512 * 1024 - 2))) == 512 * 1024


@pytest.mark.parametrize(
    "change",
    [
        "fields",
        "budget_type",
        "budget_fields",
        "purpose",
        "names_type",
        "names_duplicate",
        "names_invalid",
        "names_limit",
        "tape_empty",
        "tape_type",
        "record_fields",
        "parameters_type",
        "response_type",
        "fault_unknown",
    ],
)
def test_request_and_tape_closed_schemas(change):
    data = posture_metadata()
    if change == "fields":
        del data["as_of"]
    elif change == "budget_type":
        data["budget"] = []
    elif change == "budget_fields":
        del data["budget"]["max_calls"]
    elif change == "purpose":
        data["expected"]["purpose"] = "collector"
        # A valid collector expectation remains invalid for a posture request.
        data["expected"] = archive_metadata()["expected"]
    elif change == "names_type":
        data["inline_policy_names"] = "not-list"
    elif change == "names_duplicate":
        data["inline_policy_names"] *= 2
    elif change == "names_invalid":
        data["inline_policy_names"] = ["*"]
    elif change == "names_limit":
        data["inline_policy_names"] = [f"policy{i}" for i in range(9)]
    elif change == "tape_empty":
        data["tape"] = []
    elif change == "tape_type":
        data["tape"] = {}
    elif change == "record_fields":
        data["tape"][0]["callback"] = "forbidden"
    elif change == "parameters_type":
        data["tape"][0]["parameters"] = []
    elif change == "response_type":
        data["tape"][0]["response"] = []
    else:
        data["tape"][0]["fault"] = "arbitrary"
    with pytest.raises(EvidenceError):
        PostureRequest.from_metadata(data)


@pytest.mark.parametrize(
    "change", ["scope_fields", "scope_binding", "checkpoint", "hashes_empty", "hashes_invalid"]
)
def test_archive_requests_require_exact_scope_and_independent_hash_expectations(change):
    data = archive_metadata("verifier")
    if change == "scope_fields":
        del data["scope"]["bucket"]
    elif change == "scope_binding":
        data["scope"]["role_id"] = "AROA" + "Z" * 17
    elif change == "checkpoint":
        data["checkpoint"] = "../escape"
    elif change == "hashes_empty":
        data["expected_content_hashes"] = []
    else:
        data["expected_content_hashes"] = ["malformed"]
    with pytest.raises(EvidenceError):
        VerificationRequest.from_metadata(data)


def test_request_raw_payload_must_be_canonical_and_is_immutable():
    for raw in (None, b"!", b" " + encode(posture_metadata()), b"x" * (512 * 1024 + 1)):
        with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
            PostureRequest(raw)
    request = PostureRequest.from_metadata(posture_metadata())
    with pytest.raises((AttributeError, TypeError)):
        request.to_metadata = lambda: {}
    data = request.to_metadata()
    data["tape"].clear()
    assert request.to_metadata()["tape"]


@pytest.mark.parametrize(
    "index,field,value",
    [
        (1, "Role", {"Arn": "wrong", "RoleId": "wrong"}),
        (2, "PolicyNames", []),
        (2, "PolicyNames", ["OfflineReviewedPolicy", "OfflineReviewedPolicy"]),
        (2, "PolicyNames", [{}]),
        (3, "PolicyDocument", []),
        (4, "AttachedPolicies", ["invalid"]),
        (5, "Trails", ["invalid"]),
        (6, "Buckets", ["invalid"]),
        (7, "PublicAccessBlockConfiguration", {}),
    ],
)
def test_malformed_posture_observations_fail_closed(index, field, value):
    data = posture_metadata()
    data["tape"][index]["response"][field] = value
    with pytest.raises(EvidenceError):
        inspect_posture(data)


def test_attached_policies_boundaries_and_discovered_resources_never_expand_reads():
    data = posture_metadata()
    data["tape"][1]["response"]["Role"]["PermissionsBoundary"] = {
        "PermissionsBoundaryArn": "metadata-only"
    }
    data["tape"][2]["response"]["PolicyNames"].append("UnapprovedPolicy")
    data["tape"][4]["response"]["AttachedPolicies"] = [{"PolicyArn": "metadata-only"}]
    data["tape"][5]["response"]["Trails"] = [{"TrailARN": "metadata-only"}]
    data["tape"][6]["response"]["Buckets"] = [{"Name": "metadata-only"}]
    result = inspect_posture(data)
    assert result["budget"]["calls"] == 8
    assert result["permissions_boundary_observed"] is True
    assert result["unrequested_inline_policy_count"] == 1
    assert result["discovered_resources_read"] is False
    assert result["identity_policy_review_required"] is True
    assert result["state"] == "owner_review_required"


@pytest.mark.parametrize("kind", ["inline", "attached", "boundary"])
def test_each_unreviewed_identity_policy_surface_requires_owner_review(kind):
    data = posture_metadata()
    if kind == "inline":
        data["tape"][2]["response"]["PolicyNames"].append("UnapprovedPolicy")
    elif kind == "attached":
        data["tape"][4]["response"]["AttachedPolicies"] = [{"PolicyArn": "metadata-only"}]
    else:
        data["tape"][1]["response"]["Role"]["PermissionsBoundary"] = {
            "PermissionsBoundaryArn": "metadata-only"
        }
    result = inspect_posture(data)
    assert result["state"] == "owner_review_required"
    assert result["identity_policy_review_required"] is True
    assert result["effective_permissions_verified"] is False
    assert result["budget"]["calls"] == 8


@pytest.mark.parametrize(
    "kind",
    ["missing", "nonlist", "too_many", "bad_token", "repeated_token", "mismatched_truncation"],
)
def test_incomplete_or_hostile_pagination_cannot_claim_complete_inventory(kind):
    data = posture_metadata()
    item = data["tape"][2]
    if kind == "missing":
        del item["response"]["IsTruncated"]
    elif kind == "nonlist":
        item["response"]["PolicyNames"] = {}
    elif kind == "too_many":
        item["response"]["PolicyNames"] = [str(i) for i in range(65)]
    elif kind == "mismatched_truncation":
        item["response"]["IsTruncated"] = True
    else:
        item["response"].update(IsTruncated=True, Marker="" if kind == "bad_token" else "again")
        if kind == "repeated_token":
            repeated = deepcopy(item)
            repeated["parameters"]["Marker"] = "again"
            data["tape"].insert(3, repeated)
    with pytest.raises(EvidenceError):
        inspect_posture(data)


def test_bounded_pagination_and_exact_retry_consume_shared_limits():
    data = posture_metadata()
    page = data["tape"][5]
    page["response"]["NextToken"] = "next-page"
    following = deepcopy(page)
    following["parameters"] = {"NextToken": "next-page"}
    del following["response"]["NextToken"]
    data["tape"].insert(6, following)
    failed = deepcopy(data["tape"][0])
    failed["fault"] = "retry"
    data["tape"].insert(0, failed)
    result = inspect_posture(data)
    assert result["budget"]["calls"] == 10
    assert result["budget"]["retries"] == 1


@pytest.mark.parametrize(
    "field,value",
    [("max_calls", 1), ("max_pages", 1), ("max_operations", 1), ("max_wire_bytes", 1)],
)
def test_shared_budget_failure_is_permanent(field, value):
    data = posture_metadata()
    data["budget"][field] = value
    with pytest.raises(EvidenceError, match="AWS3_BUDGET"):
        inspect_posture(data)


def test_retry_budget_and_credential_substitution_fail_closed():
    data = posture_metadata()
    data["budget"]["max_retries"] = 0
    data["tape"][0]["fault"] = "retry"
    with pytest.raises(EvidenceError, match="AWS3_BUDGET"):
        inspect_posture(data)
    data = posture_metadata()
    data["tape"][0]["fault"] = "substitute"
    with pytest.raises(EvidenceError):
        inspect_posture(data)


def test_transport_rejection_stays_rejected_and_deadline_does_not_reset(monkeypatch):
    data = posture_metadata()
    data["tape"][0]["fault"] = "deny"
    _, tape = _start(data, Purpose.POSTURE)
    with pytest.raises(EvidenceError, match="AWS3_FIXTURE_DENIED"):
        tape.identity()
    with pytest.raises(EvidenceError, match="AWS3_REJECTED"):
        tape.check()
    assert tape.public_dict()["state"] == "rejected"
    _, tape = _start(posture_metadata(), Purpose.POSTURE)
    monkeypatch.setattr(
        "cloudsecops_live.integrations.aws_readiness.transport.time.monotonic",
        lambda: tape._started + 31,
    )
    with pytest.raises(EvidenceError, match="AWS3_DEADLINE"):
        tape.check()


def test_fixed_stall_fault_remains_a_negative_result_after_interruption(monkeypatch):
    data = posture_metadata()
    data["tape"][0]["fault"] = "stall"
    waits = []
    monkeypatch.setattr(
        "cloudsecops_live.integrations.aws_readiness.transport.time.sleep", waits.append
    )
    with pytest.raises(EvidenceError, match="AWS3_DEADLINE"):
        inspect_posture(data)
    assert waits == [30]


@pytest.mark.parametrize(
    "change", ["versions_type", "truncated_type", "marker_type", "reference_fields"]
)
def test_archive_listing_schema_is_not_guessed(change):
    data = archive_metadata()
    response = data["tape"][1]["response"]
    if change == "versions_type":
        response["versions"] = {}
    elif change == "truncated_type":
        response["truncated"] = "false"
    elif change == "marker_type":
        response["next_marker"] = ["only-one"]
    else:
        del response["versions"][0]["last_modified"]
    with pytest.raises(EvidenceError):
        collect_archive(data)


def test_archive_scope_cannot_be_substituted_after_request_parsing():
    request, tape = _start(archive_metadata(), Purpose.COLLECTOR)
    transport = ArchiveTransport(tape, request.scope)
    with pytest.raises(EvidenceError, match="AWS3_SCOPE"):
        transport.list_versions(request.scope, "other-prefix/", None)
    from dataclasses import replace

    from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
    from tests.aws_helpers import BASE_TIME

    bad = ObjectVersion("other-bucket", "wrong-key", "v1", 1, BASE_TIME)
    with pytest.raises(EvidenceError, match="AWS3_SCOPE"):
        transport.head_current(bad)
    changed = replace(request.scope, role_id="AROA" + "Z" * 17)
    with pytest.raises(EvidenceError, match="AWS3_SCOPE"):
        transport.list_versions(changed, changed.log_prefix, None)


def test_archive_marker_pair_is_passed_without_changing_the_fixed_source():
    data = archive_metadata()
    listing = deepcopy(data["tape"][1])
    marker = (listing["response"]["versions"][0]["key"], "offline-v1")
    listing["parameters"].update(KeyMarker=marker[0], VersionIdMarker=marker[1])
    listing["response"].update(versions=[], next_marker=list(marker))
    data["tape"] = [listing]
    request, tape = _start(data, Purpose.COLLECTOR)
    page = ArchiveTransport(tape, request.scope).list_versions(
        request.scope, request.scope.log_prefix, marker
    )
    assert page.next_marker == marker


@pytest.mark.parametrize(
    "change",
    ["head_type", "body_type", "invalid_base64", "body_overflow", "owner_type", "reference_fields"],
)
def test_archive_body_and_metadata_must_match_existing_collection_contract(change):
    data = archive_metadata()
    if change == "head_type":
        data["tape"][2]["response"]["version_id"] = None
    elif change == "body_type":
        data["tape"][3]["response"]["body_base64"] = []
    elif change == "invalid_base64":
        data["tape"][3]["response"]["body_base64"] = "%invalid%"
    elif change == "body_overflow":
        data["tape"][3]["response"]["body_base64"] *= 2
    elif change == "owner_type":
        data["tape"][3]["response"]["owner_account"] = None
    else:
        del data["tape"][3]["response"]["reference"]["version_id"]
    with pytest.raises(EvidenceError):
        collect_archive(data)


def test_direct_archive_body_reader_requires_the_reserved_object_bound():
    from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
    from tests.aws_helpers import BASE_TIME

    data = archive_metadata()
    item = data["tape"][3]
    reference = item["response"]["reference"]
    ref = ObjectVersion(
        reference["bucket"], reference["key"], reference["version_id"], reference["size"], BASE_TIME
    )
    data["tape"] = [item]
    request, tape = _start(data, Purpose.COLLECTOR)
    with pytest.raises(EvidenceError, match="AWS3_FIXTURE_RESPONSE"):
        ArchiveTransport(tape, request.scope).get_object(ref, ref.size)
