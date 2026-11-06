"""Independent acceptance for pending-only records and fictional capabilities."""

import copy
import json
import os
import pickle
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from pathlib import Path

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.capability import (
    CredentialCapabilityRef,
    OfflineSessionCapability,
)
from cloudsecops_live.integrations.aws_posture.contracts import (
    OwnerDecision,
    PolicyBinding,
    PostureClients,
    PostureRequest,
)
from tests.aws4a_helpers import NONCE, NOW, decision, identity, session


def test_disabled_request_contract_imports_without_sdk_or_site_dependencies():
    root = Path(__file__).resolve().parents[1] / "src"
    code = (
        "import sys;sys.path.insert(0," + repr(str(root)) + ");"
        "from cloudsecops_live.integrations.aws_posture.requests import PostureRequest;"
        "assert not any(n.startswith(('botocore','boto3')) for n in sys.modules);"
        "assert PostureRequest('a'*64,'b'*64).to_metadata()['schema_version']"
        "=='aws4a-posture-request/1'"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 0, "pure request bootstrap imported optional dependencies or failed"


def test_request_is_closed_reference_only_and_cannot_enable_execution():
    request = PostureRequest("a" * 64, NONCE)
    expected = {
        "schema_version": "aws4a-posture-request/1",
        "decision_ref": "a" * 64,
        "nonce": NONCE,
    }
    assert request.to_metadata() == expected
    assert PostureRequest.from_metadata(expected) == request
    assert PostureRequest.from_bytes(request.to_bytes()) == request
    assert "a" * 64 not in repr(request)
    with pytest.raises(FrozenInstanceError):
        request.nonce = "f" * 64


@pytest.mark.parametrize(
    "raw",
    [None, b"", b" " * 8193, b"{", b"\xff", b"NaN", b"[[[[", b'{"nonce":"a","nonce":"b"}'],
)
def test_request_wire_parser_is_bounded_and_rejects_unsupported_json(raw):
    with pytest.raises(EvidenceError, match="AWS4A_REQUEST"):
        PostureRequest.from_bytes(raw)


@pytest.mark.parametrize(
    "field",
    ["credentials", "access_key_id", "session_token", "endpoint", "operation", "worker", "live"],
)
def test_request_rejects_untrusted_credential_code_network_and_activation_fields(field):
    raw = PostureRequest("a" * 64, NONCE).to_metadata()
    raw[field] = "attacker-controlled-marker"
    with pytest.raises(EvidenceError, match="AWS4A_REQUEST") as failure:
        PostureRequest.from_metadata(raw)
    assert "attacker-controlled-marker" not in str(failure.value)


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"schema_version": "aws4a-posture-request/1"}])
def test_request_rejects_missing_and_wrong_shapes(bad):
    with pytest.raises(EvidenceError, match="AWS4A_REQUEST"):
        PostureRequest.from_metadata(bad)


def test_metadata_discriminators_and_pending_references_never_invoke_object_hooks():
    invoked = []

    class ForeignValue:
        def __eq__(self, other):
            invoked.append(other)
            return True

    foreign = ForeignValue()
    request = PostureRequest("a" * 64, NONCE).to_metadata()
    request["schema_version"] = foreign
    with pytest.raises(EvidenceError, match="AWS4A_REQUEST"):
        PostureRequest.from_metadata(request)
    for field in (
        "owner_ref",
        "custody_ref",
        "effective_iam_ref",
        "network_ref",
        "ca_sha256",
        "review_state",
    ):
        with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
            decision(**{field: foreign})
    for field in ("schema_version", "operations"):
        metadata = decision().to_metadata()
        metadata[field] = foreign
        with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
            OwnerDecision.from_metadata(metadata)
    assert not invoked


@pytest.mark.parametrize("field", ["decision_ref", "nonce"])
@pytest.mark.parametrize("value", [None, True, 1, "", "x" * 64, "A" * 64, "a" * 65, "../private"])
def test_request_identifiers_are_exact_bounded_hex_references(field, value):
    data = {"decision_ref": "a" * 64, "nonce": NONCE}
    data[field] = value
    with pytest.raises(EvidenceError, match="AWS4A_REQUEST"):
        PostureRequest(**data)


def test_owner_record_roundtrip_is_pending_even_with_complete_looking_references():
    record = decision()
    metadata = record.to_metadata()
    assert OwnerDecision.from_metadata(metadata) == record
    assert metadata["review_state"] == "pending"
    assert len(record.digest) == 64
    assert json.loads(json.dumps(metadata)) == metadata
    assert record.public_dict() == {
        "schema_version": "aws4a-owner-decision/1",
        "state": "pending_owner_review",
        "execution_enabled": False,
        "authenticated": False,
        "trusted_findings_available": False,
        "closure_available": False,
    }
    record.check(NOW)
    assert record.expected.role_arn not in repr(record)


@pytest.mark.parametrize("field", ["verified", "approved", "live", "credential_handle", "policy"])
def test_owner_record_never_promotes_caller_supplied_approval_or_policy_fields(field):
    data = decision().to_metadata()
    data[field] = True
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        OwnerDecision.from_metadata(data)


@pytest.mark.parametrize("state", [None, True, "approved", "verified", "enabled", "PENDING"])
def test_pending_state_cannot_be_reclassified(state):
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(review_state=state)


@pytest.mark.parametrize(
    "field,value",
    [
        ("record_id", "x" * 64),
        ("record_id", None),
        ("source_revision", "e" * 41),
        ("source_revision", "e" * 39),
        ("owner_ref", "https://unapproved.example"),
        ("custody_ref", "../private"),
        ("effective_iam_ref", True),
        ("network_ref", []),
        ("ca_sha256", ""),
        ("expected", object()),
        ("budget", {}),
        ("inline_policies", []),
        ("inline_policies", ()),
        ("inline_policies", (object(),)),
    ],
)
def test_owner_record_rejects_unbound_or_unsupported_fields(field, value):
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(**{field: value})


def test_pending_private_references_are_representable_without_inventing_approval():
    record = decision(
        owner_ref="pending",
        custody_ref="pending",
        effective_iam_ref="pending",
        network_ref="pending",
        ca_sha256="pending",
    )
    assert record.public_dict()["execution_enabled"] is False
    assert record.to_metadata()["ca_sha256"] == "pending"


def test_owner_record_scope_cannot_repurpose_a_collector_or_wrong_region():
    from cloudsecops_live.integrations.aws_readiness.sessions import Purpose

    # Deliberately bypass the old constructor only to simulate corrupt trusted state.
    for field, value in (("purpose", Purpose.COLLECTOR), ("region", "us-west-2")):
        expected = copy.copy(identity())
        object.__setattr__(expected, field, value)
        with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
            decision(expected=expected)


def test_pending_record_revalidates_corrupt_preconstructed_identity():
    expected = identity()
    object.__setattr__(expected, "account", True)
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(expected=expected)


@pytest.mark.parametrize(
    "start,end",
    [
        (NOW, NOW),
        (NOW, NOW - timedelta(seconds=1)),
        (NOW, NOW + timedelta(hours=1, microseconds=1)),
        (NOW.replace(tzinfo=None), NOW + timedelta(minutes=1)),
        (NOW, "later"),
    ],
)
def test_owner_window_requires_a_short_positive_utc_interval(start, end):
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(window_start=start, window_end=end)


@pytest.mark.parametrize("now", [NOW - timedelta(hours=1), NOW + timedelta(minutes=10), None])
def test_stale_future_and_unknown_owner_window_fail_closed(now):
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision().check(now)


@pytest.mark.parametrize(
    "name,digest",
    [
        ("", "a" * 64),
        ("bad/name", "a" * 64),
        ("x" * 129, "a" * 64),
        (True, "a" * 64),
        ("ok", "a" * 63),
        ("ok", "A" * 64),
    ],
)
def test_policy_bindings_require_exact_names_and_complete_hashes(name, digest):
    with pytest.raises(EvidenceError, match="AWS4A_POLICY_BINDING"):
        PolicyBinding(name, digest)


def test_duplicate_and_oversized_inline_policy_inventory_rejects():
    binding = PolicyBinding("OfflinePolicy", "a" * 64)
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(inline_policies=(binding, binding))
    with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
        decision(
            inline_policies=tuple(PolicyBinding("Policy" + str(n), "a" * 64) for n in range(9))
        )


def test_full_owner_record_changes_modify_its_binding_digest():
    record = decision()
    for changed in (
        replace(record, owner_ref="1" * 64),
        replace(record, custody_ref="2" * 64),
        replace(record, network_ref="3" * 64),
        replace(record, ca_sha256="4" * 64),
        replace(record, window_end=record.window_end - timedelta(seconds=1)),
        replace(record, inline_policies=(PolicyBinding("OtherPolicy", "a" * 64),)),
    ):
        assert changed.digest != record.digest


def test_malformed_owner_metadata_is_not_a_pending_record():
    for bad in (None, [], "json", {}, {"schema_version": "other"}):
        with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
            OwnerDecision.from_metadata(bad)
    for field, value in (
        ("window_start", "not-a-date"),
        ("window_start", None),
        ("budget", None),
        ("budget", {"max_calls": 1}),
        ("inline_policies", "invalid"),
        ("inline_policies", [{"name": "x", "sha256": "a" * 64, "verified": True}]),
    ):
        data = decision().to_metadata()
        data[field] = value
        with pytest.raises(EvidenceError, match="AWS4A_DECISION"):
            OwnerDecision.from_metadata(data)


def test_client_bundle_is_not_request_serializable_or_publicly_verbose():
    marker = "fake-client-private-marker"
    clients = PostureClients(marker, marker, marker, marker, marker)
    assert marker not in repr(clients)
    assert not hasattr(clients, "from_metadata")
    with pytest.raises(TypeError):
        json.dumps(clients)


def test_fictional_capability_is_one_use_scope_nonce_and_process_bound():
    record, bound = decision(), session()
    capability = OfflineSessionCapability(bound, record.digest, NONCE)
    assert capability.redeem(record, NONCE, NOW) is bound
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        capability.redeem(record, NONCE, NOW)
    assert bound.credentials.secret_key not in repr(capability)
    assert bound.credentials.token not in repr(capability)
    assert not hasattr(capability, "__dict__")


def test_concurrent_redemptions_have_exactly_one_winner():
    record, bound = decision(), session()
    capability = OfflineSessionCapability(bound, record.digest, NONCE)
    start = threading.Barrier(2)

    def redeem():
        start.wait(timeout=2)
        try:
            return capability.redeem(record, NONCE, NOW) is bound
        except EvidenceError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: redeem(), range(2)))
    assert sorted(outcomes) == [False, True]


def test_foreign_process_rejects_before_touching_an_inherited_lock(monkeypatch):
    record = decision()
    capability = OfflineSessionCapability(session(), record.digest, NONCE)
    original_pid = os.getpid()
    monkeypatch.setattr(
        "cloudsecops_live.integrations.aws_posture.capability.os.getpid", lambda: original_pid + 1
    )

    class InheritedLock:
        def __enter__(self):
            pytest.fail("foreign process attempted to acquire an inherited lock")

        def __exit__(self, *args):
            return False

    capability._lock = InheritedLock()
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        capability.redeem(record, NONCE, NOW)


@pytest.mark.parametrize(
    "mutation", ["nonce", "decision", "process", "expired", "identity", "material"]
)
def test_failed_capability_redemption_consumes_it_and_cannot_adopt_substitutions(
    monkeypatch, mutation
):
    record, bound = decision(), session()
    capability = OfflineSessionCapability(bound, record.digest, NONCE)
    actual_record, actual_nonce, now = record, NONCE, NOW
    if mutation == "nonce":
        actual_nonce = "f" * 64
    elif mutation == "decision":
        actual_record = replace(record, owner_ref="0" * 64)
    elif mutation == "process":
        original_pid = os.getpid()
        monkeypatch.setattr(
            "cloudsecops_live.integrations.aws_posture.capability.os.getpid",
            lambda: original_pid + 1,
        )
    elif mutation == "expired":
        now = NOW + timedelta(minutes=11)
    elif mutation == "identity":
        object.__setattr__(bound, "_expected", replace(record.expected, role_id="AROA" + "Z" * 17))
    else:
        bound.credentials.token = "fictional-substitution-marker"
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        capability.redeem(actual_record, actual_nonce, now)
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        capability.redeem(record, NONCE, NOW)


def test_capability_material_cannot_be_pickled_copied_or_serialized():
    capability = OfflineSessionCapability(session(), decision().digest, NONCE)
    for operation in (pickle.dumps, copy.copy, copy.deepcopy, lambda value: value.__getstate__()):
        with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
            operation(capability)
    with pytest.raises(TypeError):
        json.dumps(capability)
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        capability.__reduce__()


@pytest.mark.parametrize(
    "args", [(object(), "a" * 64, NONCE), (None, "a" * 64, NONCE), ("session", "x", NONCE)]
)
def test_capability_rejects_unsupported_session_and_binding_metadata(args):
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        OfflineSessionCapability(*args)


def test_real_credential_reference_is_metadata_only_and_has_no_redemption_path():
    reference = CredentialCapabilityRef(
        "a" * 64, decision().digest, NONCE, os.getpid(), NOW + timedelta(seconds=30)
    )
    assert not hasattr(reference, "redeem")
    assert reference.public_dict()["execution_enabled"] is False
    assert "a" * 64 not in repr(reference)
    assert not hasattr(reference, "__dict__")
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        pickle.dumps(reference)
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        reference.__getstate__()


@pytest.mark.parametrize(
    "field,value",
    [
        ("capability_id", "x"),
        ("decision_digest", None),
        ("nonce", True),
        ("owner_pid", True),
        ("owner_pid", 0),
        ("expires_at", None),
    ],
)
def test_capability_reference_rejects_unsupported_metadata(field, value):
    fields = {
        "capability_id": "a" * 64,
        "decision_digest": "b" * 64,
        "nonce": NONCE,
        "owner_pid": os.getpid(),
        "expires_at": NOW,
    }
    fields[field] = value
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY"):
        CredentialCapabilityRef(**fields)


def test_capability_rejects_nondata_nonce_before_any_comparison_hook():
    class Unsupported:
        def __ne__(self, other):
            raise AssertionError("comparison hook must not execute")

    record = decision()
    capability = OfflineSessionCapability(session(record), record.digest, NONCE)
    with pytest.raises(EvidenceError):
        capability.redeem(record, Unsupported(), NOW)
    with pytest.raises(EvidenceError, match="AWS4A_CAPABILITY_CONSUMED"):
        capability.redeem(record, NONCE, NOW)
