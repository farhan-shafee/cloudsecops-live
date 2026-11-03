"""Controlled test results are never AWS authentication receipts."""

from dataclasses import replace
from hashlib import sha256

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import require_authenticated
from cloudsecops_live.integrations.aws_cloudtrail.validation import (
    CheckOutcome,
    ControlledValidation,
    DigestMember,
    assess_digest,
)
from tests.test_aws_collection import FakeTransport, run


def fixture():
    batch = run()
    obj = batch.objects[0]
    member = DigestMember(
        obj.reference.bucket, obj.reference.key, obj.reference.version_id, obj.log.content_sha256
    )
    receipt = ControlledValidation(
        "aws-cli/fixture-only",
        0,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        (member,),
        True,
        True,
    )
    return obj, receipt


def test_consistent_fixture_checks_remain_pending_and_unusable_for_authentication():
    obj, receipt = fixture()
    result = assess_digest(obj, receipt)
    assert result.state == "pending_source_authentication"
    assert result.consistency_passed is True
    assert result.authenticated is False
    assert result.reason == "AWS_AUTHENTICATION_UNAVAILABLE"
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("exit_code", 1, "AWS_VALIDATION_COMMAND_FAILED"),
        ("signature", CheckOutcome.INVALID, "AWS_DIGEST_SIGNATURE_INVALID"),
        ("standard_chain", CheckOutcome.INVALID, "AWS_DIGEST_CHAIN_INVALID"),
        ("backfill_chain", CheckOutcome.INVALID, "AWS_DIGEST_CHAIN_INVALID"),
        ("standard_chain", CheckOutcome.PENDING, "AWS_DIGEST_PENDING"),
        ("backfill_chain", CheckOutcome.PENDING, "AWS_DIGEST_PENDING"),
        ("signature", CheckOutcome.PENDING, "AWS_DIGEST_PENDING"),
        ("complete", False, "AWS_VALIDATION_INCOMPLETE"),
        ("versions_unchanged", False, "AWS_SOURCE_CHANGED"),
        ("members", (), "AWS_DIGEST_MEMBERSHIP_MISSING"),
    ],
)
def test_missing_delayed_invalid_and_incomplete_evidence_never_passes(field, value, reason):
    obj, receipt = fixture()
    result = assess_digest(obj, replace(receipt, **{field: value}))
    assert result.reason == reason
    assert result.consistency_passed is False
    assert result.authenticated is False


def test_exact_member_location_version_and_content_hash_are_required():
    obj, receipt = fixture()
    member = receipt.members[0]
    for changed in [
        replace(member, bucket="unrelated-bucket"),
        replace(member, key="unrelated/log.json.gz"),
        replace(member, version_id="different-version"),
        replace(member, content_sha256=obj.log.archive_sha256),
        replace(member, content_sha256=sha256(b"changed").hexdigest()),
    ]:
        result = assess_digest(obj, replace(receipt, members=(changed,)))
        assert result.consistency_passed is False
        assert result.authenticated is False


def test_contradictory_members_are_explicit_conflicts():
    obj, receipt = fixture()
    conflict = replace(receipt.members[0], content_sha256=sha256(b"other").hexdigest())
    result = assess_digest(obj, replace(receipt, members=(*receipt.members, conflict)))
    assert result.state == "conflicting"
    assert result.reason == "AWS_DIGEST_MEMBERSHIP_CONFLICT"


@pytest.mark.parametrize("value", [None, {}, {"verified": True}, True])
def test_arbitrary_flags_and_json_receipts_cannot_promote_source(value):
    obj, _ = fixture()
    with pytest.raises(EvidenceError):
        assess_digest(obj, value)
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(value)


def test_public_output_has_no_source_location_or_account_material():
    fake = FakeTransport()
    result = run(fake)
    output = str(result.to_public_dict())
    for private in (
        fake.scope.account,
        fake.scope.bucket,
        fake.scope.role_arn,
        fake.scope.trail_arn,
        fake.ref.key,
        fake.identity.user_id,
    ):
        assert private not in output
