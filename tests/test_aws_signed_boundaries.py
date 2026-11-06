"""Bounded resource, chain-boundary and private-receipt acceptance expectations."""

import gzip
import json
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256

import pytest

from cloudsecops_live.integrations.aws_cloudtrail.signed import ChainAnchor, ChainSpec
from tests.aws4b_helpers import (
    END,
    START,
    bundle,
    digest_document,
    log_object,
    ref,
    sign_document,
)
from tests.test_aws_signed_verification import (
    assess,
    rejected,
    replace_digest,
    two_digest_bundle,
)
from tests.test_aws_signed_verification import (
    private_keys as private_keys,
)


def test_private_success_receipt_binds_plan_keys_and_signature_material(private_keys):
    value = bundle(private_keys[0])
    result = assess(value)
    assert result.plan == value.plan
    assert result.key_bindings == (
        (
            value.keys[0].fingerprint,
            value.keys[0].der_sha256,
            value.keys[0].valid_from,
            value.keys[0].valid_until,
        ),
    )
    binding = result.digests[0]
    assert (
        binding.signature_sha256
        == sha256(bytes.fromhex(dict(value.digests[0].metadata)["signature"])).hexdigest()
    )
    assert binding.key_sha256 == value.keys[0].der_sha256
    assert binding.key_time == END
    assert binding.chain == "standard"


@pytest.mark.parametrize("slot", ["plan", "scope", "standard", "anchor"])
def test_missing_structured_plan_never_raises_raw_exception(private_keys, slot):
    value = bundle(private_keys[0])
    if slot == "plan":
        value = value.replace(plan=None)
    elif slot == "anchor":
        value = value.replace(
            plan=replace(value.plan, standard=replace(value.plan.standard, anchor={}))
        )
    else:
        value = value.replace(plan=replace(value.plan, **{slot: None}))
    rejected(value)


@pytest.mark.parametrize(
    "end", [START, START - timedelta(seconds=1), START + timedelta(hours=24, seconds=1)]
)
def test_reversed_empty_and_overlong_intervals_reject(private_keys, end):
    value = bundle(private_keys[0])
    rejected(value.replace(plan=replace(value.plan, end=end)))


@pytest.mark.parametrize("head", [("wrong", "x", "v"), ("one",), None])
def test_invalid_head_or_unspecified_present_chain_rejects(private_keys, head):
    value = bundle(private_keys[0])
    rejected(value.replace(plan=replace(value.plan, standard=ChainSpec("standard", head))))


def test_missing_all_digests_and_missing_selected_chain_fail_closed(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(digests=()))
    fake = replace(value.plan, backfill=ChainSpec("backfill", value.plan.standard.head))
    rejected(value.replace(plan=fake))


def test_duplicate_log_object_is_ambiguous_not_additional_evidence(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(logs=value.logs * 2))


def test_two_valid_signed_digests_cannot_disagree_on_same_member(private_keys):
    value = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(value.digests[1].archive))
    doc["logFiles"][0]["s3Object"] = value.logs[0].reference.key
    doc["logFiles"][0]["hashValue"] = "0" * 64
    changed = sign_document(private_keys[0], doc)
    rejected(value.replace(digests=(value.digests[0], changed)))


def test_backfill_anchor_cannot_join_a_standard_chain(private_keys):
    value = two_digest_bundle(private_keys)
    first = value.digests[0]
    doc = json.loads(gzip.decompress(value.digests[1].archive))
    backfill_key = first.reference.key.replace(".json.gz", "_backfill.json.gz")
    doc["previousDigestS3Object"] = backfill_key
    second = sign_document(private_keys[0], doc)
    anchor = ChainAnchor(
        (first.reference.bucket, backfill_key, first.reference.version_id),
        sha256(gzip.decompress(first.archive)).hexdigest(),
        dict(first.metadata)["signature"],
        END,
    )
    plan = replace(value.plan, start=END, standard=replace(value.plan.standard, anchor=anchor))
    rejected(value.replace(plan=plan, digests=(second,), logs=value.logs[1:]))


@pytest.mark.parametrize("point", ["before", "after"])
def test_bad_anchor_time_or_missing_head_rejects(private_keys, point):
    value = two_digest_bundle(private_keys)
    first = value.digests[0]
    anchor = ChainAnchor(
        ref(first),
        sha256(gzip.decompress(first.archive)).hexdigest(),
        dict(first.metadata)["signature"],
        END + timedelta(seconds=1),
    )
    spec = replace(
        value.plan.standard,
        anchor=anchor,
        head=None if point == "before" else value.plan.standard.head,
    )
    rejected(value.replace(plan=replace(value.plan, standard=spec)))


def test_signed_duplicate_member_list_is_ambiguous(private_keys):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    doc["logFiles"] *= 2
    rejected(replace_digest(value, sign_document(private_keys[0], doc)))


@pytest.mark.parametrize(
    "mutation", ["algorithm", "times", "missing-time", "no-member", "null-member"]
)
def test_signed_unsupported_member_structures_reject(private_keys, mutation):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    member = doc["logFiles"][0]
    if mutation == "algorithm":
        member["hashAlgorithm"] = "MD5"
    elif mutation == "times":
        member.update(
            oldestEventTime="2026-01-01T02:00:00Z", newestEventTime="2026-01-01T01:00:00Z"
        )
    elif mutation == "missing-time":
        member.update(oldestEventTime="2026-01-01T02:00:00Z")
    elif mutation == "no-member":
        doc["logFiles"] = []
    else:
        doc["logFiles"] = None
    rejected(replace_digest(value, sign_document(private_keys[0], doc)))


def test_well_sized_invalid_der_is_sanitized(private_keys):
    value = bundle(private_keys[0])
    der = b"invalid supplied public key" * 10
    rejected(
        value.replace(keys=(replace(value.keys[0], der=der, der_sha256=sha256(der).hexdigest()),))
    )


def test_private_key_encoding_is_not_accepted_as_public_material(private_keys):
    # Do not serialize a private key: an arbitrary DER value of the supported size
    # must not pass merely because its custody hash was independently supplied.
    value = bundle(private_keys[0])
    der = b"\x30\x82" + b"x" * 512
    rejected(
        value.replace(keys=(replace(value.keys[0], der=der, der_sha256=sha256(der).hexdigest()),))
    )


def test_der_trailing_bytes_are_not_ignored(private_keys):
    value = bundle(private_keys[0])
    der = value.keys[0].der + b"trailing"
    rejected(
        value.replace(keys=(replace(value.keys[0], der=der, der_sha256=sha256(der).hexdigest()),))
    )


def test_signature_length_must_match_the_selected_key(private_keys):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    metadata = tuple((k, "0" * 768 if k == "signature" else v) for k, v in digest.metadata)
    rejected(replace_digest(value, replace(digest, metadata=metadata)))


def test_total_expansion_limit_rejects_otherwise_valid_signed_objects(private_keys):
    value = bundle(private_keys[0])
    content = b'{"Records":[]}' + b" " * (4 * 1024 * 1024 - len(b'{"Records":[]}'))
    logs = tuple(log_object(name=f"large-{i}", content=content) for i in range(5))
    doc = digest_document(value.keys[0], logs=logs)
    digest = sign_document(private_keys[0], doc)
    result = rejected(replace_digest(value.replace(logs=logs), digest))
    assert result.reason == "AWS4B_BUNDLE_LIMIT"
    assert result.logs == () and result.digests == ()


def test_total_record_count_is_bounded_across_multiple_signed_logs(private_keys):
    from tests.aws_helpers import event

    value = bundle(private_keys[0])
    template = event()
    template = {key: val for key, val in template.items() if key != "userIdentity"}
    records = [dict(template, eventID=f"00000000-0000-4000-8000-{i:012d}") for i in range(1000)]
    ten_logs = tuple(log_object(records, name=f"records-{i}") for i in range(10))
    digest = sign_document(private_keys[0], digest_document(value.keys[0], logs=ten_logs))
    accepted = assess(replace_digest(value.replace(logs=ten_logs), digest))
    assert accepted.state == "consistent"
    assert accepted.unique_events == 1000 and accepted.duplicate_events == 9000
    last = log_object([records[0]], name="one-over")
    logs = ten_logs + (last,)
    digest = sign_document(private_keys[0], digest_document(value.keys[0], logs=logs))
    result = rejected(replace_digest(value.replace(logs=logs), digest))
    assert result.reason == "AWS4B_BUNDLE_LIMIT"
    assert result.unique_events == 0 and result.logs == ()
