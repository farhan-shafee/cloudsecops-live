"""Independent cryptographic, custody and authority boundaries; zero AWS operations."""

import gzip
import json
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta, timezone
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import require_authenticated
from cloudsecops_live.integrations.aws_cloudtrail.signed import (
    ChainAnchor,
    ChainSpec,
    verify_bundle,
)
from tests.aws4b_helpers import (
    END,
    START,
    acquired,
    bundle,
    digest_document,
    log_object,
    ref,
    sign_document,
    stamp,
    supplied_key,
)
from tests.aws_helpers import event, scope


@pytest.fixture(scope="session")
def private_keys():
    # Ephemeral in-memory fictional signing identities; no private serialization.
    return tuple(rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2))


def assess(value):
    return verify_bundle(value.plan, value.keys, value.digests, value.logs)


def rejected(value):
    result = assess(value)
    assert result.state in {"invalid", "incomplete", "conflicting", "unsupported"}
    assert result.reason.startswith("AWS4B_") and len(result.reason) < 96
    assert result.authenticated is False
    assert result.trusted_findings is False
    assert result.may_close is False
    return result


def replace_digest(value, digest):
    standard = replace(value.plan.standard, head=ref(digest))
    return value.replace(digests=(digest,), plan=replace(value.plan, standard=standard))


def test_real_rsa_signature_and_signed_member_bytes_consistent_but_never_aws_authentic(
    private_keys,
):
    value = bundle(private_keys[0])
    result = assess(value)
    assert result.state == "consistent"
    assert result.unique_events == 1 and result.duplicate_events == 0
    assert len(result.digests) == 1 and len(result.logs) == 1
    assert result.authenticated is False
    assert result.trusted_findings is False and result.may_close is False
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)
    with pytest.raises(FrozenInstanceError):
        result.authenticated = True


def test_public_receipt_does_not_disclose_private_custody_identifiers(private_keys):
    value = bundle(private_keys[0])
    result = assess(value)
    public = json.dumps(result.public(), sort_keys=True)
    assert "false" in public and "consistent" in public
    for secret in (
        scope().account,
        scope().bucket,
        scope().trail_arn,
        value.digests[0].reference.key,
        value.digests[0].reference.version_id,
        value.keys[0].der_sha256,
        dict(value.digests[0].metadata)["signature"],
    ):
        assert secret not in public


@pytest.mark.parametrize("mutation", ["byte", "empty", "short", "nonhex", "algorithm"])
def test_tampered_or_unsupported_signature_never_passes(private_keys, mutation):
    value = bundle(private_keys[0])
    metadata = dict(value.digests[0].metadata)
    if mutation == "byte":
        metadata["signature"] = ("00" if metadata["signature"][:2] != "00" else "01") + metadata[
            "signature"
        ][2:]
    elif mutation == "empty":
        metadata["signature"] = ""
    elif mutation == "short":
        metadata["signature"] = "ab"
    elif mutation == "nonhex":
        metadata["signature"] = "z" * 512
    else:
        metadata["signature-algorithm"] = "SHA1withRSA"
    rejected(replace_digest(value, replace(value.digests[0], metadata=tuple(metadata.items()))))


@pytest.mark.parametrize("variation", ["pretty", "space", "newline", "unicode"])
def test_original_digest_bytes_are_not_reserialized_before_verification(private_keys, variation):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    doc = json.loads(gzip.decompress(digest.archive))
    if variation == "pretty":
        content = json.dumps(doc, indent=2).encode()
    elif variation == "space":
        content = b" " + gzip.decompress(digest.archive)
    elif variation == "newline":
        content = gzip.decompress(digest.archive) + b"\n"
    else:
        doc["digestPublicKeyFingerprint"] = "b" * 32
        content = json.dumps(doc).encode()
    modified = acquired(content, digest.reference.key, metadata=digest.metadata)
    rejected(replace_digest(value, modified))


def test_noncanonical_but_originally_signed_json_is_supported(private_keys):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    signed = sign_document(private_keys[0], doc, content=json.dumps(doc, indent=2).encode())
    assert assess(replace_digest(value, signed)).state == "consistent"


@pytest.mark.parametrize("bad_field", ["fingerprint", "region", "der", "der_sha256"])
def test_substituted_trusted_key_bindings_are_rejected(private_keys, bad_field):
    value = bundle(private_keys[0])
    key = value.keys[0]
    replacement = {
        "fingerprint": "b" * 32,
        "region": "us-west-2",
        "der": supplied_key(private_keys[1]).der,
        "der_sha256": "0" * 64,
    }[bad_field]
    rejected(value.replace(keys=(replace(key, **{bad_field: replacement}),)))


def test_attacker_key_with_consistent_custody_hash_cannot_verify_existing_signature(private_keys):
    value = bundle(private_keys[0])
    wrong = supplied_key(private_keys[1])
    rejected(value.replace(keys=(wrong,)))


@pytest.mark.parametrize("field", ["valid_from", "valid_until"])
def test_signing_key_outside_its_supplied_validity_interval_is_rejected(private_keys, field):
    value = bundle(private_keys[0])
    point = (
        END + timedelta(microseconds=1)
        if field == "valid_from"
        else END - timedelta(microseconds=1)
    )
    rejected(value.replace(keys=(replace(value.keys[0], **{field: point}),)))


def test_pkcs1_public_key_der_is_accepted_with_exact_independent_pin(private_keys):
    value = bundle(private_keys[0])
    der = (
        private_keys[0]
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    )
    key = replace(value.keys[0], der=der, der_sha256=sha256(der).hexdigest())
    assert assess(value.replace(keys=(key,))).state == "consistent"


@pytest.mark.parametrize("size", [1024])
def test_weak_rsa_key_is_rejected_even_with_valid_mathematical_signature(size):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=size)
    rejected(bundle(weak))


def two_digest_bundle(private_keys, *, rotation=False, kind="standard"):
    key1 = supplied_key(private_keys[0], fingerprint="a" * 32)
    key2 = supplied_key(private_keys[1], fingerprint="b" * 32)
    first_log = log_object(name="first")
    second_log = log_object([event("bbbbbbbb-bbbb-4ccc-8ddd-" + "e" * 12, 30)], name="second")
    first = sign_document(
        private_keys[0],
        digest_document(key1, logs=(first_log,), kind=kind),
        kind=kind,
    )
    second_end = END + timedelta(hours=1)
    second = sign_document(
        private_keys[1] if rotation else private_keys[0],
        digest_document(
            key2 if rotation else key1,
            start=END,
            end=second_end,
            logs=(second_log,),
            previous=first,
            kind=kind,
        ),
        kind=kind,
        generation=second_end,
    )
    value = bundle(private_keys[0])
    chain = ChainSpec(kind, ref(second))
    plan = replace(value.plan, end=second_end, **{kind: chain})
    if kind == "backfill":
        plan = replace(plan, standard=ChainSpec("standard", None))
    return value.replace(
        keys=(key1, key2) if rotation else (key1,),
        plan=plan,
        digests=(first, second),
        logs=(first_log, second_log),
    )


def test_rotation_uses_fingerprint_key_selection_and_validates_every_link(private_keys):
    value = two_digest_bundle(private_keys, rotation=True)
    result = assess(value)
    assert result.state == "consistent" and result.unique_events == 2
    assert len(result.digests) == 2
    rejected(value.replace(keys=value.keys[:1]))


def test_standard_and_backfill_chains_verified_independently(private_keys):
    standard = bundle(private_keys[0])
    backfill = bundle(private_keys[0], kind="backfill")
    plan = replace(standard.plan, backfill=backfill.plan.backfill)
    both = standard.replace(plan=plan, digests=standard.digests + backfill.digests)
    result = assess(both)
    assert result.state == "consistent" and len(result.digests) == 2
    assert result.unique_events == 1
    bad = replace(backfill.digests[0], metadata=())
    rejected(both.replace(digests=(standard.digests[0], bad)))


def test_backfill_key_selection_uses_generation_time_not_delivery_interval(private_keys):
    value = bundle(private_keys[0], kind="backfill")
    generation = END + timedelta(days=10)
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    key = replace(
        value.keys[0],
        valid_from=generation - timedelta(minutes=1),
        valid_until=generation + timedelta(minutes=1),
    )
    digest = sign_document(private_keys[0], doc, kind="backfill", generation=generation)
    result = assess(value.replace(keys=(key,), digests=(digest,)))
    assert result.state == "consistent"
    rejected(value.replace(keys=(key,)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("previousDigestHashValue", "0" * 64),
        ("previousDigestSignature", "0" * 512),
        ("previousDigestS3Bucket", "other-fictional-bucket"),
        ("previousDigestS3Object", "unrelated/key.json.gz"),
        ("previousDigestHashAlgorithm", "MD5"),
    ],
)
def test_signed_but_manipulated_previous_links_reject_whole_bundle(private_keys, field, value):
    chain = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(chain.digests[-1].archive))
    doc[field] = value
    second = sign_document(private_keys[0], doc)
    rejected(chain.replace(digests=(chain.digests[0], second)))


def test_missing_chain_member_cannot_be_replaced_by_valid_terminal_signature(private_keys):
    value = two_digest_bundle(private_keys)
    rejected(value.replace(digests=value.digests[1:]))


def test_unexpected_restart_does_not_cover_a_continuous_requested_interval(private_keys):
    value = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(value.digests[-1].archive))
    for key in tuple(doc):
        if key.startswith("previousDigest"):
            doc[key] = None
    restarted = sign_document(private_keys[0], doc)
    rejected(value.replace(digests=(value.digests[0], restarted)))


def test_signed_gap_in_delivery_intervals_is_incomplete(private_keys):
    value = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(value.digests[-1].archive))
    doc["digestStartTime"] = stamp(END + timedelta(seconds=1))
    second = sign_document(private_keys[0], doc)
    rejected(value.replace(digests=(value.digests[0], second)))


def test_signed_overlapping_intervals_are_not_silently_merged(private_keys):
    value = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(value.digests[-1].archive))
    doc["digestStartTime"] = stamp(END - timedelta(seconds=1))
    second = sign_document(private_keys[0], doc)
    rejected(value.replace(digests=(value.digests[0], second)))


def test_explicit_previous_anchor_binds_first_supplied_digest(private_keys):
    value = two_digest_bundle(private_keys)
    first = value.digests[0]
    anchor = ChainAnchor(
        ref(first),
        sha256(gzip.decompress(first.archive)).hexdigest(),
        dict(first.metadata)["signature"],
        END,
    )
    standard = replace(value.plan.standard, anchor=anchor)
    plan = replace(value.plan, start=END, standard=standard)
    anchored = value.replace(plan=plan, digests=value.digests[1:], logs=value.logs[1:])
    assert assess(anchored).state == "consistent"
    bad_anchor = replace(anchor, content_sha256="0" * 64)
    rejected(anchored.replace(plan=replace(plan, standard=replace(standard, anchor=bad_anchor))))


@pytest.mark.parametrize("drift", ["before", "after", "returned", "delete", "nonlatest", "time"])
def test_retained_version_continuity_must_match_for_every_object(private_keys, drift):
    value = bundle(private_keys[0])
    log = value.logs[0]
    if drift in {"before", "after"}:
        altered = replace(
            log, **{drift: replace(getattr(log, drift), version_id="changed-version")}
        )
    elif drift == "returned":
        altered = replace(log, reference=replace(log.reference, version_id="other-version"))
    elif drift == "delete":
        altered = replace(log, after=replace(log.after, is_delete_marker=True))
    elif drift == "nonlatest":
        altered = replace(log, before=replace(log.before, is_latest=False))
    else:
        altered = replace(log, observed_after=log.observed_before - timedelta(seconds=1))
    rejected(value.replace(logs=(altered,)))


@pytest.mark.parametrize(
    "target", ["archive", "content", "wrongkey", "wrongbucket", "missing", "extra"]
)
def test_exact_signed_log_membership_and_separate_hash_domains(private_keys, target):
    value = bundle(private_keys[0])
    log = value.logs[0]
    if target == "archive":
        altered = replace(log, archive_sha256=sha256(gzip.decompress(log.archive)).hexdigest())
    elif target == "content":
        altered = log_object([event(seconds=10)])
    elif target in {"wrongkey", "wrongbucket"}:
        reference = replace(
            log.reference,
            **(
                {"key": scope().log_prefix + "unrelated.json.gz"}
                if target == "wrongkey"
                else {"bucket": "other-fictional-bucket"}
            ),
        )
        altered = replace(log, reference=reference, before=reference, after=reference)
    elif target == "missing":
        rejected(value.replace(logs=()))
        return
    else:
        rejected(value.replace(logs=(log, log_object(name="unreferenced"))))
        return
    rejected(value.replace(logs=(altered,)))


def test_identical_event_duplicates_are_counted_once_without_trust_promotion(private_keys):
    value = bundle(private_keys[0], records=[event(), event()])
    result = assess(value)
    assert result.state == "consistent"
    assert result.unique_events == 1 and result.duplicate_events == 1


def test_full_record_changes_under_same_identity_conflict_even_when_normalization_would_discard(
    private_keys,
):
    left, right = event(), event()
    right["unknownDiscardedField"] = {"changed": True}
    rejected(bundle(private_keys[0], records=[left, right]))


def test_replay_for_different_expected_interval_or_head_is_rejected(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(plan=replace(value.plan, end=END + timedelta(seconds=1))))
    wrong_head = (scope().bucket, value.digests[0].reference.key, "different-approved-version")
    rejected(value.replace(plan=replace(value.plan, standard=ChainSpec("standard", wrong_head))))


@pytest.mark.parametrize(
    "kind", ["duplicate-object", "fork", "duplicate-key", "nul", "nan", "extra", "trust"]
)
def test_ambiguous_and_hostile_digest_evidence_rejects_before_acceptance(private_keys, kind):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    if kind == "duplicate-object":
        rejected(value.replace(digests=(digest, digest)))
        return
    if kind == "fork":
        changed = replace(digest, reference=replace(digest.reference, version_id="forked-version"))
        rejected(value.replace(digests=(digest, changed)))
        return
    doc = json.loads(gzip.decompress(digest.archive))
    if kind == "duplicate-key":
        raw = gzip.decompress(digest.archive).replace(
            b'{"awsAccountId":', b'{"awsAccountId":"bogus","awsAccountId":', 1
        )
    elif kind == "nul":
        doc["unknown"] = {"hostile\x00key": "hostile\x00value"}
        raw = json.dumps(doc).encode()
    elif kind == "nan":
        raw = gzip.decompress(digest.archive)[:-1] + b',"unknown":NaN}'
    elif kind == "extra":
        doc["newUnsupportedField"] = True
        raw = json.dumps(doc).encode()
    else:
        doc.update(authenticated=True, trusted_findings=True, may_close=True)
        raw = json.dumps(doc).encode()
    hostile = sign_document(private_keys[0], doc, content=raw)
    rejected(replace_digest(value, hostile))


@pytest.mark.parametrize("kind", ["missing", "duplicate", "generation-standard", "unrecognized"])
def test_signature_metadata_must_be_unambiguous_and_appropriate(private_keys, kind):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    metadata = list(digest.metadata)
    if kind == "missing":
        metadata = []
    elif kind == "duplicate":
        metadata += [metadata[0]]
    elif kind == "generation-standard":
        metadata += [("backfill-generation-timestamp", stamp(END))]
    else:
        metadata += [("authenticated", "true")]
    rejected(replace_digest(value, replace(digest, metadata=tuple(metadata))))


def test_wrong_digest_location_remains_invalid_even_when_resigned(private_keys):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    doc["digestS3Object"] = doc["digestS3Object"].replace("_offline-lab_", "_unapproved-trail_")
    rejected(replace_digest(value, sign_document(private_keys[0], doc)))


def test_wrong_account_in_signed_digest_remains_invalid(private_keys):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    doc["awsAccountId"] = "2" * 12
    rejected(replace_digest(value, sign_document(private_keys[0], doc)))


def test_repeated_and_reordered_bundle_has_identical_result(private_keys):
    value = two_digest_bundle(private_keys)
    result = assess(value)
    assert result == assess(value)
    assert result == assess(
        value.replace(digests=tuple(reversed(value.digests)), logs=tuple(reversed(value.logs)))
    )


def test_zero_key_bundle_and_duplicate_key_identity_fail_closed(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(keys=()))
    rejected(value.replace(keys=value.keys + value.keys))


def test_pss_signature_cannot_substitute_for_supported_pkcs1v15(private_keys):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    doc = json.loads(gzip.decompress(digest.archive))
    data = (
        doc["digestEndTime"]
        + "\n"
        + doc["digestS3Bucket"]
        + "/"
        + doc["digestS3Object"]
        + "\n"
        + sha256(gzip.decompress(digest.archive)).hexdigest()
        + "\nnull"
    ).encode()
    signature = (
        private_keys[0]
        .sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        .hex()
    )
    metadata = tuple(
        (key, signature if key == "signature" else val) for key, val in digest.metadata
    )
    rejected(replace_digest(value, replace(digest, metadata=metadata)))


def test_naive_and_non_utc_plan_timestamps_cannot_change_coverage_meaning(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(plan=replace(value.plan, start=START.replace(tzinfo=None))))
    rejected(
        value.replace(
            plan=replace(value.plan, start=START.astimezone(timezone(timedelta(hours=1))))
        )
    )


def test_digest_count_and_archive_size_limits_are_fail_closed(private_keys):
    value = bundle(private_keys[0])
    rejected(value.replace(digests=value.digests * 33))
    oversized = replace(value.digests[0], archive=b"a" * (1024 * 1024 + 1))
    rejected(replace_digest(value, oversized))


def test_gzip_bomb_is_rejected_without_unbounded_expansion(private_keys):
    value = bundle(private_keys[0])
    bomb = acquired(
        b"x" * (4 * 1024 * 1024 + 1),
        value.digests[0].reference.key,
        metadata=value.digests[0].metadata,
    )
    rejected(replace_digest(value, bomb))


@pytest.mark.parametrize("boundary", ["valid_from", "valid_until"])
def test_key_validity_exact_endpoint_is_supported(private_keys, boundary):
    value = bundle(private_keys[0])
    key = replace(value.keys[0], **{boundary: END})
    assert assess(value.replace(keys=(key,))).state == "consistent"


def test_non_rsa_public_key_is_not_accepted_as_a_trusted_rsa_identity(private_keys):
    value = bundle(private_keys[0])
    public = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    wrong = replace(value.keys[0], der=public, der_sha256=sha256(public).hexdigest())
    rejected(value.replace(keys=(wrong,)))


def test_wrong_rsa_exponent_is_unsupported_even_with_valid_signature():
    weak = rsa.generate_private_key(public_exponent=3, key_size=2048)
    rejected(bundle(weak))


@pytest.mark.parametrize("der", [b"", b"not a public key", b"\x30\x82\xff\xff"])
def test_malformed_der_fails_without_exposing_supplied_bytes(private_keys, der):
    value = bundle(private_keys[0])
    wrong = replace(value.keys[0], der=der, der_sha256=sha256(der).hexdigest())
    result = rejected(value.replace(keys=(wrong,)))
    assert "not a public key" not in json.dumps(result.public())


def test_compressed_previous_digest_hash_cannot_replace_content_hash(private_keys):
    value = two_digest_bundle(private_keys)
    doc = json.loads(gzip.decompress(value.digests[1].archive))
    doc["previousDigestHashValue"] = sha256(value.digests[0].archive).hexdigest()
    modified = sign_document(private_keys[0], doc)
    rejected(value.replace(digests=(value.digests[0], modified)))


def test_compressed_log_hash_cannot_replace_signed_content_hash(private_keys):
    value = bundle(private_keys[0])
    doc = json.loads(gzip.decompress(value.digests[0].archive))
    doc["logFiles"][0]["hashValue"] = value.logs[0].archive_sha256
    rejected(replace_digest(value, sign_document(private_keys[0], doc)))


@pytest.mark.parametrize(
    "slot", ["signature", "signature-algorithm", "backfill-generation-timestamp"]
)
def test_backfill_missing_critical_metadata_never_passes(private_keys, slot):
    value = bundle(private_keys[0], kind="backfill")
    digest = value.digests[0]
    missing = tuple(pair for pair in digest.metadata if pair[0] != slot)
    rejected(value.replace(digests=(replace(digest, metadata=missing),)))


@pytest.mark.parametrize(
    "generation", ["not-time", "2026-01-01T01:00:00", "2026-01-01T01:00:00+01:00"]
)
def test_backfill_invalid_generation_timestamp_is_rejected(private_keys, generation):
    value = bundle(private_keys[0], kind="backfill")
    digest = value.digests[0]
    metadata = tuple(
        (key, generation if key == "backfill-generation-timestamp" else val)
        for key, val in digest.metadata
    )
    rejected(value.replace(digests=(replace(digest, metadata=metadata),)))


@pytest.mark.parametrize("field", ["reference", "before", "after"])
def test_null_version_observations_are_not_version_specific_custody(private_keys, field):
    value = bundle(private_keys[0])
    log = value.logs[0]
    changed = replace(log, **{field: replace(getattr(log, field), version_id="null")})
    rejected(value.replace(logs=(changed,)))


def test_returned_object_size_cannot_be_forged_even_if_hash_matches(private_keys):
    value = bundle(private_keys[0])
    log = value.logs[0]
    reference = replace(log.reference, size=log.reference.size + 1)
    altered = replace(log, reference=reference, before=reference, after=reference)
    rejected(value.replace(logs=(altered,)))


@pytest.mark.parametrize(
    "raw", [b'{"Records":[]}', b'{"Records":[1]}', b'{"Records":[],"authenticated":true}']
)
def test_unrelated_log_payload_cannot_replace_expected_signed_log(private_keys, raw):
    value = bundle(private_keys[0])
    replacement = log_object(content=raw)
    rejected(value.replace(logs=(replacement,)))


def test_empty_records_can_be_cryptographically_bound_without_manufacturing_events(private_keys):
    value = bundle(private_keys[0], records=[])
    result = assess(value)
    assert result.state == "consistent"
    assert result.unique_events == 0 and result.duplicate_events == 0
    assert result.trusted_findings is False and result.may_close is False


def test_real_signature_can_bind_old_event_times_because_interval_is_delivery_time(private_keys):
    old = event()
    old["eventTime"] = "2025-12-31T23:30:00Z"
    old["userIdentity"]["sessionContext"]["attributes"]["creationDate"] = "2025-12-31T23:00:00Z"
    assert assess(bundle(private_keys[0], records=[old])).state == "consistent"


def test_no_ambient_sdk_or_socket_activity_is_required(private_keys, monkeypatch):
    import socket

    import boto3
    import botocore.session

    def forbidden(*args, **kwargs):
        raise AssertionError("AWS4B must remain fully offline")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(botocore.session, "get_session", forbidden)
    assert assess(bundle(private_keys[0])).state == "consistent"


def test_forged_authenticated_constructor_flags_are_not_supported(private_keys):
    value = bundle(private_keys[0])
    for target in (value.keys[0], value.digests[0], value.plan, value.plan.standard):
        with pytest.raises(TypeError):
            replace(target, authenticated=True)
    result = assess(value)
    for field in ("authenticated", "trusted_findings", "may_close"):
        # Python3.14 changed dataclasses.replace's init=False denial to TypeError.
        with pytest.raises((ValueError, TypeError)):
            replace(result, **{field: True})


def test_different_key_material_with_same_fingerprint_is_ambiguous(private_keys):
    value = bundle(private_keys[0])
    collision = supplied_key(private_keys[1])
    rejected(value.replace(keys=value.keys + (collision,)))


def test_replayed_signature_at_different_original_s3_location_is_invalid(private_keys):
    value = bundle(private_keys[0])
    digest = value.digests[0]
    reference = replace(
        digest.reference, key=digest.reference.key.replace("offline-lab_", "other-lab_")
    )
    moved = replace(digest, reference=reference, before=reference, after=reference)
    rejected(replace_digest(value, moved))


def test_unrecognized_chain_kind_cannot_relabel_standard_as_backfill(private_keys):
    value = bundle(private_keys[0])
    forged = replace(value.plan.standard, kind="backfill")
    rejected(value.replace(plan=replace(value.plan, standard=forged)))


def test_successful_receipt_has_no_approved_recommendation_or_case_interface(private_keys):
    result = assess(bundle(private_keys[0]))
    assert not hasattr(result, "recommendation_id")
    assert not hasattr(result, "case_id")
    assert not hasattr(result, "verified")
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)
