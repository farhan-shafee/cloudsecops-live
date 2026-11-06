"""Supplied-input verification; no transport, credentials or database writes."""

from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from typing import Literal

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_cloudtrail.parsing import parse_aws_shaped
from cloudsecops_live.integrations.aws_cloudtrail.signed.contracts import (
    AcquiredObject,
    ChainAnchor,
    ChainSpec,
    ObjectBinding,
    Reference,
    SignedAssessment,
    SuppliedKey,
    VerificationPlan,
)
from cloudsecops_live.integrations.aws_cloudtrail.signed.crypto import key_bundle, verify_signature
from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import (
    LIMITS,
    Digest,
    hex_text,
    object_content,
    parse_digest,
    reference,
    safe_key,
    signature,
    utc,
)


def _reference(value: object, scope: AwsScope) -> Reference:
    if (
        type(value) is not tuple
        or len(value) != 3
        or not all(isinstance(x, str) and 1 <= len(x) <= 1024 for x in value)
        or value[0] != scope.bucket
        or value[2] == "null"
    ):
        raise EvidenceError("AWS4B_PLAN")
    safe_key(value[1], scope.digest_prefix)
    return value


def _plan(plan: VerificationPlan) -> None:
    if type(plan) is not VerificationPlan or type(plan.scope) is not AwsScope:
        raise EvidenceError("AWS4B_PLAN")
    plan.scope.__post_init__()
    if not timedelta(0) < utc(plan.end) - utc(plan.start) <= timedelta(hours=24):
        raise EvidenceError("AWS4B_PLAN")
    for kind, spec in (("standard", plan.standard), ("backfill", plan.backfill)):
        if type(spec) is not ChainSpec or spec.kind != kind:
            raise EvidenceError("AWS4B_PLAN")
        if spec.head is not None:
            _reference(spec.head, plan.scope)
        if spec.anchor is not None:
            anchor = spec.anchor
            if type(anchor) is not ChainAnchor or spec.head is None:
                raise EvidenceError("AWS4B_PLAN")
            _reference(anchor.reference, plan.scope)
            hex_text(anchor.content_sha256)
            signature(anchor.signature)
            if utc(anchor.end) > plan.start:
                raise EvidenceError("AWS4B_PLAN")
            # The supplied boundary anchor cannot splice another trail or chain.
            scope = plan.scope
            suffix = "_backfill" if kind == "backfill" else ""
            expected_key = (
                scope.digest_prefix
                + anchor.end.strftime("%Y/%m/%d/")
                + scope.account
                + "_CloudTrail-Digest_"
                + scope.region
                + "_"
                + scope.trail_arn.rsplit("/", 1)[1]
                + "_"
                + scope.region
                + "_"
                + anchor.end.strftime("%Y%m%dT%H%M%SZ")
                + suffix
                + ".json.gz"
            )
            if anchor.reference[1] != expected_key:
                raise EvidenceError("AWS4B_ANCHOR")


def _chain(spec: ChainSpec, items: list[Digest], plan: VerificationPlan) -> None:
    if spec.head is None:
        if items:
            raise EvidenceError("AWS4B_UNEXPECTED_CHAIN")
        return
    if not items:
        raise EvidenceError("AWS4B_CHAIN_MISSING")
    items.sort(key=lambda item: (item.end, reference(item.obj)))
    if reference(items[-1].obj) != spec.head:
        raise EvidenceError("AWS4B_HEAD")
    first, last = items[0], items[-1]
    if first.start > plan.start or last.end < plan.end:
        raise EvidenceError("AWS4B_COVERAGE")
    anchor = spec.anchor
    if anchor is None:
        if first.previous is not None:
            raise EvidenceError("AWS4B_CHAIN_MISSING")
    elif (
        first.previous
        != (anchor.reference[0], anchor.reference[1], anchor.content_sha256, anchor.signature)
        or first.start != anchor.end
    ):
        raise EvidenceError("AWS4B_ANCHOR")
    for older, newer in zip(items, items[1:], strict=False):
        expected = (
            older.obj.reference.bucket,
            older.obj.reference.key,
            older.content_sha256,
            older.signature,
        )
        if newer.previous != expected:
            raise EvidenceError("AWS4B_LINK")
        if older.end != newer.start:
            raise EvidenceError("AWS4B_COVERAGE")


def _verify(
    plan: VerificationPlan,
    keys: tuple[SuppliedKey, ...],
    digests: tuple[AcquiredObject, ...],
    logs: tuple[AcquiredObject, ...],
) -> SignedAssessment:
    _plan(plan)
    if (
        type(digests) is not tuple
        or type(logs) is not tuple
        or not 1 <= len(digests) <= 32
        or len(logs) > 32
    ):
        raise EvidenceError("AWS4B_BUNDLE_LIMIT")
    selected_keys = key_bundle(keys, plan.scope.region)
    parsed: list[Digest] = []
    seen_objects: set[tuple[str, str]] = set()
    expanded_bytes = 0
    for obj in digests:
        digest = parse_digest(obj, plan.scope)
        location = obj.reference.bucket, obj.reference.key
        if location in seen_objects:
            raise EvidenceError("AWS4B_OBJECT_CONFLICT")
        seen_objects.add(location)
        expanded_bytes += len(digest.content)
        if expanded_bytes > 16 * 1024 * 1024:
            raise EvidenceError("AWS4B_BUNDLE_LIMIT")
        verify_signature(digest, selected_keys)
        parsed.append(digest)
    _chain(plan.standard, [d for d in parsed if d.kind == "standard"], plan)
    _chain(plan.backfill, [d for d in parsed if d.kind == "backfill"], plan)
    membership: dict[tuple[str, str], str] = {}
    for digest in parsed:
        for member in digest.members:
            location = member.bucket, member.key
            if location in membership and membership[location] != member.content_sha256:
                raise EvidenceError("AWS4B_MEMBER_CONFLICT")
            membership[location] = member.content_sha256
    if len(membership) > 32:
        raise EvidenceError("AWS4B_BUNDLE_LIMIT")
    bindings: list[ObjectBinding] = []
    events: dict[tuple[str, str, str], str] = {}
    duplicates = records = 0
    supplied_locations: set[tuple[str, str]] = set()
    for obj in logs:
        content = object_content(obj)
        expanded_bytes += len(content)
        if expanded_bytes > 16 * 1024 * 1024:
            raise EvidenceError("AWS4B_BUNDLE_LIMIT")
        location = obj.reference.bucket, obj.reference.key
        if location in supplied_locations:
            raise EvidenceError("AWS4B_OBJECT_CONFLICT")
        supplied_locations.add(location)
        safe_key(obj.reference.key, plan.scope.log_prefix)
        if (
            obj.metadata != ()
            or obj.reference.bucket != plan.scope.bucket
            or membership.get(location) != sha256(content).hexdigest()
        ):
            raise EvidenceError("AWS4B_MEMBERSHIP")
        # Reparse actual retained bytes, never caller-constructed normalized data.
        log = parse_aws_shaped(obj.archive, plan.scope, limits=LIMITS)
        records += len(log.events)
        if records > 10_000:
            raise EvidenceError("AWS4B_BUNDLE_LIMIT")
        for event in log.events:
            if event.identity in events:
                if events[event.identity] != event.record_sha256:
                    raise EvidenceError("AWS4B_RECORD_CONFLICT")
                duplicates += 1
            else:
                events[event.identity] = event.record_sha256
        bindings.append(
            ObjectBinding(
                reference(obj),
                obj.archive_sha256,
                log.content_sha256,
                tuple(event.record_sha256 for event in log.events),
            )
        )
    if supplied_locations != membership.keys():
        raise EvidenceError("AWS4B_MEMBERSHIP_MISSING")
    return SignedAssessment(
        "consistent",
        "AWS4B_OFFLINE_CONSISTENT",
        tuple(
            sorted(
                (
                    ObjectBinding(
                        reference(d.obj),
                        d.obj.archive_sha256,
                        d.content_sha256,
                        chain=d.kind,
                        key_sha256=selected_keys[d.fingerprint][0].der_sha256,
                        signature_sha256=sha256(bytes.fromhex(d.signature)).hexdigest(),
                        key_time=d.key_time,
                    )
                    for d in parsed
                ),
                key=lambda b: b.reference,
            )
        ),
        tuple(sorted(bindings, key=lambda b: b.reference)),
        len(events),
        duplicates,
        plan.backfill.head is not None,
        plan,
        tuple(
            sorted(
                (key.fingerprint, key.der_sha256, key.valid_from, key.valid_until) for key in keys
            )
        ),
    )


def verify_bundle(
    plan: VerificationPlan,
    keys: tuple[SuppliedKey, ...],
    digests: tuple[AcquiredObject, ...],
    logs: tuple[AcquiredObject, ...],
) -> SignedAssessment:
    """Atomic bundle assessment. Fixed public failures, never partial acceptance.

    Key provenance, inventory completeness and acquisition truth are not proved by
    this operation. No result is accepted by an authenticated ingestion constructor.
    """
    try:
        return _verify(plan, keys, digests, logs)
    except EvidenceError as error:
        code = error.code if error.code.startswith("AWS4B_") else "AWS4B_SOURCE_FORMAT"
        state: Literal["invalid", "incomplete", "conflicting"]
        if "CONFLICT" in code:
            state = "conflicting"
        elif any(word in code for word in ("MISSING", "COVERAGE")):
            state = "incomplete"
        else:
            state = "invalid"
        return SignedAssessment(state, code)
