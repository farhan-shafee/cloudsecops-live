"""Literal scenarios for a checker that does not use detector output as its oracle."""

from __future__ import annotations

import gzip
import json
from copy import deepcopy
from datetime import datetime
from decimal import Decimal
from hashlib import sha256

import pytest

from cloudsecops_live.independent_verifier import source_digest, verify_snapshot
from tests.helpers import archive, event


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def snapshot(records, *, claimed=None, extra_records=()):
    """Build input claims independently; test assertions supply expected answers."""
    selected = records if claimed is None else claimed
    session = {
        "account": "LABACCOUNT_A",
        "region": "us-east-1",
        "issuer_arn": "arn:aws:iam::LABACCOUNT_A:role/InventoryLab",
        "access_key_id": "SYNTHETIC_KEY_A",
        "creation_time": "2025-12-31T23:00:00Z",
    }
    evidence = [
        {
            "identity": {
                "source_kind": "synthetic",
                "account": r["recipientAccountId"],
                "region": r["awsRegion"],
                "event_id": r["eventID"],
            },
            "record_sha256": fingerprint(r),
        }
        for r in selected
    ]
    rule = (
        "AWS-LAB-001/1.0; synthetic; ec2.amazonaws.com; DescribeInstances; Management; "
        "AwsApiCall; readOnly is true; no errors; consistent AssumedRole credential session; "
        "3 unique full event identities per inclusive 60-second event-time window; "
        "all maximal windows; transitive union only through shared evidence"
    )
    definition = sha256(rule.encode()).hexdigest()
    identity = {
        "domain": "cloudsecops-live/finding/1.0",
        "rule_id": "AWS-LAB-001",
        "rule_version": "1.0",
        "rule_definition_sha256": definition,
        "versions": ("1.0", "1.0.0", "1.0"),
        "session": session,
        "window": [selected[0]["eventTime"], selected[-1]["eventTime"]],
        "evidence": evidence,
    }
    finding = {
        "finding_id": fingerprint(identity),
        "rule_id": "AWS-LAB-001",
        "rule_version": "1.0",
        "rule_definition_sha256": definition,
        "schema_version": "1.0",
        "parser_version": "1.0.0",
        "canonicalization_version": "1.0",
        "source_kind": "synthetic",
        "authenticated": False,
        "status": "synthetic_candidate",
        "session": session,
        "count": len(selected),
        "evidence_event_ids": [r["eventID"] for r in selected],
        "evidence": evidence,
        "window_start": selected[0]["eventTime"],
        "window_end": selected[-1]["eventTime"],
        "window_explanation": "Union of maximal inclusive 60-second windows sharing evidence, "
        "transitively; the resulting component may span more than 60 seconds.",
        "attack": {"technique_id": "T1580", "name": "Cloud Infrastructure Discovery"},
        "rationale": "At least three unique successful EC2 DescribeInstances management API calls "
        "occurred in an inclusive 60-second window for one credential session.",
        "limitations": [
            "Synthetic candidate only; these records authenticate no AWS source or activity.",
            "Benign administrators, inventory tools, pagination and SDK retries can cause bursts.",
            "Visibility is limited to the supplied records; missing activity cannot be ruled out.",
            "T1580 describes infrastructure enumeration; "
            "this is no validated attack or compromise.",
        ],
    }
    draft = {
        **finding,
        "unreviewed": True,
        "case_class": "synthetic_lab_draft",
        "event_timeline": [
            {**e, "event_time": r["eventTime"]} for e, r in zip(evidence, selected, strict=True)
        ],
    }
    blobs = [archive(records), *[archive(group) for group in extra_records]]
    raw = []
    refs = []
    variants = {}
    identities = {}
    deliveries = []
    for n, blob in enumerate(blobs):
        expanded = gzip.decompress(blob)
        rid = sha256(blob).hexdigest()
        parsed = json.loads(expanded)["Records"]
        raw.append(
            {
                "raw_id": rid,
                "archive_hash": rid,
                "content_hash": sha256(expanded).hexdigest(),
                "expanded_size": len(expanded),
                "archive_size": len(blob),
                "record_count": len(parsed),
                "source_kind": "synthetic",
                "authenticated": False,
                "schema_version": "1.0",
                "parser_version": "1.0.0",
                "canonicalization_version": "1.0",
            }
        )
        deliveries.append({"batch_id": str(n), "raw_id": rid, "source_ref": f"{n}.gz"})
        for i, record in enumerate(parsed):
            identity = {
                "source_kind": "synthetic",
                "account": record["recipientAccountId"],
                "region": record["awsRegion"],
                "event_id": record["eventID"],
            }
            key, rh = fingerprint(identity), fingerprint(record)
            refs.append(
                {
                    "batch_id": str(n),
                    "raw_id": rid,
                    "source_ref": f"{n}.gz",
                    "record_index": i,
                    "event_key": key,
                    "record_hash": rh,
                }
            )
            user = record["userIdentity"]
            cred = user["sessionContext"]
            normalized_session = {
                "account": record["recipientAccountId"],
                "region": record["awsRegion"],
                "issuer_arn": cred["sessionIssuer"]["arn"],
                "access_key_id": user["accessKeyId"],
                "creation_time": cred["attributes"]["creationDate"],
            }
            variants[key, rh] = {
                "event_key": key,
                "record_hash": rh,
                "canonical_hash": rh,
                "schema_version": "1.0",
                "parser_version": "1.0.0",
                "canonicalization_version": "1.0",
                "normalized": {
                    "source_kind": "synthetic",
                    "authenticated": False,
                    "schema_version": "1.0",
                    "parser_version": "1.0.0",
                    "canonicalization_version": "1.0",
                    "event_time": datetime.fromisoformat(record["eventTime"]).isoformat(),
                    "event_source": record["eventSource"],
                    "event_name": record["eventName"],
                    "event_category": record["eventCategory"],
                    "event_type": record["eventType"],
                    "read_only": record["readOnly"],
                    "has_error": "errorCode" in record or "errorMessage" in record,
                    "session": normalized_session,
                    "identity_reason": None,
                },
            }
            identities[key] = {"event_key": key, **identity}
    fp = fingerprint(draft)
    batches = [
        {
            "batch_id": str(n),
            "checkpoint": str(n),
            "request_hash": fingerprint([(f"{n}.gz", r["raw_id"])]),
            "status": "committed",
            "generation": 1,
            "accepted_count": r["record_count"],
            "duplicate_count": 0,
            "conflicting_count": 0,
            "source_count": 1,
        }
        for n, r in enumerate(raw)
    ]
    conflict_keys = {key for key, _ in variants if sum(k == key for k, _ in variants) > 1}
    bundle = {
        "request_id": "a" * 32,
        "case_id": "b" * 64,
        "case_revision": 1,
        "case_fingerprint": fp,
        "finding_id": finding["finding_id"],
        "generation": 1,
        "published_generation": 1,
        "case_payload": {**draft, "case_id": "b" * 64, "revision": 1, "case_status": "current"},
        "finding_payload": finding,
        "manifest": {
            "raw_objects": raw,
            "source_references": refs,
            "raw_deliveries": deliveries,
            "record_variants": list(variants.values()),
            "events": list(identities.values()),
            "batches": batches,
            "conflicts": [
                {"event_key": key, "detected_generation": 1} for key in sorted(conflict_keys)
            ],
        },
        "finding_evidence": [
            {"event_key": fingerprint(e["identity"]), "record_hash": e["record_sha256"]}
            for e in evidence
        ],
        "recommendation": {
            "payload": {
                "case_id": "b" * 64,
                "case_revision": 1,
                "case_fingerprint": fp,
                "finding_id": finding["finding_id"],
                "action": "NO_ACTION_AUTHORIZED_EXERCISE",
                "conclusion": "authorized_synthetic_exercise",
                "execution_targets": [],
                "source_kind": "synthetic",
                "authenticated": False,
            }
        },
        "approval": {"decision": "approve"},
    }
    bundle["source_manifest_hash"] = sha256(
        json.dumps(
            bundle["manifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    bundle["recommendation"]["payload"].update(
        {
            "source_manifest_hash": bundle["source_manifest_hash"],
            "generation": 1,
            "evidence": bundle["finding_evidence"],
            "policy_version": "offline-no-action/1",
            "epoch": 1,
        }
    )
    bundle.update(
        {
            "request_version": "1.0",
            "checker_policy": "synthetic-aws-lab-001-independent/1",
            "checker_version": "1.0",
            "checker_source_digest": source_digest(),
        }
    )
    rec = bundle["recommendation"]
    rec.update(
        {
            k: rec["payload"][k]
            for k in (
                "case_id",
                "case_revision",
                "case_fingerprint",
                "finding_id",
                "generation",
                "epoch",
                "source_manifest_hash",
            )
        }
    )
    rec.update({"recommendation_id": bundle["case_id"], "version": 1, "author_id": "1" * 32})
    rec["recommendation_hash"] = sha256(
        json.dumps(
            rec["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    review = {
        "review_id": "2" * 32,
        "recommendation_id": bundle["case_id"],
        "version": 1,
        "recommendation_hash": rec["recommendation_hash"],
        "reviewer_id": "3" * 32,
        "decision": "approve",
        "reason": "reviewed synthetic records",
    }
    bundle["approval"] = {
        **review,
        "review_hash": sha256(
            json.dumps(review, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest(),
    }
    return bundle, {r["raw_id"]: b for r, b in zip(raw, blobs, strict=True)}


@pytest.mark.parametrize(
    ("times", "expected"),
    [
        ([0, 30, 60], "verified"),
        ([0, 30, 61], "contradicted"),
        ([0, 30, 60, 90, 120], "verified"),
        ([0, 1, 2, 62, 63, 64], "contradicted"),
        ([0, 60, 120, 180], "contradicted"),
        ([0, 20, 40, 70, 100, 120, 140], "verified"),
    ],
)
def test_literal_window_components(times, expected):
    bundle, blobs = snapshot([event(f"e{i}", t) for i, t in enumerate(times)])
    report = verify_snapshot(bundle, blobs.get)
    assert report["result"] == expected
    assert report["source_kind"] == "synthetic"
    assert report["authenticated"] is False


def test_omitted_eligible_event_is_not_verified_as_a_supporting_triple():
    records = [event("a", 0), event("b", 20), event("c", 40), event("d", 50)]
    bundle, blobs = snapshot(records, claimed=records[:3])
    assert verify_snapshot(bundle, blobs.get)["result"] == "contradicted"


def test_same_names_different_credentials_never_join():
    records = [event("a", 0), event("b", 20), event("c", 40, key="SYNTHETIC_KEY_B")]
    bundle, blobs = snapshot(records)
    report = verify_snapshot(bundle, blobs.get)
    assert report["result"] == "contradicted"
    assert report["details"]["count_valid"] is True
    assert report["details"]["session_valid"] is False
    assert report["details"]["window_valid"] is False


def test_component_span_and_invalid_count_are_reported_separately():
    bundle, blobs = snapshot([event("a", 0), event("b", 30), event("c", 60), event("d", 90)])
    bundle["finding_payload"]["count"] = 999
    report = verify_snapshot(bundle, blobs.get)
    assert report["result"] == "contradicted"
    assert report["details"]["count_valid"] is False
    assert report["details"]["session_valid"] is True
    assert report["details"]["window_valid"] is True


@pytest.mark.parametrize(
    "claimed", [None, ["invalid"], [{"identity": {}, "record_sha256": "0" * 64}]]
)
def test_malformed_claim_details_are_bounded_false_values(claimed):
    bundle, blobs = snapshot([event("a", 0), event("b", 30), event("c", 60)])
    bundle["finding_payload"]["evidence"] = claimed
    report = verify_snapshot(bundle, blobs.get)
    assert report["result"] == "contradicted"
    assert report["details"]["count_valid"] is False
    assert report["details"]["window_valid"] is False


def test_unknown_field_conflict_blocks_the_complete_dataset():
    records = [event("a", 0), event("b", 20), event("c", 40)]
    changed = {**records[0], "discardedByNormalizer": {"extra": True}}
    bundle, blobs = snapshot(records, extra_records=([changed],))
    report = verify_snapshot(bundle, blobs.get)
    assert report["result"] == "contradicted"
    assert report["checks"]["conflicts"] == "fail"


@pytest.mark.parametrize("fault", ["missing", "hash", "truncated", "references", "version"])
def test_insufficient_or_corrupt_evidence_is_inconclusive(fault):
    bundle, blobs = snapshot([event("a", 0), event("b", 20), event("c", 40)])
    rid = bundle["manifest"]["raw_objects"][0]["raw_id"]
    if fault == "missing":
        blobs.clear()
    elif fault == "hash":
        bundle["manifest"]["raw_objects"][0]["content_hash"] = "0" * 64
    elif fault == "truncated":
        blobs[rid] = blobs[rid][:-5]
    elif fault == "references":
        bundle["manifest"]["source_references"].pop()
    else:
        bundle["manifest"]["raw_objects"][0]["parser_version"] = "999"
    assert verify_snapshot(bundle, blobs.get)["result"] == "inconclusive"


def test_rehashed_case_timeline_lie_is_contradicted_by_originals():
    bundle, blobs = snapshot([event("a", 0), event("b", 20), event("c", 40)])
    bundle["case_payload"]["event_timeline"][0]["event_time"] = "2026-01-01T00:59:00Z"
    body = {
        k: v
        for k, v in bundle["case_payload"].items()
        if k not in {"case_id", "revision", "case_status"}
    }
    bundle["case_fingerprint"] = fingerprint(body)
    assert verify_snapshot(bundle, blobs.get)["result"] == "contradicted"


def test_production_detector_and_private_parser_helpers_are_not_proof_dependencies(monkeypatch):
    import cloudsecops_live.detection as detector

    def forbidden(*args, **kwargs):
        raise AssertionError("production detector called")

    for name in ("detect", "_components", "_reasons", "_finding"):
        monkeypatch.setattr(detector, name, forbidden)
    bundle, blobs = snapshot([event("a", 0), event("b", 20), event("c", 80)])
    assert verify_snapshot(bundle, blobs.get)["result"] == "contradicted"


def test_output_is_bounded_counts_and_codes_without_original_records():
    bundle, blobs = snapshot([event("a", 0), event("b", 20), event("c", 40)])
    before = deepcopy(bundle)
    report = verify_snapshot(bundle, blobs.get)
    assert bundle == before
    assert len(json.dumps(report)) < 16384
    assert "SYNTHETIC_KEY_A" not in json.dumps(report)
    assert "LABACCOUNT_A" not in json.dumps(report)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "true"),
        (False, "false"),
        (7, "7"),
        (Decimal("1.0000000000000000001"), "1.0000000000000000001"),
        (Decimal("1.0"), "1.0"),
        (Decimal("-0.0"), "0.0"),
        ({"z": [2, 1], "é": "é", "a": {"x": False}}, '{"a":{"x":false},"z":[2,1],"é":"é"}'),
    ],
)
def test_complete_record_canonicalization_has_literal_type_and_number_contract(value, expected):
    from cloudsecops_live.independent_verifier import _canonical

    assert _canonical(value) == expected


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), object()])
def test_nonfinite_and_unsupported_canonical_values_fail_closed(value):
    from cloudsecops_live.independent_verifier import _canonical

    with pytest.raises(ValueError):
        _canonical(value)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("user", "missing_assumed_role"),
        ("context", "missing_session_context"),
        ("issuer", "missing_session_identity"),
        ("access", "missing_session_identity"),
        ("principal", "inconsistent_assumed_role"),
        ("actor", "inconsistent_assumed_role"),
        ("creation", "missing_session_creation"),
        ("future", "future_session_creation"),
    ],
)
def test_raw_session_consistency_has_independent_literal_failures(change, reason):
    from cloudsecops_live.independent_verifier import _record

    raw = event("a")
    user = raw["userIdentity"]
    context = user["sessionContext"]
    if change == "user":
        raw["userIdentity"] = {"type": "IAMUser"}
    elif change == "context":
        user.pop("sessionContext")
    elif change == "issuer":
        context["sessionIssuer"] = None
    elif change == "access":
        user["accessKeyId"] = ""
    elif change == "principal":
        user["principalId"] = "OTHER:lab-session"
    elif change == "actor":
        user["arn"] = "arn:aws:sts::LABACCOUNT_A:assumed-role/Other/lab-session"
    elif change == "creation":
        context["attributes"]["creationDate"] = 3
    else:
        context["attributes"]["creationDate"] = "2026-01-02T00:00:00Z"
    checked = _record(raw)
    assert checked.qualifying is False
    assert checked.normalized["identity_reason"] == reason


@pytest.mark.parametrize("time", ["2026-01-01", "2026-01-01T00:00:00+24:00", "invalid"])
def test_time_requires_explicit_valid_bounded_utc_offset(time):
    from cloudsecops_live.independent_verifier import _time

    with pytest.raises(ValueError):
        _time(time)


@pytest.mark.parametrize(
    "fault",
    [
        "raw_bound",
        "duplicate_raw",
        "archive_total",
        "expanded_total",
        "duplicate_delivery",
        "missing_delivery",
        "reference_bind",
        "duplicate_reference",
        "batch_missing",
        "batch_request",
        "batch_count",
        "variant_missing",
        "variant_version",
        "canonical_hash",
        "normalized",
        "identity",
        "conflict",
        "checker",
        "source_pin",
    ],
)
def test_complete_manifest_is_not_a_caller_asserted_completeness_flag(fault):
    bundle, blobs = snapshot([event("a", 0), event("b", 20), event("c", 40)])
    manifest = bundle["manifest"]
    if fault == "raw_bound":
        manifest["raw_objects"] *= 65
    elif fault == "duplicate_raw":
        manifest["raw_objects"] *= 2
    elif fault == "archive_total":
        manifest["raw_objects"][0]["archive_size"] = 100 * 1024 * 1024 + 1
    elif fault == "expanded_total":
        manifest["raw_objects"][0]["expanded_size"] = 100 * 1024 * 1024 + 1
    elif fault == "duplicate_delivery":
        manifest["raw_deliveries"] *= 2
    elif fault == "missing_delivery":
        manifest["raw_deliveries"].clear()
    elif fault == "reference_bind":
        manifest["source_references"][0]["record_hash"] = "0" * 64
    elif fault == "duplicate_reference":
        manifest["source_references"].append(manifest["source_references"][0])
    elif fault == "batch_missing":
        manifest["batches"].clear()
    elif fault == "batch_request":
        manifest["batches"][0]["request_hash"] = "0" * 64
    elif fault == "batch_count":
        manifest["batches"][0]["accepted_count"] += 1
    elif fault == "variant_missing":
        manifest["record_variants"].pop()
    elif fault == "variant_version":
        manifest["record_variants"][0]["parser_version"] = "999"
    elif fault == "canonical_hash":
        manifest["record_variants"][0]["canonical_hash"] = "0" * 64
    elif fault == "normalized":
        manifest["record_variants"][0]["normalized"]["event_name"] = "forged"
    elif fault == "identity":
        manifest["events"][0]["event_id"] = "forged"
    elif fault == "conflict":
        manifest["conflicts"] = [{"event_key": "0" * 64, "detected_generation": 1}]
    elif fault == "checker":
        bundle["checker_version"] = "999"
    else:
        bundle["checker_source_digest"] = "0" * 64
    bundle["source_manifest_hash"] = sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert verify_snapshot(bundle, blobs.get)["result"] == "inconclusive"


@pytest.mark.parametrize(
    "field", ["eventSource", "eventName", "eventCategory", "eventType", "readOnly", "errorCode"]
)
def test_nonqualifying_original_fields_cannot_be_overridden_by_finding(field):
    from cloudsecops_live.independent_verifier import _record

    raw = event("a")
    raw[field] = False if field == "readOnly" else None if field == "errorCode" else "other"
    assert _record(raw).qualifying is False
