"""Independent, bounded proof of synthetic consistency, never AWS authenticity.

The public importer supplies common hostile gzip/JSON syntax and resource validation.
Its normalized events, session decisions and hashes are deliberately unused. This
checker independently reads complete raw Records, canonicalizes, qualifies, groups
credential sessions, and connects consecutive qualifying triples. Shared syntax
validation and the local verifier's code/credential custody remain trust assumptions.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any

from cloudsecops_live.contracts import Limits
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes

CHECKER_VERSION = "1.0"
CHECKER_POLICY = "synthetic-aws-lab-001-independent/1"
_DEFINITION = (
    "synthetic-aws-lab-001-independent/1; recalculate original gzip and expanded hashes; "
    "independent complete-record Decimal canonicalization and credential-session identity; "
    "deduplicate full event identities; any complete-record conflict blocks all components; "
    "successful read-only EC2 DescribeInstances Management AwsApiCall; "
    "union consecutive sorted triples spanning at most inclusive 60 seconds; "
    "compare full component, finding, case, recommendation and evidence bindings; "
    "synthetic consistency only; shared bounded importer syntax validation"
)
CHECKER_DEFINITION_SHA256 = sha256(_DEFINITION.encode()).hexdigest()
_RULE_DEFINITION = (
    "AWS-LAB-001/1.0; synthetic; ec2.amazonaws.com; DescribeInstances; Management; "
    "AwsApiCall; readOnly is true; no errors; consistent AssumedRole credential session; "
    "3 unique full event identities per inclusive 60-second event-time window; "
    "all maximal windows; transitive union only through shared evidence"
)
_RULE_HASH = sha256(_RULE_DEFINITION.encode()).hexdigest()
_VERSIONS = ("1.0", "1.0.0", "1.0")
_CHECKS = (
    "integrity",
    "completeness",
    "canonical_records",
    "conflicts",
    "evidence_binding",
    "predicate",
    "case_binding",
)
LIMITATIONS = (
    "Offline synthetic consistency only; no AWS source or real activity is authenticated.",
    "This does not verify real exercise authorization, benign intent "
    "or absence of unseen activity.",
    "Bounded gzip/JSON syntax validation is shared with ingestion; semantic proof is independent.",
    "Verifier code, credentials, database and shared-host administration remain trusted.",
)
_CANDIDATE_LIMITS = (
    "Synthetic candidate only; these records authenticate no AWS source or activity.",
    "Benign administrators, inventory tools, pagination and SDK retries can cause bursts.",
    "Visibility is limited to the supplied records; missing activity cannot be ruled out.",
    "T1580 describes infrastructure enumeration; this is no validated attack or compromise.",
)
_MAX_BYTES = 100 * 1024 * 1024


def source_digest() -> str:
    """Hash the installed proof implementation, rather than a caller-selected file."""
    return sha256(Path(__file__).read_bytes()).hexdigest()


def _fingerprint(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _workflow_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _canonical(value: Any) -> str:
    """Independent implementation of the version-1 complete-record contract."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is int:
        return str(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise EvidenceError("VERIFY_CANONICAL")
        number = format(value, "f")
        if "." in number:
            number = number.rstrip("0").rstrip(".")
        if number in {"-0", "0"}:
            number = "0"
        return number if "." in number else number + ".0"
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + _canonical(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise EvidenceError("VERIFY_CANONICAL")


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        raise ValueError("invalid_verifier_time")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("invalid_verifier_time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise EvidenceError("VERIFY_TIME")
    return parsed.astimezone(UTC)


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _session(record: dict[str, Any], moment: datetime) -> tuple[dict[str, str] | None, str | None]:
    user = record.get("userIdentity")
    if not isinstance(user, dict) or user.get("type") != "AssumedRole":
        return None, "missing_assumed_role"
    context = user.get("sessionContext")
    if not isinstance(context, dict):
        return None, "missing_session_context"
    issuer, attrs = context.get("sessionIssuer"), context.get("attributes")
    if not isinstance(issuer, dict) or not isinstance(attrs, dict):
        return None, "missing_session_identity"
    arn, actor = issuer.get("arn"), user.get("arn")
    role_id, principal, access = (
        issuer.get("principalId"),
        user.get("principalId"),
        user.get("accessKeyId"),
    )
    if not all(isinstance(v, str) and v for v in (arn, actor, role_id, principal, access)):
        return None, "missing_session_identity"
    assert isinstance(arn, str) and isinstance(actor, str) and isinstance(role_id, str)
    assert isinstance(principal, str) and isinstance(access, str)
    account = record["recipientAccountId"]
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::([^:]+):role/(.+)", arn)
    parts = principal.split(":")
    label = r"[A-Za-z0-9_+=,.@-]{1,128}"
    if (
        not match
        or issuer.get("type") != "Role"
        or user.get("accountId") != account
        or issuer.get("accountId") != account
        or match.group(2) != account
        or len(parts) != 2
        or parts[0] != role_id
        or not re.fullmatch(label, parts[1])
        or not re.fullmatch(label, role_id)
        or not re.fullmatch(r"SYNTHETIC_KEY_[A-Z0-9_]{1,64}", access)
    ):
        return None, "inconsistent_assumed_role"
    role_name = match.group(3).split("/")[-1]
    expected = f"arn:{match.group(1)}:sts::{account}:assumed-role/{role_name}/{parts[1]}"
    if not re.fullmatch(label, role_name) or actor != expected:
        return None, "inconsistent_assumed_role"
    try:
        creation = _time(attrs["creationDate"])
    except (KeyError, TypeError, ValueError):
        return None, "missing_session_creation"
    if creation > moment:
        return None, "future_session_creation"
    return {
        "account": account,
        "region": record["awsRegion"],
        "issuer_arn": arn,
        "access_key_id": access,
        "creation_time": _stamp(creation),
    }, None


@dataclass(frozen=True)
class _Record:
    identity: dict[str, str]
    event_key: str
    record_hash: str
    canonical: bytes
    moment: datetime
    session: dict[str, str] | None
    qualifying: bool
    normalized: dict[str, Any]


def _record(raw: dict[str, Any]) -> _Record:
    identity = {
        "source_kind": "synthetic",
        "account": raw["recipientAccountId"],
        "region": raw["awsRegion"],
        "event_id": raw["eventID"],
    }
    canonical = _canonical(raw).encode("utf-8")
    moment = _time(raw["eventTime"])
    session, reason = _session(raw, moment)
    error = "errorCode" in raw or "errorMessage" in raw
    qualified = (
        raw.get("eventSource") == "ec2.amazonaws.com"
        and raw.get("eventName") == "DescribeInstances"
        and raw.get("eventCategory") == "Management"
        and raw.get("eventType") == "AwsApiCall"
        and raw.get("readOnly") is True
        and not error
        and session is not None
    )
    normalized = {
        "source_kind": "synthetic",
        "authenticated": False,
        "schema_version": "1.0",
        "parser_version": "1.0.0",
        "canonicalization_version": "1.0",
        "event_time": moment.isoformat(),
        "event_source": raw.get("eventSource", ""),
        "event_name": raw.get("eventName", ""),
        "event_category": raw.get("eventCategory", ""),
        "event_type": raw.get("eventType", ""),
        "read_only": raw.get("readOnly"),
        "has_error": error,
        "session": session,
        "identity_reason": reason,
    }
    return _Record(
        identity,
        _fingerprint(identity),
        sha256(canonical).hexdigest(),
        canonical,
        moment,
        session,
        qualified,
        normalized,
    )


def _root(roots: list[int], index: int) -> int:
    while roots[index] != index:
        roots[index] = roots[roots[index]]
        index = roots[index]
    return index


def _components(records: list[_Record]) -> list[list[_Record]]:
    sessions: dict[str, list[_Record]] = defaultdict(list)
    for record in records:
        if record.qualifying:
            sessions[_fingerprint(record.session)].append(record)
    components: list[list[_Record]] = []
    for values in sessions.values():
        values.sort(key=lambda item: (item.moment, tuple(item.identity.values())))
        roots = list(range(len(values)))
        touched: set[int] = set()

        for index in range(len(values) - 2):
            if (values[index + 2].moment - values[index].moment).total_seconds() <= 60:
                for other in (index + 1, index + 2):
                    roots[_root(roots, other)] = _root(roots, index)
                touched.update((index, index + 1, index + 2))
        groups: dict[int, list[_Record]] = defaultdict(list)
        for index in sorted(touched):
            groups[_root(roots, index)].append(values[index])
        components.extend(groups.values())
    return components


def _finding(records: list[_Record]) -> dict[str, Any]:
    evidence = [{"identity": item.identity, "record_sha256": item.record_hash} for item in records]
    window = [_stamp(records[0].moment), _stamp(records[-1].moment)]
    material = {
        "domain": "cloudsecops-live/finding/1.0",
        "rule_id": "AWS-LAB-001",
        "rule_version": "1.0",
        "rule_definition_sha256": _RULE_HASH,
        "versions": _VERSIONS,
        "session": records[0].session,
        "window": window,
        "evidence": evidence,
    }
    return {
        "finding_id": _fingerprint(material),
        "rule_id": "AWS-LAB-001",
        "rule_version": "1.0",
        "rule_definition_sha256": _RULE_HASH,
        "schema_version": "1.0",
        "parser_version": "1.0.0",
        "canonicalization_version": "1.0",
        "status": "synthetic_candidate",
        "source_kind": "synthetic",
        "authenticated": False,
        "session": records[0].session,
        "count": len(records),
        "evidence_event_ids": [r.identity["event_id"] for r in records],
        "evidence": evidence,
        "window_start": window[0],
        "window_end": window[1],
        "window_explanation": "Union of maximal inclusive 60-second windows sharing evidence, "
        "transitively; the resulting component may span more than 60 seconds.",
        "attack": {"technique_id": "T1580", "name": "Cloud Infrastructure Discovery"},
        "rationale": "At least three unique successful EC2 DescribeInstances management API calls "
        "occurred in an inclusive 60-second window for one credential session.",
        "limitations": list(_CANDIDATE_LIMITS),
    }


def _versions(row: dict[str, Any]) -> bool:
    return (
        tuple(row.get(k) for k in ("schema_version", "parser_version", "canonicalization_version"))
        == _VERSIONS
    )


def _predicate_details(
    claim: dict[str, Any],
    unique: dict[tuple[str, str], _Record],
    components: list[list[_Record]],
) -> dict[str, Any]:
    """Keep count, credential identity and window validity separate in the receipt."""
    invalid = {"count_valid": False, "session_valid": False, "window_valid": False}
    try:
        evidence = claim["evidence"]
        if not isinstance(evidence, list) or len(evidence) > 10_000:
            return invalid
        keys = [(_fingerprint(item["identity"]), item["record_sha256"]) for item in evidence]
        selected = [unique[key] for key in keys]
        distinct = len(set(keys)) == len(keys)
        sessions = {_fingerprint(record.session) for record in selected}
        return {
            "count_valid": distinct
            and type(claim["count"]) is int
            and claim["count"] == len(selected)
            and len(selected) >= 3,
            "session_valid": bool(selected)
            and len(sessions) == 1
            and all(record.session is not None for record in selected),
            "window_valid": distinct
            and any(keys == [(r.event_key, r.record_hash) for r in c] for c in components),
            "claimed_evidence_records": len(selected),
            "claimed_qualifying_records": sum(r.qualifying for r in selected),
        }
    except (KeyError, TypeError):
        return invalid


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    checks = report["checks"]
    if (
        any(checks[k] != "pass" for k in ("integrity", "completeness", "canonical_records"))
        or "unknown" in checks.values()
    ):
        report["result"] = "inconclusive"
    elif "fail" in checks.values():
        report["result"] = "contradicted"
    else:
        report["result"] = "verified"
    return report


def verify_snapshot(
    bundle: dict[str, Any], original: Callable[[str], bytes | None]
) -> dict[str, Any]:
    """Reconstruct proof from a server-pinned manifest and one-original-at-a-time reader.

    No supplied result, normalized qualification, finding count or source-trust flag
    serves as proof. Details contain bounded counts/reason codes, never raw identifiers.
    """
    report: dict[str, Any] = {
        "checker_version": CHECKER_VERSION,
        "checker_digest": CHECKER_DEFINITION_SHA256,
        "source_digest": source_digest(),
        "result": "inconclusive",
        "checks": dict.fromkeys(_CHECKS, "unknown"),
        "details": {"limitations": list(LIMITATIONS)},
        "scope": "offline_synthetic_only",
        "source_kind": "synthetic",
        "authenticated": False,
    }
    checks, details = report["checks"], report["details"]
    stage = "completeness"
    try:
        if (
            bundle["request_version"] != "1.0"
            or bundle["checker_policy"] != CHECKER_POLICY
            or bundle["checker_version"] != CHECKER_VERSION
            or bundle["checker_source_digest"] != report["source_digest"]
        ):
            raise EvidenceError("VERIFY_CHECKER_BINDING")
        manifest = bundle["manifest"]
        for name, maximum in (
            ("raw_objects", 64),
            ("source_references", 10_000),
            ("raw_deliveries", 10_000),
            ("record_variants", 10_000),
            ("events", 10_000),
            ("batches", 256),
            ("conflicts", 10_000),
        ):
            if not isinstance(manifest[name], list) or len(manifest[name]) > maximum:
                raise EvidenceError("VERIFY_LIMIT")
        manifest_hash = _workflow_hash(manifest)
        if manifest_hash != bundle["source_manifest_hash"]:
            raise EvidenceError("VERIFY_MANIFEST_HASH")
        rows, refs = manifest["raw_objects"], manifest["source_references"]
        if len(rows) > 64 or len(refs) > 10_000 or len(manifest["raw_deliveries"]) > 10_000:
            raise EvidenceError("VERIFY_LIMIT")
        ids = [row["raw_id"] for row in rows]
        if len(set(ids)) != len(ids):
            raise EvidenceError("VERIFY_MANIFEST")
        if (
            sum(row["archive_size"] for row in rows) > _MAX_BYTES
            or sum(row["expanded_size"] for row in rows) > _MAX_BYTES
        ):
            raise EvidenceError("VERIFY_LIMIT")
        stage = "integrity"
        observed: dict[tuple[str, int], _Record] = {}
        compressed = expanded = 0
        for row in rows:
            if (
                not _versions(row)
                or row["source_kind"] != "synthetic"
                or row["authenticated"] is not False
            ):
                raise EvidenceError("VERIFY_VERSION")
            blob = original(row["raw_id"])
            if not isinstance(blob, bytes):
                raise EvidenceError("VERIFY_MISSING_ORIGINAL")
            compressed += len(blob)
            if compressed > _MAX_BYTES or expanded >= _MAX_BYTES:
                raise EvidenceError("VERIFY_LIMIT")
            parsed = parse_bytes(blob, limits=Limits(max_expanded_bytes=_MAX_BYTES - expanded))
            content = parsed.evidence.content_bytes
            archive_hash, content_hash = sha256(blob).hexdigest(), sha256(content).hexdigest()
            records = json.loads(content, parse_float=Decimal)["Records"]
            expanded += len(content)
            if (
                archive_hash != row["raw_id"]
                or archive_hash != row["archive_hash"]
                or content_hash != row["content_hash"]
                or len(content) != row["expanded_size"]
                or len(blob) != row["archive_size"]
                or len(records) != row["record_count"]
                or len(observed) + len(records) > 10_000
            ):
                raise EvidenceError("VERIFY_ORIGINAL_MISMATCH")
            for index, raw in enumerate(records):
                observed[row["raw_id"], index] = _record(raw)
        checks["integrity"] = "pass"
        stage = "completeness"
        deliveries = {
            (r["batch_id"], r["raw_id"], r["source_ref"]) for r in manifest["raw_deliveries"]
        }
        if len(deliveries) != len(manifest["raw_deliveries"]) or {r[1] for r in deliveries} != set(
            ids
        ):
            raise EvidenceError("VERIFY_DELIVERY_COVERAGE")
        raw_counts = {row["raw_id"]: row["record_count"] for row in rows}
        if sum(raw_counts[rid] for _, rid, _ in deliveries) > 10_000:
            raise EvidenceError("VERIFY_LIMIT")
        expected_refs = {
            (batch, rid, source, index)
            for batch, rid, source in deliveries
            for index in range(raw_counts[rid])
        }
        ref_keys = {(r["batch_id"], r["raw_id"], r["source_ref"], r["record_index"]) for r in refs}
        if len(refs) != len(ref_keys) or ref_keys != expected_refs:
            raise EvidenceError("VERIFY_REFERENCE_COVERAGE")
        for ref in refs:
            record = observed[ref["raw_id"], ref["record_index"]]
            if (ref["event_key"], ref["record_hash"]) != (record.event_key, record.record_hash):
                raise EvidenceError("VERIFY_REFERENCE_BINDING")
        batches = manifest["batches"]
        if len({b["batch_id"] for b in batches}) != len(batches) or {
            b["batch_id"] for b in batches
        } != {b for b, _, _ in deliveries}:
            raise EvidenceError("VERIFY_BATCH_COVERAGE")
        for batch in batches:
            request = sorted(
                (source, rid) for b, rid, source in deliveries if b == batch["batch_id"]
            )
            if (
                batch["status"] != "committed"
                or _fingerprint(request) != batch["request_hash"]
                or batch["source_count"] != len(request)
                or batch["accepted_count"] + batch["duplicate_count"] + batch["conflicting_count"]
                != sum(ref["batch_id"] == batch["batch_id"] for ref in refs)
            ):
                raise EvidenceError("VERIFY_BATCH_BINDING")
        checks["completeness"] = "pass"
        stage = "canonical_records"
        unique = {(r.event_key, r.record_hash): r for r in observed.values()}
        variants = manifest["record_variants"]
        if len(variants) != len(unique) or {
            (r["event_key"], r["record_hash"]) for r in variants
        } != set(unique):
            raise EvidenceError("VERIFY_VARIANT_COVERAGE")
        for row in variants:
            record = unique[row["event_key"], row["record_hash"]]
            if (
                not _versions(row)
                or row["canonical_hash"] != record.record_hash
                or row["normalized"] != record.normalized
            ):
                raise EvidenceError("VERIFY_CANONICAL_MISMATCH")
        identities = {r.event_key: r.identity for r in observed.values()}
        events = manifest["events"]
        if (
            len(events) != len(identities)
            or {r["event_key"]: {k: v for k, v in r.items() if k != "event_key"} for r in events}
            != identities
        ):
            raise EvidenceError("VERIFY_IDENTITY_COVERAGE")
        checks["canonical_records"] = "pass"
        by_identity: dict[str, set[bytes]] = defaultdict(set)
        for record in unique.values():
            by_identity[record.event_key].add(record.canonical)
        conflicts = {key for key, values in by_identity.items() if len(values) > 1}
        if {r["event_key"] for r in manifest["conflicts"]} != conflicts:
            raise EvidenceError("VERIFY_CONFLICT_COVERAGE")
        checks["conflicts"] = "fail" if conflicts else "pass"
        components = [] if conflicts else _components(list(unique.values()))
        findings = [_finding(component) for component in components]
        matches = [
            (f, c)
            for f, c in zip(findings, components, strict=True)
            if f["finding_id"] == bundle["finding_id"]
        ]
        checks["predicate"] = "pass" if len(matches) == 1 else "fail"
        checks["evidence_binding"] = "fail"
        checks["case_binding"] = "fail"
        stage = "case_binding"
        if len(matches) == 1:
            finding, component = matches[0]
            associations = [
                {"event_key": r.event_key, "record_hash": r.record_hash} for r in component
            ]
            if bundle["finding_payload"] == finding and sorted(
                bundle["finding_evidence"], key=_fingerprint
            ) == sorted(associations, key=_fingerprint):
                checks["evidence_binding"] = "pass"
            draft = {
                **finding,
                "unreviewed": True,
                "case_class": "synthetic_lab_draft",
                "event_timeline": [
                    {
                        "identity": r.identity,
                        "event_time": _stamp(r.moment),
                        "record_sha256": r.record_hash,
                    }
                    for r in component
                ],
            }
            expected = {
                **draft,
                "case_id": bundle["case_id"],
                "revision": bundle["case_revision"],
                "case_status": "current",
            }
            recommendation = bundle["recommendation"]["payload"]
            required = {
                "case_id": bundle["case_id"],
                "case_revision": bundle["case_revision"],
                "case_fingerprint": bundle["case_fingerprint"],
                "finding_id": finding["finding_id"],
                "generation": bundle["generation"],
                "source_manifest_hash": manifest_hash,
                "action": "NO_ACTION_AUTHORIZED_EXERCISE",
                "conclusion": "authorized_synthetic_exercise",
                "execution_targets": [],
                "source_kind": "synthetic",
                "authenticated": False,
                "policy_version": "offline-no-action/1",
            }
            rec, review = bundle["recommendation"], bundle["approval"]
            review_material = {
                k: review[k]
                for k in (
                    "review_id",
                    "recommendation_id",
                    "version",
                    "recommendation_hash",
                    "reviewer_id",
                    "decision",
                    "reason",
                )
            }
            if (
                bundle["case_payload"] == expected
                and _fingerprint(draft) == bundle["case_fingerprint"]
                and bundle["generation"] == bundle["published_generation"]
                and all(recommendation.get(k) == v for k, v in required.items())
                and recommendation.get("authenticated") is False
                and sorted(recommendation["evidence"], key=_fingerprint)
                == sorted(associations, key=_fingerprint)
                and bundle["approval"]["decision"] == "approve"
                and rec["recommendation_id"] == bundle["case_id"]
                and rec["recommendation_hash"] == _workflow_hash(recommendation)
                and all(
                    rec[k] == recommendation[k]
                    for k in (
                        "case_id",
                        "case_revision",
                        "case_fingerprint",
                        "finding_id",
                        "generation",
                        "epoch",
                        "source_manifest_hash",
                    )
                )
                and review["recommendation_id"] == rec["recommendation_id"]
                and review["version"] == rec["version"]
                and review["recommendation_hash"] == rec["recommendation_hash"]
                and review["review_hash"] == _workflow_hash(review_material)
                and review["reviewer_id"] != rec["author_id"]
            ):
                checks["case_binding"] = "pass"
        details.update(
            {
                "raw_objects": len(rows),
                "original_records": len(observed),
                "delivery_references": len(refs),
                "unique_events": len(identities),
                "conflicts": len(conflicts),
                "components": len(components),
                "matching_components": len(matches),
                "qualifying_unique_records": sum(r.qualifying for r in unique.values()),
                "credential_sessions": len(
                    {_fingerprint(r.session) for r in unique.values() if r.qualifying}
                ),
            }
        )
        details.update(_predicate_details(bundle["finding_payload"], unique, components))
    except (EvidenceError, KeyError, ValueError, TypeError, OverflowError, OSError, StopIteration):
        checks[stage] = "fail"
        details["reason"] = "original_or_manifest_unavailable_or_inconsistent"
    return _finish(report)
