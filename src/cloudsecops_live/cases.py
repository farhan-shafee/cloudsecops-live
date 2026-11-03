"""Append-only, unreviewed synthetic draft conclusions and explicit lineage."""

import json
from collections.abc import Sequence
from dataclasses import asdict
from hashlib import sha256
from typing import Any

from psycopg import Connection
from psycopg.types.json import Jsonb

from cloudsecops_live.database import machine_audit
from cloudsecops_live.detection import DetectionReport
from cloudsecops_live.errors import EvidenceError


def evidence_fingerprint(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def case_identity(finding_id: str, parents: Sequence[str] = ()) -> str:
    return evidence_fingerprint(
        {
            "domain": "cloudsecops-live/draft-case/1",
            "finding": finding_id,
            "parents": sorted(parents),
        }
    )


def revise_case(
    conn: Connection[dict[str, Any]],
    case_id: str,
    expected_revision: int,
    payload: dict[str, Any],
    finding_id: str,
    generation: int,
    status: str = "current",
) -> int:
    """Caller owns transaction and schema check; compare-and-swap never replaces history."""
    if status not in {"current", "superseded", "withdrawn"}:
        raise EvidenceError("INVALID_CASE_STATE")
    if payload.get("source_kind") != "synthetic" or payload.get("authenticated") is not False:
        raise EvidenceError("INVALID_PROVENANCE")
    if payload.get("unreviewed") is not True:
        raise EvidenceError("INVALID_CASE_STATE")
    revision = expected_revision + 1
    updated = conn.execute(
        "UPDATE csl.cases SET current_revision=%s,status=%s "
        "WHERE case_id=%s AND current_revision=%s RETURNING case_id",
        (revision, status, case_id, expected_revision),
    ).fetchone()
    if updated is None:
        raise EvidenceError("STALE_REVISION")
    normalized = {
        k: v for k, v in payload.items() if k not in {"case_id", "revision", "case_status"}
    }
    stored = {**normalized, "case_id": case_id, "revision": revision, "case_status": status}
    fingerprint = evidence_fingerprint(normalized)
    conn.execute(
        "INSERT INTO csl.case_revisions "
        "(case_id,revision,payload,fingerprint,finding_id,generation,status) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (case_id, revision, Jsonb(stored), fingerprint, finding_id, generation, status),
    )
    for kind, table in (("draft_revision", "case_timeline"), ("case_revision", "audit")):
        if table == "case_timeline":
            conn.execute(
                "INSERT INTO csl.case_timeline(case_id,revision,kind,payload) VALUES (%s,%s,%s,%s)",
                (case_id, revision, kind, Jsonb(stored)),
            )
        else:
            machine_audit(conn, kind, stored)
    outbox_id = evidence_fingerprint(
        {"domain": "offline-outbox/1", "case": case_id, "rev": revision}
    )
    message = {
        "source_kind": "synthetic",
        "authenticated": False,
        "delivery_class": "offline_test_only",
        "case_id": case_id,
        "revision": revision,
        "case_status": status,
        "evidence_fingerprint": fingerprint,
        "finding_id": finding_id,
    }
    conn.execute(
        "INSERT INTO csl.outbox(outbox_id,idempotency_key,case_id,revision,payload) "
        "VALUES (%s,%s,%s,%s,%s)",
        (outbox_id, outbox_id, case_id, revision, Jsonb(message)),
    )
    return revision


def _identities(payload: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    return {
        (
            item["identity"]["source_kind"],
            item["identity"]["account"],
            item["identity"]["region"],
            item["identity"]["event_id"],
        )
        for item in payload["evidence"]
    }


def publish(
    conn: Connection[dict[str, Any]], report: DetectionReport, generation: int
) -> dict[str, int]:
    """Dataset row is locked by caller through snapshot, detection and publication."""
    old = conn.execute(
        "SELECT c.case_id,c.current_revision,r.payload,r.finding_id,r.fingerprint "
        "FROM csl.cases c JOIN csl.case_revisions r "
        "ON (r.case_id,r.revision)=(c.case_id,c.current_revision) "
        "WHERE c.status IN ('pending','current') ORDER BY c.case_id FOR UPDATE OF c"
    ).fetchall()
    prior = {row["case_id"]: row for row in old}
    consumed: set[str] = set()
    revisions = 0
    for finding in report.findings:
        payload = finding.to_dict()
        conn.execute(
            "INSERT INTO csl.findings(finding_id,payload,generation,status) "
            "VALUES (%s,%s,%s,'current') ON CONFLICT (finding_id) DO UPDATE SET status='current'",
            (finding.finding_id, Jsonb(payload), generation),
        )
        for event in finding.evidence:
            conn.execute(
                "INSERT INTO csl.finding_evidence(finding_id,event_key,record_hash) "
                "SELECT %s,event_key,%s FROM csl.events WHERE "
                "source_kind=%s AND account=%s AND region=%s AND event_id=%s "
                "ON CONFLICT DO NOTHING",
                (
                    finding.finding_id,
                    event.record_sha256,
                    event.identity.source_kind,
                    event.identity.account,
                    event.identity.region,
                    event.identity.event_id,
                ),
            )
        identities = _identities(payload)
        parents = sorted(k for k, row in prior.items() if identities & _identities(row["payload"]))
        draft = {
            **payload,
            "unreviewed": True,
            "case_class": "synthetic_lab_draft",
            "event_timeline": [
                {
                    "identity": asdict(event.identity),
                    "event_time": event.event_time.isoformat().replace("+00:00", "Z"),
                    "record_sha256": event.record_sha256,
                }
                for event in finding.evidence
            ],
        }
        fingerprint = evidence_fingerprint(draft)
        if len(parents) == 1:
            case_id = parents[0]
            row = prior[case_id]
            if row["fingerprint"] == fingerprint and row["finding_id"] == finding.finding_id:
                conn.execute("UPDATE csl.cases SET status='current' WHERE case_id=%s", (case_id,))
            else:
                revise_case(
                    conn, case_id, row["current_revision"], draft, finding.finding_id, generation
                )
                revisions += 1
        else:
            case_id = case_identity(finding.finding_id, parents)
            conn.execute(
                "INSERT INTO csl.cases(case_id,current_revision,status) VALUES (%s,0,'pending')",
                (case_id,),
            )
            revise_case(conn, case_id, 0, draft, finding.finding_id, generation)
            revisions += 1
            for parent in parents:
                row = prior[parent]
                historical = {**row["payload"], "superseded_by": case_id}
                revise_case(
                    conn,
                    parent,
                    row["current_revision"],
                    historical,
                    row["finding_id"],
                    generation,
                    "superseded",
                )
                revisions += 1
                conn.execute(
                    "INSERT INTO csl.case_lineage(parent_case_id,child_case_id,generation) "
                    "VALUES (%s,%s,%s)",
                    (parent, case_id, generation),
                )
        consumed.update(parents)
    for case_id, row in prior.items():
        if case_id not in consumed:
            historical = {**row["payload"], "withdrawal_reason": "conflict_or_no_current_component"}
            revise_case(
                conn,
                case_id,
                row["current_revision"],
                historical,
                row["finding_id"],
                generation,
                "withdrawn",
            )
            revisions += 1
    current_ids = [f.finding_id for f in report.findings]
    conn.execute(
        "UPDATE csl.findings SET status='obsolete' WHERE NOT (finding_id=ANY(%s))",
        (current_ids,),
    )
    return {"findings": len(report.findings), "case_revisions": revisions}
