"""Atomic bounded synthetic originals, complete-record variants and delivery references."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from hashlib import sha256
from typing import Any
from uuid import uuid4

from psycopg import Connection
from psycopg.types.json import Jsonb

from cloudsecops_live.contracts import (
    EventIdentity,
    Limits,
    NormalizedEvent,
    ParsedLog,
    RecordReference,
)
from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes

_MAX_BYTES = 100 * 1024 * 1024
MAX_BATCHES = 256
MAX_RAW_DELIVERIES = 10_000
MAX_INGESTION_ERRORS = 1000
_SOURCE_ERRORS = {
    "COMPRESSED_LIMIT",
    "EXPANDED_LIMIT",
    "INVALID_GZIP",
    "INVALID_JSON",
    "STRING_LIMIT",
    "INVALID_UNICODE",
    "DEPTH_LIMIT",
    "NODE_LIMIT",
    "RECORD_LIMIT",
    "NUMBER_LIMIT",
    "DUPLICATE_KEY",
    "INVALID_NUMBER",
    "NONFINITE_NUMBER",
    "INVALID_TIMESTAMP",
    "INVALID_RECORD_SCHEMA",
    "INVALID_RECORD_IDENTITY",
    "INVALID_INPUT_TYPE",
    "INVALID_SOURCE_REFERENCE",
    "INVALID_UTF8",
    "INVALID_FIXTURE_ENVELOPE",
    "UNSUPPORTED_VERSION",
    "INVALID_SOURCE_CLASSIFICATION",
    "INVALID_RECORDS",
    "STORE_LIMIT",
    "INVALID_CHECKPOINT",
    "DUPLICATE_SOURCE_DELIVERY",
    "CHECKPOINT_CONFLICT",
}


def event_key(identity: EventIdentity) -> str:
    """Use a stable key while PostgreSQL also enforces the full identity tuple."""
    return sha256(
        json.dumps(asdict(identity), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _normalized(event: NormalizedEvent) -> dict[str, object]:
    return {
        "source_kind": "synthetic",
        "authenticated": False,
        "schema_version": event.schema_version,
        "parser_version": event.parser_version,
        "canonicalization_version": event.canonicalization_version,
        "event_time": event.event_time.isoformat(),
        "event_source": event.event_source,
        "event_name": event.event_name,
        "event_category": event.event_category,
        "event_type": event.event_type,
        "read_only": event.read_only,
        "has_error": event.has_error,
        "session": asdict(event.session) if event.session else None,
        "identity_reason": event.identity_reason,
    }


def _valid_label(value: str) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    )


def _receipt(row: dict[str, Any], published: int) -> dict[str, object]:
    return {
        "batch_id": row["batch_id"],
        "checkpoint": row["checkpoint"],
        "generation": row["generation"],
        "accepted": row["accepted_count"],
        "duplicates": row["duplicate_count"],
        "conflicting": row["conflicting_count"],
        "pending": int(row["generation"] > published),
        "failed": 0,
    }


def load_logs(conn: Connection[dict[str, Any]]) -> list[ParsedLog]:
    """Reparse original bytes and compare *all* persisted derivatives before detection.

    Callers hold the pipeline lock for a coherent dataset snapshot. No missing or
    corrupted original can be represented as an empty successful detector input.
    """
    Database.check_schema(conn)
    originals = conn.execute("SELECT * FROM csl.raw_objects ORDER BY raw_id").fetchall()
    references = conn.execute(
        "SELECT * FROM csl.source_references ORDER BY raw_id,record_index,batch_id,source_ref"
    ).fetchall()
    deliveries = conn.execute("SELECT * FROM csl.raw_deliveries").fetchall()
    batches = conn.execute("SELECT * FROM csl.batches").fetchall()
    checkpoints = conn.execute("SELECT * FROM csl.checkpoints").fetchall()
    if {(r["batch_id"], r["checkpoint"], r["generation"]) for r in batches} != {
        (r["batch_id"], r["checkpoint"], r["generation"]) for r in checkpoints
    }:
        raise EvidenceError("CHECKPOINT_MISMATCH")
    if len(batches) > MAX_BATCHES or len(deliveries) > MAX_RAW_DELIVERIES:
        raise EvidenceError("STORE_LIMIT")
    errors = conn.execute("SELECT count(*) AS n FROM csl.ingestion_errors").fetchone()
    if not errors or errors["n"] > MAX_INGESTION_ERRORS:
        raise EvidenceError("STORE_LIMIT")
    raw_counts = {r["raw_id"]: r["record_count"] for r in originals}
    delivery_keys = {(r["batch_id"], r["raw_id"], r["source_ref"]) for r in deliveries}
    if {r["raw_id"] for r in deliveries} != set(raw_counts):
        raise EvidenceError("RAW_DELIVERY_MISMATCH")
    reference_counts: dict[tuple[str, str, str], int] = {}
    for ref in references:
        delivery_key = (ref["batch_id"], ref["raw_id"], ref["source_ref"])
        reference_counts[delivery_key] = reference_counts.get(delivery_key, 0) + 1
    if set(reference_counts) - delivery_keys or any(
        reference_counts.get(key, 0) != raw_counts.get(key[1]) for key in delivery_keys
    ):
        raise EvidenceError("SOURCE_REFERENCE_MISMATCH")
    for batch in batches:
        request = sorted(
            (r["source_ref"], r["raw_id"]) for r in deliveries if r["batch_id"] == batch["batch_id"]
        )
        request_hash = sha256(json.dumps(request, separators=(",", ":")).encode()).hexdigest()
        if request_hash != batch["request_hash"]:
            raise EvidenceError("BATCH_RECEIPT_MISMATCH")
        if batch["source_count"] != sum(r["batch_id"] == batch["batch_id"] for r in deliveries):
            raise EvidenceError("RAW_DELIVERY_MISMATCH")
        if batch["accepted_count"] + batch["duplicate_count"] + batch["conflicting_count"] != sum(
            r["batch_id"] == batch["batch_id"] for r in references
        ):
            raise EvidenceError("BATCH_RECEIPT_MISMATCH")
    variants = conn.execute("SELECT * FROM csl.record_variants").fetchall()
    identities = conn.execute("SELECT * FROM csl.events").fetchall()
    if (
        len(originals) > 64
        or sum(len(row["archive_bytes"]) for row in originals) > _MAX_BYTES
        or sum(row["expanded_size"] for row in originals) > _MAX_BYTES
        or len(references) > 10_000
    ):
        raise EvidenceError("STORE_LIMIT")
    by_raw: dict[str, list[dict[str, Any]]] = {}
    for row in references:
        by_raw.setdefault(row["raw_id"], []).append(row)
    stored_variants = {
        (r["event_key"], r["record_hash"]): bytes(r["canonical_bytes"]) for r in variants
    }
    stored_identities = {
        row["event_key"]: (row["source_kind"], row["account"], row["region"], row["event_id"])
        for row in identities
    }
    normalized = {(r["event_key"], r["record_hash"]): r["normalized"] for r in variants}
    observed_variants: dict[tuple[str, str], bytes] = {}
    observed_identities: dict[str, tuple[str, str, str, str]] = {}
    result: list[ParsedLog] = []
    expanded_total = 0
    for row in originals:
        if (
            row["source_kind"],
            row["authenticated"],
            row["schema_version"],
            row["parser_version"],
            row["canonicalization_version"],
        ) != ("synthetic", False, "1.0", "1.0.0", "1.0"):
            raise EvidenceError("UNSUPPORTED_VERSION")
        remaining = _MAX_BYTES - expanded_total
        parsed = parse_bytes(
            bytes(row["archive_bytes"]),
            source_ref=row["source_ref"],
            limits=Limits(max_expanded_bytes=max(1, remaining)),
        )
        expanded_total += len(parsed.evidence.content_bytes)
        if expanded_total > _MAX_BYTES:
            raise EvidenceError("STORE_LIMIT")
        raw = parsed.evidence
        if (
            raw.archive_sha256 != row["raw_id"]
            or raw.archive_sha256 != row["archive_hash"]
            or raw.content_sha256 != row["content_hash"]
            or len(raw.content_bytes) != row["expanded_size"]
            or len(parsed.events) != row["record_count"]
        ):
            raise EvidenceError("RAW_EVIDENCE_MISMATCH")
        raw_refs = by_raw.pop(row["raw_id"], [])
        grouped: dict[int, list[dict[str, Any]]] = {}
        for ref in raw_refs:
            if not 0 <= ref["record_index"] < len(parsed.events) or not _valid_label(
                ref["source_ref"]
            ):
                raise EvidenceError("SOURCE_REFERENCE_MISMATCH")
            grouped.setdefault(ref["record_index"], []).append(ref)
        enriched = []
        for index, event in enumerate(parsed.events):
            key = event_key(event.identity)
            identity = event.identity
            observed_identities[key] = (
                identity.source_kind,
                identity.account,
                identity.region,
                identity.event_id,
            )
            variant_key = (key, event.record_sha256)
            if (
                variant_key in observed_variants
                and observed_variants[variant_key] != event.canonical_record
            ):
                raise EvidenceError("RECORD_HASH_COLLISION")
            observed_variants[variant_key] = event.canonical_record
            if normalized.get(variant_key) != _normalized(event):
                raise EvidenceError("NORMALIZED_EVIDENCE_MISMATCH")
            refs = grouped.get(index, [])
            if not refs or any((r["event_key"], r["record_hash"]) != variant_key for r in refs):
                raise EvidenceError("SOURCE_REFERENCE_MISMATCH")
            enriched.append(
                replace(
                    event,
                    references=tuple(
                        RecordReference(
                            r["source_ref"], index, raw.archive_sha256, raw.content_sha256
                        )
                        for r in refs
                    ),
                )
            )
        result.append(ParsedLog(raw, tuple(enriched)))
    if by_raw or observed_identities != stored_identities or observed_variants != stored_variants:
        raise EvidenceError("STORE_EVIDENCE_MISMATCH")
    if any(
        (r["schema_version"], r["parser_version"], r["canonicalization_version"])
        != ("1.0", "1.0.0", "1.0")
        for r in variants
    ):
        raise EvidenceError("UNSUPPORTED_VERSION")
    variant_counts: dict[str, int] = {}
    for key, _ in observed_variants:
        variant_counts[key] = variant_counts.get(key, 0) + 1
    expected_conflicts = {key for key, count in variant_counts.items() if count > 1}
    conflicts = {
        row["event_key"] for row in conn.execute("SELECT event_key FROM csl.conflicts").fetchall()
    }
    if expected_conflicts != conflicts:
        raise EvidenceError("STORE_CONFLICT_MISMATCH")
    return result


def record_ingestion_error(db: Database, code: str, checkpoint: str) -> None:
    """Bounded quarantine metadata only: fixed reason and hash, never raw input text."""
    safe_code = code if code in _SOURCE_ERRORS else "SOURCE_VALIDATION_FAILURE"
    checkpoint_hash = (
        sha256(checkpoint.encode()).hexdigest() if _valid_label(checkpoint) else "invalid"
    )
    with db.connect() as conn, conn.transaction():
        db.check_schema(conn)
        conn.execute("SELECT singleton FROM csl.pipeline WHERE singleton FOR UPDATE")
        row = conn.execute("SELECT count(*) AS n FROM csl.ingestion_errors").fetchone()
        if not row or row["n"] >= MAX_INGESTION_ERRORS:
            raise EvidenceError("INGESTION_ERROR_LIMIT")
        conn.execute(
            "INSERT INTO csl.ingestion_errors(checkpoint,code) VALUES (%s,%s)",
            (checkpoint_hash, safe_code),
        )


def ingest(
    db: Database,
    sources: Sequence[tuple[str, bytes]],
    *,
    checkpoint: str,
    fault: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Commit before acknowledgment; permanent validation failures remain failures."""
    try:
        return _ingest(db, sources, checkpoint=checkpoint, fault=fault)
    except EvidenceError as exc:
        if exc.code in _SOURCE_ERRORS:
            try:
                record_ingestion_error(db, exc.code, checkpoint)
            except Exception:
                # A failed quarantine write cannot acknowledge or hide the original rejection.
                pass
        raise


def _ingest(
    db: Database,
    sources: Sequence[tuple[str, bytes]],
    *,
    checkpoint: str,
    fault: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Parse before the transaction; commit originals, references and required work together."""
    if not _valid_label(checkpoint):
        raise EvidenceError("INVALID_CHECKPOINT")
    if not 1 <= len(sources) <= 64:
        raise EvidenceError("STORE_LIMIT")
    # Budget parsing itself, rather than allocating 64 individually valid 100 MiB trees.
    logs: list[ParsedLog] = []
    cached: dict[str, ParsedLog] = {}
    compressed_total = expanded_total = record_total = 0
    for label, data in sources:
        if not isinstance(data, bytes):
            raise EvidenceError("INVALID_INPUT_TYPE")
        if not _valid_label(label):
            raise EvidenceError("INVALID_SOURCE_REFERENCE")
        digest = sha256(data).hexdigest()
        prior_log = cached.get(digest)
        if prior_log:
            if prior_log.evidence.archive_bytes != data:
                raise EvidenceError("ARCHIVE_HASH_COLLISION")
            raw = replace(prior_log.evidence, source_ref=label)
            events = tuple(
                replace(e, references=tuple(replace(ref, source_ref=label) for ref in e.references))
                for e in prior_log.events
            )
            log = ParsedLog(raw, events)
        else:
            compressed_total += len(data)
            if compressed_total > _MAX_BYTES:
                raise EvidenceError("STORE_LIMIT")
            remaining = _MAX_BYTES - expanded_total
            try:
                log = parse_bytes(
                    data, source_ref=label, limits=Limits(max_expanded_bytes=max(1, remaining))
                )
            except EvidenceError as exc:
                if exc.code == "EXPANDED_LIMIT" and remaining < _MAX_BYTES:
                    raise EvidenceError("STORE_LIMIT") from None
                raise
            expanded_total += len(log.evidence.content_bytes)
            if expanded_total > _MAX_BYTES:
                raise EvidenceError("STORE_LIMIT")
            cached[digest] = log
        record_total += len(log.events)
        if record_total > 10_000:
            raise EvidenceError("STORE_LIMIT")
        logs.append(log)
    requests = [(log.evidence.source_ref, log.evidence.archive_sha256) for log in logs]
    if len(set(requests)) != len(requests):
        raise EvidenceError("DUPLICATE_SOURCE_DELIVERY")
    if sum(len(log.events) for log in logs) > 10_000:
        raise EvidenceError("STORE_LIMIT")
    request_hash = sha256(json.dumps(sorted(requests), separators=(",", ":")).encode()).hexdigest()
    with db.connect() as conn:
        with conn.transaction():
            db.check_schema(conn)
            pipeline = conn.execute(
                "SELECT * FROM csl.pipeline WHERE singleton FOR UPDATE"
            ).fetchone()
            assert pipeline is not None
            load_logs(conn)
            prior = conn.execute(
                "SELECT * FROM csl.batches WHERE checkpoint=%s", (checkpoint,)
            ).fetchone()
            if prior:
                if prior["request_hash"] != request_hash:
                    raise EvidenceError("CHECKPOINT_CONFLICT")
                return _receipt(prior, pipeline["published_generation"])
            batch_count = conn.execute("SELECT count(*) AS n FROM csl.batches").fetchone()
            raw_delivery_count = conn.execute(
                "SELECT count(*) AS n FROM csl.raw_deliveries"
            ).fetchone()
            assert batch_count is not None and raw_delivery_count is not None
            if (
                batch_count["n"] >= MAX_BATCHES
                or raw_delivery_count["n"] + len(logs) > MAX_RAW_DELIVERIES
            ):
                raise EvidenceError("STORE_LIMIT")
            raw_rows = conn.execute("SELECT * FROM csl.raw_objects").fetchall()
            stored_raw = {r["raw_id"]: r for r in raw_rows}
            new_raw = {
                log.evidence.archive_sha256: log
                for log in logs
                if log.evidence.archive_sha256 not in stored_raw
            }
            for log in logs:
                prior_raw = stored_raw.get(log.evidence.archive_sha256)
                if prior_raw and bytes(prior_raw["archive_bytes"]) != log.evidence.archive_bytes:
                    raise EvidenceError("ARCHIVE_HASH_COLLISION")
            deliveries = conn.execute("SELECT count(*) AS n FROM csl.source_references").fetchone()
            assert deliveries is not None
            if (
                len(stored_raw) + len(new_raw) > 64
                or sum(len(r["archive_bytes"]) for r in raw_rows)
                + sum(len(log.evidence.archive_bytes) for log in new_raw.values())
                > _MAX_BYTES
                or sum(r["expanded_size"] for r in raw_rows)
                + sum(len(log.evidence.content_bytes) for log in new_raw.values())
                > _MAX_BYTES
                or deliveries["n"] + sum(len(log.events) for log in logs) > 10_000
            ):
                raise EvidenceError("STORE_LIMIT")
            variants = {
                (r["event_key"], r["record_hash"]): bytes(r["canonical_bytes"])
                for r in conn.execute("SELECT * FROM csl.record_variants").fetchall()
            }
            known_events = {
                r["event_key"] for r in conn.execute("SELECT event_key FROM csl.events").fetchall()
            }
            accepted = duplicate = conflicting = changed = 0
            new_conflicts: set[str] = set()
            for log in logs:
                for event in log.events:
                    key = event_key(event.identity)
                    variant_key = (key, event.record_sha256)
                    if variant_key in variants:
                        if variants[variant_key] != event.canonical_record:
                            raise EvidenceError("RECORD_HASH_COLLISION")
                        duplicate += 1
                    else:
                        changed += 1
                        if key in known_events:
                            conflicting += 1
                            new_conflicts.add(key)
                        else:
                            accepted += 1
                        known_events.add(key)
                        variants[variant_key] = event.canonical_record
            generation = pipeline["generation"] + int(changed > 0)
            batch_id = str(uuid4())
            conn.execute(
                "INSERT INTO csl.batches(batch_id,checkpoint,request_hash,status,generation,"
                "accepted_count,duplicate_count,conflicting_count,source_count) "
                "VALUES (%s,%s,%s,'committed',%s,%s,%s,%s,%s)",
                (
                    batch_id,
                    checkpoint,
                    request_hash,
                    generation,
                    accepted,
                    duplicate,
                    conflicting,
                    len(logs),
                ),
            )
            for log in new_raw.values():
                raw = log.evidence
                conn.execute(
                    "INSERT INTO csl.raw_objects(raw_id,source_ref,archive_bytes,archive_hash,"
                    "content_hash,expanded_size,record_count) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (
                        raw.archive_sha256,
                        raw.source_ref,
                        raw.archive_bytes,
                        raw.archive_sha256,
                        raw.content_sha256,
                        len(raw.content_bytes),
                        len(log.events),
                    ),
                )
            for log in logs:
                conn.execute(
                    "INSERT INTO csl.raw_deliveries(batch_id,raw_id,source_ref) VALUES (%s,%s,%s)",
                    (batch_id, log.evidence.archive_sha256, log.evidence.source_ref),
                )
                for index, event in enumerate(log.events):
                    key = event_key(event.identity)
                    identity = event.identity
                    conn.execute(
                        "INSERT INTO csl.events(event_key,source_kind,account,region,event_id) "
                        "VALUES "
                        "(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (
                            key,
                            identity.source_kind,
                            identity.account,
                            identity.region,
                            identity.event_id,
                        ),
                    )
                    conn.execute(
                        "INSERT INTO csl.record_variants(event_key,record_hash,canonical_bytes,"
                        "normalized) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                        (
                            key,
                            event.record_sha256,
                            event.canonical_record,
                            Jsonb(_normalized(event)),
                        ),
                    )
                    conn.execute(
                        "INSERT INTO csl.source_references(batch_id,raw_id,source_ref,"
                        "record_index,event_key,record_hash) VALUES (%s,%s,%s,%s,%s,%s)",
                        (
                            batch_id,
                            log.evidence.archive_sha256,
                            log.evidence.source_ref,
                            index,
                            key,
                            event.record_sha256,
                        ),
                    )
            for key in new_conflicts:
                conn.execute(
                    "INSERT INTO csl.conflicts(event_key,detected_generation) VALUES (%s,%s) ON "
                    "CONFLICT DO NOTHING",
                    (key, generation),
                )
            conn.execute(
                "INSERT INTO csl.checkpoints(checkpoint,batch_id,generation) VALUES (%s,%s,%s)",
                (checkpoint, batch_id, generation),
            )
            if changed:
                conn.execute("UPDATE csl.pipeline SET generation=%s WHERE singleton", (generation,))
                conn.execute("UPDATE csl.findings SET status='pending' WHERE status='current'")
                conn.execute("UPDATE csl.cases SET status='pending' WHERE status='current'")
                conn.execute(
                    "INSERT INTO csl.jobs(job_id,generation) VALUES (%s,%s)",
                    (str(uuid4()), generation),
                )
            conn.execute(
                "INSERT INTO csl.audit(kind,payload) VALUES ('ingestion_committed',%s)",
                (Jsonb({"batch_id": batch_id, "generation": generation}),),
            )
            if fault:
                fault("before_ingest_commit")
            row = {
                "batch_id": batch_id,
                "checkpoint": checkpoint,
                "generation": generation,
                "accepted_count": accepted,
                "duplicate_count": duplicate,
                "conflicting_count": conflicting,
            }
        # Outer connection is not an outer transaction: explicit transaction committed.
        if fault:
            fault("after_ingest_commit")
        return _receipt(row, pipeline["published_generation"])


def _verify_case_links(
    findings: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    revisions: list[dict[str, Any]],
    lineage: list[dict[str, Any]],
) -> None:
    revision_map = {(r["case_id"], r["revision"]): r for r in revisions}
    by_finding = {r["finding_id"]: r for r in findings}
    by_case = {r["case_id"]: r for r in cases}
    covered: dict[str, int] = {}
    expected_lineage: set[tuple[str, str, int]] = set()
    for case in cases:
        latest = revision_map.get((case["case_id"], case["current_revision"]))
        if not latest:
            raise EvidenceError("CASE_HISTORY_MISMATCH")
        finding = by_finding.get(latest["finding_id"])
        if case["status"] in {"current", "pending"}:
            if not finding or finding["status"] != case["status"]:
                raise EvidenceError("CASE_FINDING_COVERAGE_MISMATCH")
            covered[latest["finding_id"]] = covered.get(latest["finding_id"], 0) + 1
        successor = latest["payload"].get("superseded_by")
        if case["status"] == "superseded" or successor is not None:
            child_initial = revision_map.get((successor, 1)) if isinstance(successor, str) else None
            if (
                case["status"] != "superseded"
                or not isinstance(successor, str)
                or successor not in by_case
                or successor == case["case_id"]
                or not child_initial
                or child_initial["generation"] != latest["generation"]
            ):
                raise EvidenceError("CASE_LINEAGE_MISMATCH")
            expected_lineage.add((case["case_id"], successor, latest["generation"]))
    active_findings = {r["finding_id"] for r in findings if r["status"] in {"current", "pending"}}
    if set(covered) != active_findings or any(count != 1 for count in covered.values()):
        raise EvidenceError("CASE_FINDING_COVERAGE_MISMATCH")
    stored_lineage = {(r["parent_case_id"], r["child_case_id"], r["generation"]) for r in lineage}
    if stored_lineage != expected_lineage or len(stored_lineage) != len(lineage):
        raise EvidenceError("CASE_LINEAGE_MISMATCH")


def verify_store(db: Database) -> dict[str, object]:
    """Validate originals, derivatives and complete revision/outbox history together."""
    from cloudsecops_live.cases import evidence_fingerprint
    from cloudsecops_live.detection import detect

    with db.connect() as conn, conn.transaction():
        db.check_schema(conn)
        pipeline = conn.execute("SELECT * FROM csl.pipeline WHERE singleton FOR UPDATE").fetchone()
        assert pipeline is not None
        logs = load_logs(conn)
        generation = pipeline["generation"]
        published = pipeline["published_generation"]
        jobs = conn.execute("SELECT * FROM csl.jobs").fetchall()
        batches = conn.execute("SELECT * FROM csl.batches").fetchall()
        expected_generations = set(range(1, generation + 1))
        if {row["generation"] for row in jobs} != expected_generations or {
            row["generation"]
            for row in batches
            if row["accepted_count"] + row["conflicting_count"] > 0
        } != expected_generations:
            raise EvidenceError("STORE_GENERATION_MISMATCH")
        if published and not any(
            row["generation"] == published and row["status"] == "succeeded" for row in jobs
        ):
            raise EvidenceError("STORE_GENERATION_MISMATCH")
        available = {
            (event_key(e.identity), e.record_sha256): e for log in logs for e in log.events
        }
        findings = conn.execute("SELECT * FROM csl.findings").fetchall()
        by_finding = {row["finding_id"]: row for row in findings}
        finding_timelines: dict[str, list[dict[str, object]]] = {}
        for row in findings:
            refs = conn.execute(
                "SELECT event_key,record_hash FROM csl.finding_evidence WHERE finding_id=%s",
                (row["finding_id"],),
            ).fetchall()
            selected = [available.get((ref["event_key"], ref["record_hash"])) for ref in refs]
            if not selected or any(event is None for event in selected):
                raise EvidenceError("FINDING_EVIDENCE_MISMATCH")
            chosen = [event for event in selected if event is not None]
            report = detect([ParsedLog(logs[0].evidence, tuple(chosen))])
            matching = [
                f
                for f in report.findings
                if f.finding_id == row["finding_id"] and f.to_dict() == row["payload"]
            ]
            if not 1 <= row["generation"] <= generation or len(matching) != 1:
                raise EvidenceError("FINDING_EVIDENCE_MISMATCH")
            finding_timelines[row["finding_id"]] = [
                {
                    "identity": asdict(event.identity),
                    "event_time": event.event_time.isoformat().replace("+00:00", "Z"),
                    "record_sha256": event.record_sha256,
                }
                for event in matching[0].evidence
            ]
        current_findings = {row["finding_id"] for row in findings if row["status"] == "current"}
        if published == generation:
            if current_findings != {f.finding_id for f in detect(logs).findings}:
                raise EvidenceError("CURRENT_FINDING_MISMATCH")
        elif current_findings:
            raise EvidenceError("CURRENT_FINDING_MISMATCH")
        revisions = conn.execute("SELECT * FROM csl.case_revisions").fetchall()
        revision_map = {(r["case_id"], r["revision"]): r for r in revisions}
        timelines = conn.execute("SELECT * FROM csl.case_timeline").fetchall()
        outbox = conn.execute("SELECT * FROM csl.outbox").fetchall()
        for row in revisions:
            payload = row["payload"]
            key = (row["case_id"], row["revision"])
            body = {
                k: v for k, v in payload.items() if k not in {"case_id", "revision", "case_status"}
            }
            if (
                payload.get("case_id") != row["case_id"]
                or payload.get("revision") != row["revision"]
                or payload.get("case_status") != row["status"]
                or payload.get("unreviewed") is not True
                or not 1 <= row["generation"] <= generation
                or evidence_fingerprint(body) != row["fingerprint"]
            ):
                raise EvidenceError("CASE_REVISION_MISMATCH")
            finding = by_finding.get(row["finding_id"])
            if not finding or any(payload.get(k) != v for k, v in finding["payload"].items()):
                raise EvidenceError("CASE_REVISION_MISMATCH")
            if payload.get("event_timeline") != finding_timelines.get(row["finding_id"]):
                raise EvidenceError("CASE_EVENT_TIMELINE_MISMATCH")
            timeline = [t for t in timelines if (t["case_id"], t["revision"]) == key]
            messages = [o for o in outbox if (o["case_id"], o["revision"]) == key]
            if (
                len(timeline) != 1
                or timeline[0]["payload"] != payload
                or timeline[0]["kind"] != "draft_revision"
                or len(messages) != 1
            ):
                raise EvidenceError("CASE_HISTORY_MISMATCH")
            message = messages[0]
            expected_key = evidence_fingerprint(
                {"domain": "offline-outbox/1", "case": row["case_id"], "rev": row["revision"]}
            )
            expected_payload = {
                "source_kind": "synthetic",
                "authenticated": False,
                "delivery_class": "offline_test_only",
                "case_id": row["case_id"],
                "revision": row["revision"],
                "case_status": row["status"],
                "evidence_fingerprint": row["fingerprint"],
                "finding_id": row["finding_id"],
            }
            if (
                message["outbox_id"] != expected_key
                or message["idempotency_key"] != expected_key
                or message["payload"] != expected_payload
            ):
                raise EvidenceError("OUTBOX_REVISION_MISMATCH")
        cases = conn.execute("SELECT * FROM csl.cases").fetchall()
        for case in cases:
            history = [r for r in revisions if r["case_id"] == case["case_id"]]
            latest = revision_map.get((case["case_id"], case["current_revision"]))
            if (
                not latest
                or {r["revision"] for r in history} != set(range(1, case["current_revision"] + 1))
                or (case["status"] != "pending" and case["status"] != latest["status"])
                or (case["status"] == "pending" and latest["status"] != "current")
                or (published < generation and case["status"] == "current")
            ):
                raise EvidenceError("CASE_HISTORY_MISMATCH")
        _verify_case_links(
            findings,
            cases,
            revisions,
            conn.execute("SELECT * FROM csl.case_lineage").fetchall(),
        )
        sink = {
            r["idempotency_key"]: r
            for r in conn.execute("SELECT * FROM csl.offline_sink").fetchall()
        }
        for message in outbox:
            receipt = sink.pop(message["idempotency_key"], None)
            if receipt and (
                receipt["payload"] != message["payload"]
                or evidence_fingerprint(receipt["payload"]) != receipt["payload_hash"]
            ):
                raise EvidenceError("OUTBOX_RECEIPT_MISMATCH")
            if message["status"] == "locally_acknowledged" and not receipt:
                raise EvidenceError("OUTBOX_RECEIPT_MISMATCH")
        if sink:
            raise EvidenceError("OUTBOX_RECEIPT_MISMATCH")
        counts = {
            table: conn.execute(f"SELECT count(*) AS n FROM csl.{table}").fetchone()
            for table in ("raw_objects", "events", "record_variants", "source_references")
        }
        return {
            "verified": True,
            "generation": generation,
            **{table: row["n"] for table, row in counts.items() if row is not None},
        }
