"""Finite PostgreSQL work claiming with database-clock leases and fenced commits."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from psycopg.types.json import Jsonb

from cloudsecops_live.cases import publish
from cloudsecops_live.database import Database
from cloudsecops_live.detection import detect
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import load_logs


@dataclass(frozen=True, slots=True)
class Claim:
    job_id: str
    token: str
    generation: int
    attempt: int


def _fault(fault: Callable[[str], None] | None, point: str) -> None:
    if fault is not None:
        fault(point)


def claim_job(db: Database, *, lease_seconds: int = 30) -> Claim | None:
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
        raise EvidenceError("INVALID_LEASE")
    token = str(uuid4())
    with db.connect() as conn:
        db.check_schema(conn)
        conn.execute(
            "UPDATE csl.jobs SET status='dead',claim_token=NULL,lease_until=NULL,"
            "last_error='RETRIES_EXHAUSTED',completed_at=clock_timestamp() "
            "WHERE attempts>=max_attempts AND (status='retryable' OR "
            "(status='leased' AND lease_until<=clock_timestamp()))"
        )
        row = conn.execute(
            "SELECT job_id,generation,attempts FROM csl.jobs WHERE attempts<max_attempts "
            "AND (status IN ('queued','retryable') OR "
            "(status='leased' AND lease_until<=clock_timestamp())) "
            "ORDER BY generation DESC,job_id FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE csl.jobs SET status='leased',claim_token=%s,"
            "lease_until=clock_timestamp()+(%s * interval '1 second'),attempts=attempts+1 "
            "WHERE job_id=%s",
            (token, lease_seconds, row["job_id"]),
        )
        conn.execute(
            "INSERT INTO csl.job_attempts(job_id,attempt,token) VALUES (%s,%s,%s)",
            (row["job_id"], row["attempts"] + 1, token),
        )
        conn.execute(
            "INSERT INTO csl.audit(kind,payload) VALUES ('job_claim',%s)",
            (Jsonb({"job_id": row["job_id"], "attempt": row["attempts"] + 1}),),
        )
    return Claim(row["job_id"], token, row["generation"], row["attempts"] + 1)


def _record_failure(db: Database, claim: Claim, code: str) -> None:
    # This separate transaction records failure only if this worker still owns a live lease.
    with db.connect() as conn:
        db.check_schema(conn)
        changed = conn.execute(
            "UPDATE csl.jobs SET status=CASE WHEN attempts>=max_attempts THEN 'dead' "
            "ELSE 'retryable' END,claim_token=NULL,lease_until=NULL,last_error=%s "
            "WHERE job_id=%s AND status='leased' AND claim_token=%s "
            "AND lease_until>clock_timestamp() RETURNING job_id",
            (code, claim.job_id, claim.token),
        ).fetchone()
        if changed:
            conn.execute(
                "UPDATE csl.job_attempts SET result=%s,finished_at=clock_timestamp() "
                "WHERE job_id=%s AND attempt=%s AND token=%s",
                (code, claim.job_id, claim.attempt, claim.token),
            )
            conn.execute(
                "INSERT INTO csl.audit(kind,payload) VALUES ('job_failure',%s)",
                (Jsonb({"job_id": claim.job_id, "code": code}),),
            )


def run_job(
    db: Database,
    claim: Claim,
    *,
    fault: Callable[[str], None] | None = None,
) -> dict[str, object]:
    try:
        with db.connect() as conn:
            db.check_schema(conn)
            state = conn.execute("SELECT * FROM csl.pipeline WHERE singleton FOR UPDATE").fetchone()
            row = conn.execute(
                "SELECT *,lease_until>clock_timestamp() AS live FROM csl.jobs "
                "WHERE job_id=%s FOR UPDATE",
                (claim.job_id,),
            ).fetchone()
            if (
                not row
                or row["status"] != "leased"
                or row["claim_token"] != claim.token
                or not row["live"]
            ):
                raise EvidenceError("LOST_LEASE")
            if state is None:
                raise EvidenceError("MISSING_PIPELINE")
            if row["generation"] != state["generation"]:
                status = "superseded"
                counts: dict[str, Any] = {"findings": 0, "case_revisions": 0}
            else:
                report = detect(load_logs(conn))
                counts = publish(conn, report, row["generation"])
                counts["conflicts"] = len(report.conflicts)
                conn.execute(
                    "UPDATE csl.pipeline SET published_generation=%s WHERE singleton",
                    (row["generation"],),
                )
                status = "succeeded"
            changed = conn.execute(
                "UPDATE csl.jobs SET status=%s,claim_token=NULL,lease_until=NULL,"
                "completed_at=clock_timestamp(),last_error=NULL "
                "WHERE job_id=%s AND claim_token=%s AND lease_until>clock_timestamp() "
                "RETURNING job_id",
                (status, claim.job_id, claim.token),
            ).fetchone()
            if changed is None:
                raise EvidenceError("LOST_LEASE")
            conn.execute(
                "UPDATE csl.job_attempts SET result=%s,finished_at=clock_timestamp() "
                "WHERE job_id=%s AND attempt=%s AND token=%s",
                (status, claim.job_id, claim.attempt, claim.token),
            )
            conn.execute(
                "INSERT INTO csl.audit(kind,payload) VALUES ('job_completed',%s)",
                (Jsonb({"job_id": claim.job_id, "status": status, **counts}),),
            )
            _fault(fault, "before_job_commit")
        _fault(fault, "after_job_commit")
        return {"status": status, "job_id": claim.job_id, **counts}
    except Exception as exc:
        # Never leak source text; failure recording cannot turn a failed operation into success.
        code = exc.code if isinstance(exc, EvidenceError) else "WORKER_FAILURE"
        try:
            _record_failure(db, claim, code)
        except Exception:
            pass
        raise


def work_once(db: Database) -> dict[str, object]:
    claim = claim_job(db)
    return {"status": "idle"} if claim is None else run_job(db, claim)
