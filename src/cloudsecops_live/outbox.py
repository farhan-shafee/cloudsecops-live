"""Transactional delivery to an idempotent LOCAL TEST sink, never a SIEM receipt."""

from collections.abc import Callable
from uuid import uuid4

from psycopg.types.json import Jsonb

from cloudsecops_live.cases import evidence_fingerprint
from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.worker import _fault


def deliver_once(
    db: Database,
    *,
    fault: Callable[[str], None] | None = None,
    lease_seconds: int = 30,
) -> dict[str, object]:
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
        raise EvidenceError("INVALID_LEASE")
    token = str(uuid4())
    with db.connect() as conn:
        db.check_schema(conn)
        committed = conn.execute(
            "SELECT o.* FROM csl.outbox o JOIN csl.offline_sink s "
            "ON s.idempotency_key=o.idempotency_key "
            "WHERE o.status IN ('retryable','failed') OR "
            "(o.status='attempted' AND o.lease_until<=clock_timestamp()) "
            "ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT 1"
        ).fetchone()
        if committed is not None:
            sink = conn.execute(
                "SELECT payload,payload_hash FROM csl.offline_sink WHERE idempotency_key=%s",
                (committed["idempotency_key"],),
            ).fetchone()
            if (
                sink is None
                or sink["payload"] != committed["payload"]
                or sink["payload_hash"] != evidence_fingerprint(committed["payload"])
            ):
                raise EvidenceError("SINK_CONFLICT")
            _fault(fault, "before_outbox_ack")
            conn.execute(
                "UPDATE csl.outbox SET status='locally_acknowledged',"
                "acknowledged_at=clock_timestamp(),claim_token=NULL,lease_until=NULL,"
                "last_error=NULL "
                "WHERE outbox_id=%s",
                (committed["outbox_id"],),
            )
            conn.execute(
                "INSERT INTO csl.audit(kind,payload) VALUES ('outbox_receipt_reconciled',%s)",
                (
                    Jsonb(
                        {"outbox_id": committed["outbox_id"], "delivery_class": "offline_test_only"}
                    ),
                ),
            )
            # A matching sink receipt already committed; reconciling it consumes no new attempt.
            reconciled = committed["outbox_id"]
        else:
            reconciled = None
    if reconciled is not None:
        _fault(fault, "after_outbox_ack")
        return {
            "status": "locally_acknowledged",
            "outbox_id": reconciled,
            "delivery_class": "offline_test_only",
            "searchable_siem_alert": False,
            "reconciled": True,
        }
    with db.connect() as conn:
        db.check_schema(conn)
        conn.execute(
            "UPDATE csl.outbox SET status='failed',claim_token=NULL,lease_until=NULL,"
            "last_error='RETRIES_EXHAUSTED' WHERE attempts>=max_attempts "
            "AND (status='retryable' OR (status='attempted' AND lease_until<=clock_timestamp()))"
        )
        row = conn.execute(
            "SELECT * FROM csl.outbox WHERE attempts<max_attempts AND "
            "(status IN ('queued','retryable') OR (status='attempted' "
            "AND lease_until<=clock_timestamp())) ORDER BY created_at,outbox_id "
            "FOR UPDATE SKIP LOCKED LIMIT 1"
        ).fetchone()
        if row is None:
            return {"status": "idle"}
        conn.execute(
            "UPDATE csl.outbox SET status='attempted',attempts=attempts+1,claim_token=%s,"
            "lease_until=clock_timestamp()+(%s * interval '1 second') WHERE outbox_id=%s",
            (token, lease_seconds, row["outbox_id"]),
        )
        conn.execute(
            "INSERT INTO csl.audit(kind,payload) VALUES ('outbox_attempt',%s)",
            (Jsonb({"outbox_id": row["outbox_id"], "attempt": row["attempts"] + 1}),),
        )
    try:
        _fault(fault, "after_outbox_claim")
        payload_hash = evidence_fingerprint(row["payload"])
        # Sink commit deliberately precedes the sender's acknowledgment. A retry sees the same key.
        with db.connect() as conn:
            db.check_schema(conn)
            live = conn.execute(
                "SELECT outbox_id FROM csl.outbox WHERE outbox_id=%s AND status='attempted' "
                "AND claim_token=%s AND lease_until>clock_timestamp() FOR UPDATE",
                (row["outbox_id"], token),
            ).fetchone()
            if live is None:
                raise EvidenceError("LOST_LEASE")
            conn.execute(
                "INSERT INTO csl.offline_sink(idempotency_key,payload,payload_hash) "
                "VALUES (%s,%s,%s) "
                "ON CONFLICT (idempotency_key) DO NOTHING",
                (row["idempotency_key"], Jsonb(row["payload"]), payload_hash),
            )
            receipt = conn.execute(
                "SELECT payload,payload_hash FROM csl.offline_sink WHERE idempotency_key=%s",
                (row["idempotency_key"],),
            ).fetchone()
            if (
                not receipt
                or receipt["payload_hash"] != payload_hash
                or receipt["payload"] != row["payload"]
            ):
                raise EvidenceError("SINK_CONFLICT")
            _fault(fault, "before_sink_commit")
        _fault(fault, "after_sink_commit")
        with db.connect() as conn:
            db.check_schema(conn)
            _fault(fault, "before_outbox_ack")
            acknowledged = conn.execute(
                "UPDATE csl.outbox SET status='locally_acknowledged',"
                "acknowledged_at=clock_timestamp(),"
                "claim_token=NULL,lease_until=NULL,last_error=NULL WHERE outbox_id=%s "
                "AND status='attempted' AND claim_token=%s AND lease_until>clock_timestamp() "
                "RETURNING outbox_id",
                (row["outbox_id"], token),
            ).fetchone()
            if acknowledged is None:
                raise EvidenceError("LOST_LEASE")
            conn.execute(
                "INSERT INTO csl.audit(kind,payload) VALUES ('outbox_local_ack',%s)",
                (Jsonb({"outbox_id": row["outbox_id"], "delivery_class": "offline_test_only"}),),
            )
        _fault(fault, "after_outbox_ack")
        return {
            "status": "locally_acknowledged",
            "outbox_id": row["outbox_id"],
            "delivery_class": "offline_test_only",
            "searchable_siem_alert": False,
        }
    except Exception:
        try:
            with db.connect() as conn:
                db.check_schema(conn)
                conn.execute(
                    "UPDATE csl.outbox SET status=CASE WHEN attempts>=max_attempts THEN 'failed' "
                    "ELSE 'retryable' END,claim_token=NULL,lease_until=NULL,"
                    "last_error='DELIVERY_FAILURE' "
                    "WHERE outbox_id=%s AND status='attempted' AND claim_token=%s "
                    "AND lease_until>clock_timestamp()",
                    (row["outbox_id"], token),
                )
        except Exception:
            pass
        raise
