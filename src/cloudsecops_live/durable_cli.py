"""Explicit offline persistence commands; private DSNs never enter output."""

import json
from collections.abc import Sequence
from pathlib import Path

import psycopg

from cloudsecops_live.cli import _error, _load, _Parser
from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.outbox import deliver_once
from cloudsecops_live.storage import ingest, record_ingestion_error, verify_store
from cloudsecops_live.worker import work_once


def _database(path: str) -> Database:
    try:
        file = Path(path)
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 4096:
            raise ValueError
        with file.open("rb") as handle:
            data = handle.read(4097)
        if len(data) > 4096:
            raise ValueError
        config = json.loads(data)
        if not isinstance(config, dict) or not isinstance(config.get("dsn"), str):
            raise ValueError
        return Database(config["dsn"])
    except (OSError, ValueError, TypeError):
        raise EvidenceError("INVALID_DATABASE_CONFIG") from None


def _status(db: Database) -> dict[str, object]:
    with db.connect() as conn:
        db.check_schema(conn)
        state = conn.execute("SELECT generation,published_generation FROM csl.pipeline").fetchone()
        if state is None:
            raise EvidenceError("SCHEMA_INCOMPATIBLE")
        output: dict[str, object] = dict(state)
        for table in ("jobs", "outbox", "cases", "findings"):
            # Identifiers are fixed constants, never request input.
            rows = conn.execute(
                f"SELECT status,count(*) AS count FROM csl.{table} GROUP BY status"
            ).fetchall()
            output[table] = {row["status"]: row["count"] for row in rows}
        output["pending"] = state["generation"] != state["published_generation"]
        return output


def main(argv: Sequence[str]) -> int:
    parser = _Parser(description="Bounded local synthetic evidence persistence; no cloud access.")
    parser.add_argument(
        "command",
        choices=(
            "db-migrate",
            "db-ingest",
            "db-work",
            "db-deliver",
            "db-status",
            "db-cases",
            "db-verify",
        ),
    )
    parser.add_argument("--config", default=".tools/private/local-postgres.json")
    parser.add_argument("--checkpoint")
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("paths", nargs="*")
    try:
        args = parser.parse_args(argv)
        if not 1 <= args.limit <= 64 or (args.command == "db-ingest" and not args.checkpoint):
            raise EvidenceError("USAGE")
        if (args.command == "db-ingest") != bool(args.paths):
            raise EvidenceError("USAGE")
        db = _database(args.config)
        status = 0
        if args.command == "db-migrate":
            db.migrate()
            result: dict[str, object] = {"schema_version": 1, "status": "migrated"}
        elif args.command == "db-ingest":
            try:
                logs = _load(args.paths)
            except EvidenceError as error:
                record_ingestion_error(db, error.code, args.checkpoint)
                raise
            result = ingest(
                db,
                [(log.evidence.source_ref, log.evidence.archive_bytes) for log in logs],
                checkpoint=args.checkpoint,
            )
            result["acknowledgment"] = (
                "ingestion_committed; detection remains separate durable work"
            )
            status = 3 if result.get("conflicting", 0) else 0
        elif args.command in {"db-work", "db-deliver"}:
            operations = []
            operation = work_once if args.command == "db-work" else deliver_once
            for _ in range(args.limit):
                receipt = operation(db)
                operations.append(receipt)
                if receipt["status"] == "idle":
                    break
            result = {"operations": operations, **_status(db)}
            if args.command == "db-work" and result["pending"]:
                status = 75
            if args.command == "db-deliver":
                queued = result["outbox"]
                if isinstance(queued, dict) and any(k != "locally_acknowledged" for k in queued):
                    status = 75
        elif args.command == "db-verify":
            result = verify_store(db)
        elif args.command == "db-cases":
            with db.connect() as conn:
                db.check_schema(conn)
                rows = conn.execute(
                    "SELECT c.case_id,c.current_revision,c.status,r.payload,r.fingerprint "
                    "FROM csl.cases c JOIN csl.case_revisions r "
                    "ON (r.case_id,r.revision)=(c.case_id,c.current_revision) ORDER BY c.case_id"
                ).fetchall()
                result = {"cases": rows}
        else:
            result = _status(db)
        result.update(
            {
                "operation": args.command,
                "source_kind": "synthetic",
                "authenticated": False,
                "limitations": [
                    "Unreviewed synthetic lab evidence only; hashes do not authenticate AWS.",
                    "Local test sink receipts establish no searchable SIEM delivery.",
                ],
            }
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return status
    except EvidenceError as error:
        return _error(error.code, 64 if error.code == "USAGE" else 2)
    except psycopg.Error:
        return _error("DATABASE_OPERATION_FAILED", 75)
    except Exception:
        return _error("INTERNAL_ERROR", 70)
