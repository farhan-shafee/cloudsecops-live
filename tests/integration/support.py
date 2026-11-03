"""Independent fixture data and read-only acceptance observations."""

from __future__ import annotations

from typing import Any

from cloudsecops_live.database import Database
from cloudsecops_live.storage import ingest
from tests.helpers import archive, event


def add(db: Database, seconds: list[int], checkpoint: str = "first") -> dict[str, Any]:
    return ingest(
        db,
        [(f"synthetic/{checkpoint}.json.gz", archive([event(f"e{t}", t) for t in seconds]))],
        checkpoint=checkpoint,
    )


def rows(db: Database, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return list(conn.execute(query, params).fetchall())


def one(db: Database, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    result = rows(db, query, params)
    assert len(result) == 1
    return result[0]


def current(db: Database) -> list[dict[str, Any]]:
    return rows(
        db,
        "SELECT c.case_id,c.current_revision,c.status,r.payload,r.fingerprint "
        "FROM csl.cases c JOIN csl.case_revisions r "
        "ON r.case_id=c.case_id AND r.revision=c.current_revision "
        "WHERE c.status='current' ORDER BY c.case_id",
    )


def explode_fault(point: str):
    def fault(actual: str) -> None:
        if actual == point:
            raise RuntimeError("controlled_test_fault:" + point)

    return fault
