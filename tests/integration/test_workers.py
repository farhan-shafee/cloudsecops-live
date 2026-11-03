"""Claims, fencing and commit boundaries against real PostgreSQL transactions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.worker import claim_job, run_job, work_once
from tests.integration.support import add, current, explode_fault, one


def test_simultaneous_claimers_cannot_both_own_one_job(db):
    add(db, [0, 20, 40])
    start = Barrier(2)

    def claim():
        start.wait(timeout=10)
        return claim_job(db)

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: claim(), range(2)))
    winners = [claim for claim in claims if claim is not None]
    assert len(winners) == 1
    assert run_job(db, winners[0])["status"] == "succeeded"
    assert len(current(db)) == 1
    assert work_once(db)["status"] == "idle"


def test_active_lease_blocks_claim_and_expired_token_cannot_publish(db):
    add(db, [0, 20, 40])
    old = claim_job(db)
    assert old is not None
    assert claim_job(db) is None
    with db.connect() as conn:
        conn.execute(
            "UPDATE csl.jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=%s",
            (old.job_id,),
        )
    new = claim_job(db)
    assert new is not None and new.token != old.token
    with pytest.raises(EvidenceError, match="LOST_LEASE"):
        run_job(db, old)
    assert current(db) == []
    assert run_job(db, new)["status"] == "succeeded"
    assert len(current(db)) == 1


def test_expired_final_attempt_becomes_terminal_without_another_claim(db):
    add(db, [0, 20, 40])
    with db.connect() as conn:
        conn.execute("UPDATE csl.jobs SET max_attempts=1")
    claim = claim_job(db)
    assert claim is not None
    with db.connect() as conn:
        conn.execute("UPDATE csl.jobs SET lease_until=clock_timestamp()-interval '1 second'")
    assert claim_job(db) is None
    job = one(db, "SELECT status,attempts FROM csl.jobs")
    assert job == {"status": "dead", "attempts": 1}
    assert current(db) == []


@pytest.mark.parametrize("point,saved", [("before_job_commit", False), ("after_job_commit", True)])
def test_controlled_worker_fault_commit_boundary(db, point, saved):
    add(db, [0, 20, 40])
    claim = claim_job(db)
    assert claim is not None
    with pytest.raises(RuntimeError, match="controlled_test_fault"):
        run_job(db, claim, fault=explode_fault(point))
    assert bool(current(db)) is saved
    if saved:
        assert one(db, "SELECT status FROM csl.jobs")["status"] == "succeeded"
        assert work_once(db)["status"] == "idle"
    else:
        with db.connect() as conn:
            conn.execute(
                "UPDATE csl.jobs SET lease_until=clock_timestamp()-interval '1 second' "
                "WHERE status='leased'"
            )
        assert work_once(db)["status"] == "succeeded"
    assert one(db, "SELECT count(*) AS n FROM csl.case_revisions")["n"] == 1


def test_new_generation_fences_older_snapshot_even_with_valid_lease(db):
    add(db, [0, 20, 40])
    claim = claim_job(db)
    assert claim is not None
    add(db, [10], "newer")
    assert run_job(db, claim)["status"] == "superseded"
    assert current(db) == []
    assert work_once(db)["status"] == "succeeded"
    assert current(db)[0]["payload"]["evidence_event_ids"] == ["e0", "e10", "e20", "e40"]


def test_corrupt_supporting_original_never_becomes_successful_empty_detection(db):
    add(db, [0, 20, 40])
    # Model owner-level restored-data corruption, then restore the expected schema.
    with db.connect() as conn:
        conn.execute("ALTER TABLE csl.raw_objects DISABLE TRIGGER immutable_history")
        conn.execute("UPDATE csl.raw_objects SET content_hash=repeat('0',64)")
        conn.execute("ALTER TABLE csl.raw_objects ENABLE TRIGGER immutable_history")
    with pytest.raises(EvidenceError, match="RAW_EVIDENCE_MISMATCH"):
        work_once(db)
    assert current(db) == []
    assert one(db, "SELECT status,last_error FROM csl.jobs") == {
        "status": "retryable",
        "last_error": "RAW_EVIDENCE_MISMATCH",
    }
    assert one(db, "SELECT published_generation FROM csl.pipeline")["published_generation"] == 0
