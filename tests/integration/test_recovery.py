"""Real child-process death plus injected faults; these are separate mechanisms."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from cloudsecops_live.storage import ingest, verify_store
from cloudsecops_live.worker import work_once
from tests.helpers import archive, event
from tests.integration.support import add, current, explode_fault, one


@pytest.mark.parametrize(
    "point,saved", [("before_ingest_commit", False), ("after_ingest_commit", True)]
)
def test_controlled_ingestion_fault_is_atomic_and_checkpoint_replays(db, point, saved):
    sources = [("synthetic/replay.gz", archive([event("e0"), event("e20", 20), event("e40", 40)]))]
    with pytest.raises(RuntimeError, match="controlled_test_fault"):
        ingest(db, sources, checkpoint="replay", fault=explode_fault(point))
    assert verify_store(db)["raw_objects"] == int(saved)
    result = ingest(db, sources, checkpoint="replay")
    # A checkpoint replay returns its original durable receipt, not a new batch.
    assert result["accepted"] == 3
    assert one(db, "SELECT count(*) AS n FROM csl.batches")["n"] == 1
    assert one(db, "SELECT count(*) AS n FROM csl.source_references")["n"] == 3
    assert verify_store(db)["events"] == 3
    assert work_once(db)["status"] == "succeeded"
    assert len(current(db)) == 1
    assert work_once(db)["status"] == "idle"


CHILD = """
import json, os, sys, time
from pathlib import Path
from cloudsecops_live.database import Database
from cloudsecops_live.worker import claim_job, run_job
db = Database(os.environ['CSL_CHILD_DSN'])
claim = claim_job(db)
def fault(point):
    if point == sys.argv[1]:
        Path(sys.argv[2]).write_text('reached', encoding='utf-8')
        while True:
            time.sleep(0.05)
run_job(db, claim, fault=fault)
"""


@pytest.mark.parametrize("point,saved", [("before_job_commit", False), ("after_job_commit", True)])
def test_genuine_subprocess_termination_at_worker_transaction_boundary(db, tmp_path, point, saved):
    add(db, [0, 20, 40])
    marker = tmp_path / "fault-reached"
    env = os.environ.copy()
    env["CSL_CHILD_DSN"] = make_conninfo(**db._values)
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, point, str(marker)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "Child did not reach the declared transaction boundary"
        child.kill()
        assert child.wait(timeout=10) != 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    assert bool(current(db)) is saved
    if not saved:
        with db.connect() as conn:
            conn.execute(
                "UPDATE csl.jobs SET lease_until=clock_timestamp()-interval '1 second' "
                "WHERE status='leased'"
            )
        assert work_once(db)["status"] == "succeeded"
    assert one(db, "SELECT count(*) AS n FROM csl.case_revisions")["n"] == 1
    assert work_once(db)["status"] == "idle"
    assert verify_store(db)["verified"] is True


def test_actual_database_connection_interruption_rolls_back_then_recovers(db):
    add(db, [0, 20, 40])
    # Interrupt only this test's open connection, never a container or unrelated DB.
    victim = db.connect()
    try:
        victim.execute("UPDATE csl.jobs SET last_error='uncommitted'")
        pid = victim.info.backend_pid
        with db.connect() as control:
            terminated = control.execute(
                "SELECT pg_terminate_backend(%s) AS stopped", (pid,)
            ).fetchone()
        assert terminated["stopped"] is True
        with pytest.raises(psycopg.Error):
            victim.commit()
    finally:
        victim.close()
    assert one(db, "SELECT last_error FROM csl.jobs")["last_error"] is None
    assert work_once(db)["status"] == "succeeded"
    assert verify_store(db)["verified"] is True
