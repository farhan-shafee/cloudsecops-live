"""A published generation is not eligible while its current job is pending again."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.pipeline_roles import provision_pipeline
from tests.integration.support import one
from tests.integration.test_reviewed_authority_races import wait_for_authority_lock
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def prepared_closure(flow):
    rec = flow.recommend()
    review = flow.review(rec)
    receipt = flow.verify(rec)
    store, token, nonce, version = flow.prepare("close", "reviewer", rec["version"])
    return store, (
        token,
        nonce,
        flow.cid,
        version,
        rec["recommendation_id"],
        rec["version"],
        rec["recommendation_hash"],
        review["review_id"],
        receipt["verification_id"],
        "Close the synthetic exercise",
    )


def test_requeued_current_generation_blocks_old_verified_closure(workflow):  # noqa: F811
    store, args = prepared_closure(workflow)
    worker = Database(provision_pipeline(workflow.db, "worker")["dsn"])
    nonce_hash = sha256(args[1].encode()).hexdigest()
    generation = one(workflow.db, "SELECT generation FROM csl.pipeline")["generation"]
    for status in ("queued", "leased", "retryable", "dead", "superseded"):
        with worker.connect() as conn:
            conn.execute(
                "UPDATE csl.jobs SET status=%s,claim_token=%s,lease_until=CASE "
                "WHEN %s='leased' THEN clock_timestamp()+interval '5 minutes' "
                "ELSE NULL END WHERE generation=%s",
                (status, "held-worker-claim" if status == "leased" else None, status, generation),
            )
        with pytest.raises(EvidenceError, match="WS_STALE"):
            store.close(*args)
        assert store.view(args[0], workflow.cid)["eligible"] is False
        assert one(workflow.db, "SELECT generation,published_generation FROM csl.pipeline") == {
            "generation": generation,
            "published_generation": generation,
        }
        assert (
            one(
                workflow.db,
                "SELECT used FROM csl.ws_workflow_csrf WHERE nonce_hash=%s",
                (nonce_hash,),
            )["used"]
            is False
        )
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
    with workflow.db.connect() as conn:
        conn.execute(
            "UPDATE csl.jobs SET status='succeeded',claim_token=NULL,lease_until=NULL,"
            "generation=generation+100 WHERE generation=%s",
            (generation,),
        )
    try:
        with pytest.raises(EvidenceError, match="WS_STALE"):
            store.close(*args)
        assert one(workflow.db, "SELECT generation,published_generation FROM csl.pipeline") == {
            "generation": generation,
            "published_generation": generation,
        }
        assert (
            one(
                workflow.db,
                "SELECT used FROM csl.ws_workflow_csrf WHERE nonce_hash=%s",
                (nonce_hash,),
            )["used"]
            is False
        )
        assert (
            one(workflow.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_close'")["n"]
            == 0
        )
    finally:
        with workflow.db.connect() as conn:
            conn.execute(
                "UPDATE csl.jobs SET generation=%s WHERE generation=%s",
                (generation, generation + 100),
            )
    with worker.connect() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM csl.jobs WHERE generation<%s", (generation,)
            ).fetchone()["n"]
            > 0
        )
        conn.execute("UPDATE csl.jobs SET status='queued' WHERE generation<%s", (generation,))
    assert store.view(args[0], workflow.cid)["eligible"] is True
    assert store.close(*args)["case_id"] == workflow.cid
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1


def test_closure_waits_for_current_job_status_then_rechecks_eligibility(workflow):  # noqa: F811
    store, args = prepared_closure(workflow)
    worker = Database(provision_pipeline(workflow.db, "worker")["dsn"])
    with (
        worker.connect() as control,
        workflow.db.connect() as observer,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        control.execute(
            "UPDATE csl.jobs SET status='queued' "
            "WHERE generation=(SELECT generation FROM csl.pipeline)"
        )
        future = executor.submit(store.close, *args)
        try:
            wait_for_authority_lock(observer, workflow.db, store.data_db._values["user"], future)
        finally:
            control.commit()
        with pytest.raises(EvidenceError, match="WS_STALE"):
            future.result(timeout=5)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
    assert (
        one(
            workflow.db,
            "SELECT used FROM csl.ws_workflow_csrf WHERE nonce_hash=%s",
            (sha256(args[1].encode()).hexdigest(),),
        )["used"]
        is False
    )
