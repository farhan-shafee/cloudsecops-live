"""Authorization is refreshed after the specific authority row lock is acquired."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from cloudsecops_live.errors import EvidenceError
from tests.integration.support import one
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def wait_for_authority_lock(control, db, role, future):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        control.execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
        waiting = control.execute(
            "SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=%s AND usename=%s "
            "AND backend_type='client backend' AND wait_event_type='Lock' "
            "AND pid<>pg_backend_pid()",
            (db._values["dbname"], role),
        ).fetchall()
        assert len(waiting) <= 1
        if waiting:
            return
        if future.done():
            pytest.fail("Mutation finished before locking its live authority")
        time.sleep(0.02)
    pytest.fail("Mutation did not reach the held authority row lock")


def prepared_review(flow, recommendation):
    store, token, nonce, version = flow.prepare("review", "reviewer", recommendation["version"])
    return store, (
        token,
        nonce,
        flow.cid,
        version,
        recommendation["recommendation_id"],
        recommendation["version"],
        recommendation["recommendation_hash"],
        "approve",
        "Reviewed",
    )


def test_waiting_review_reloads_the_reviewers_downgraded_role(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    store, arguments = prepared_review(workflow, recommendation)
    reviewer_id = workflow.workspace.accounts["reviewer"]["user_id"]
    with workflow.db.connect() as control, ThreadPoolExecutor(max_workers=1) as executor:
        control.execute(
            "UPDATE csl.ws_users SET app_role='auditor' WHERE user_id=%s", (reviewer_id,)
        )
        future = executor.submit(store.review, *arguments)
        try:
            wait_for_authority_lock(control, workflow.db, store.data_db._values["user"], future)
        finally:
            control.commit()
        with pytest.raises(EvidenceError) as rejected:
            future.result(timeout=5)
        assert rejected.value.code == "WS_DENIED"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 0


def test_waiting_review_rechecks_revoked_author_assignment(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    store, arguments = prepared_review(workflow, recommendation)
    author_id = workflow.workspace.accounts["alice"]["user_id"]
    with workflow.db.connect() as control, ThreadPoolExecutor(max_workers=1) as executor:
        control.execute(
            "DELETE FROM csl.ws_case_grants WHERE user_id=%s AND case_id=%s",
            (author_id, workflow.cid),
        )
        future = executor.submit(store.review, *arguments)
        try:
            wait_for_authority_lock(control, workflow.db, store.data_db._values["user"], future)
        finally:
            control.commit()
        with pytest.raises(EvidenceError) as rejected:
            future.result(timeout=5)
        assert rejected.value.code == "WS_STALE"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 0


def test_waiting_close_rechecks_verifier_source_repin(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    review = workflow.review(recommendation)
    receipt = workflow.verify(recommendation)
    store, token, nonce, version = workflow.prepare("close", "reviewer", recommendation["version"])
    arguments = (
        token,
        nonce,
        workflow.cid,
        version,
        recommendation["recommendation_id"],
        recommendation["version"],
        recommendation["recommendation_hash"],
        review["review_id"],
        receipt["verification_id"],
        "Close synthetic exercise",
    )
    with workflow.db.connect() as control, ThreadPoolExecutor(max_workers=1) as executor:
        control.execute(
            "UPDATE csl.ws_verifiers SET checker_source_digest=%s WHERE verifier_id=%s",
            ("f" * 64, workflow.verifier_account["verifier_id"]),
        )
        future = executor.submit(store.close, *arguments)
        try:
            wait_for_authority_lock(control, workflow.db, store.data_db._values["user"], future)
        finally:
            control.commit()
        with pytest.raises(EvidenceError) as rejected:
            future.result(timeout=5)
        assert rejected.value.code == "WS_STALE"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
