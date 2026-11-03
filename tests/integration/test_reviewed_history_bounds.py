"""Recommendation history projects bounded metadata rather than repeated full evidence."""

from __future__ import annotations

import secrets

from cloudsecops_live.database import Database
from cloudsecops_live.worker import work_once
from cloudsecops_live.workflow_store import WorkflowStore
from cloudsecops_live.workspace_roles import grant_case, provision_user
from cloudsecops_live.workspace_store import WorkspaceStore
from tests.integration.support import add, current


def test_large_recommendation_history_has_one_full_payload_and_authorized_single_reads(db):
    add(db, list(range(100)))
    work_once(db)
    case = current(db)[0]
    account = provision_user(db, "history_author", "analyst", "x" * 64)
    grant_case(db, "history_author", case["case_id"])
    auth, data = Database(account["auth_dsn"]), Database(account["data_dsn"])
    token = account["user_id"] + "." + secrets.token_urlsafe(32)
    WorkspaceStore(auth, data).create_session(token)
    store = WorkflowStore(auth, data)
    first = None
    for _ in range(21):
        view = store.view(token, case["case_id"])
        nonce = secrets.token_urlsafe(32)
        store.issue_csrf(token, nonce, "recommend", case["case_id"], view["workflow_version"])
        recommendation = store.recommend(
            token,
            nonce,
            case["case_id"],
            case["current_revision"],
            case["fingerprint"],
            view["workflow_version"],
            "Synthetic authorized exercise",
            "Benign inventory is plausible",
            "Supplied synthetic records only",
        )
        if first is None:
            first = recommendation
    result = store.view(token, case["case_id"])
    assert len(result["recommendations"]) == 20
    assert all("payload" not in item for item in result["recommendations"])
    assert all("evidence" not in item for item in result["recommendations"])
    assert result["recommendation_count"] == 21
    assert result["recommendations_truncated"] is True
    assert len(result["current_recommendation"]["payload"]["evidence"]) == 100
    assert {row["version"] for row in result["recommendations"]} == set(range(2, 22))
    assert set(result["recommendations"][0]) == {
        "recommendation_id",
        "version",
        "recommendation_hash",
        "author_id",
        "case_revision",
        "created_at",
        "expires_at",
    }
    historical = store.recommendation(token, case["case_id"], 1)
    assert historical["payload"] == first["payload"]
    assert historical["effective"] is False
    assert historical["recommendation_hash"] == first["recommendation_hash"]
    for version in (None, 0, -1, 65, 999):
        assert store.recommendation(token, case["case_id"], version) is None
    assert store.recommendation(token, "f" * 64, 1) is None
    assert store.recommendation(token, "malformed", 1) is None
    denied = provision_user(db, "unassigned_history", "auditor", "x" * 64)
    other_auth, other_data = Database(denied["auth_dsn"]), Database(denied["data_dsn"])
    other_token = denied["user_id"] + "." + secrets.token_urlsafe(32)
    WorkspaceStore(other_auth, other_data).create_session(other_token)
    other_store = WorkflowStore(other_auth, other_data)
    assert other_store.recommendation(other_token, case["case_id"], 1) is None
