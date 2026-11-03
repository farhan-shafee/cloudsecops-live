"""Policy gates require material change for reopening and live bound author authority."""

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import disable_user
from tests.integration.support import one
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def test_closed_exercise_cannot_reopen_without_material_new_evidence(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    review = workflow.review(recommendation)
    receipt = workflow.verify(recommendation)
    workflow.close(recommendation, review, receipt)
    before = workflow.view()
    with pytest.raises(EvidenceError):
        workflow.reopen()
    after = workflow.view()
    assert after["state"] == "closed"
    assert after["workflow_version"] == before["workflow_version"]
    assert after["closures"] == before["closures"]
    assert (
        one(workflow.db, "SELECT count(*) AS n FROM csl.ws_transitions WHERE action='reopen'")["n"]
        == 0
    )


def test_disabled_recommendation_author_cannot_gain_a_fresh_approval(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    disable_user(workflow.db, "alice")
    with pytest.raises(EvidenceError):
        workflow.review(recommendation)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 0
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0


def test_revoked_author_case_assignment_invalidates_verified_closure(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    review = workflow.review(recommendation)
    receipt = workflow.verify(recommendation)
    with workflow.db.connect() as conn:
        conn.execute(
            "DELETE FROM csl.ws_case_grants WHERE user_id=%s AND case_id=%s",
            (
                workflow.workspace.accounts["alice"]["user_id"],
                workflow.cid,
            ),
        )
    with pytest.raises(EvidenceError):
        workflow.close(recommendation, review, receipt)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 1
