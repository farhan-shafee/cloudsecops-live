"""Separate real TLS web and verifier processes complete the synthetic exercise."""

from __future__ import annotations

import asyncio
import socket

from cloudsecops_live.worker import work_once
from tests.integration.support import add, one
from tests.integration.test_workspace_security import ORIGIN, PASSWORD, fields, login
from tests.integration.workflow_support import (  # noqa: F401
    workflow,  # noqa: F811
    workspace,
    workspace_password_hash,
)


def test_real_https_separate_verifier_closure_then_late_evidence_and_explicit_reopen(
    workflow,  # noqa: F811
    tmp_path,  # noqa: F811
):
    from scripts.reviewed_workflow_smoke import run_smoke

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    web, verifier = workflow.runtime_files(tmp_path, origin=f"https://127.0.0.1:{port}")
    result = run_smoke(web, verifier, "alice", PASSWORD, "reviewer", PASSWORD, workflow.cid)
    for key in (
        "https",
        "certificate_verified",
        "recommendation",
        "distinct_review",
        "independent_verifier",
        "synthetic_exercise_closed",
    ):
        assert result[key] is True
    assert result["source_kind"] == "synthetic"
    assert result["authenticated"] is False
    assert result["secrets_in_receipt"] is False
    assert PASSWORD not in str(result)
    assert workflow.verifier_account["dsn"] not in str(result)
    assert workflow.view()["state"] == "closed"
    rec = one(workflow.db, "SELECT * FROM csl.ws_recommendations")
    review = one(workflow.db, "SELECT * FROM csl.ws_reviews")
    receipt = one(workflow.db, "SELECT * FROM csl.ws_verifications")
    assert receipt["result"] == "verified"
    assert review["reviewer_id"] != rec["author_id"]
    store, token, nonce, version = workflow.prepare("close", "reviewer", rec["version"])
    assert store and token
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    add(workflow.db, [base + 10], "https-late-evidence")

    async def scenario():
        async with workflow.workspace.client() as client:
            # Use the real server-created session's account through the same
            # strict forms and transport boundary after the child server stops.
            assert (await login(client, "reviewer")).status_code == 303
            old_close = {
                "csrf_token": nonce,
                "workflow_version": str(version),
                "recommendation_id": rec["recommendation_id"],
                "recommendation_version": str(rec["version"]),
                "recommendation_hash": rec["recommendation_hash"],
                "review_id": review["review_id"],
                "verification_id": receipt["verification_id"],
                "reason": "An old closure must fail after new evidence.",
            }
            # The prepared token belongs to a different session, so obtain a
            # current session-bound close token while preserving the old version.
            raw = client.cookies.get("__Host-csl_session")
            import secrets

            old_close["csrf_token"] = secrets.token_urlsafe(32)
            workflow.store("reviewer").issue_csrf(
                raw, old_close["csrf_token"], "close", workflow.cid, version, rec["version"]
            )
            response = await client.post(
                f"/cases/{workflow.cid}/close", data=old_close, headers={"Origin": ORIGIN}
            )
            assert response.status_code == 409
            work_once(workflow.db)
            page = await client.get(f"/cases/{workflow.cid}/workflow")
            assert page.status_code == 200 and "reopen_required" in page.text
            target = f"/cases/{workflow.cid}/reopen"
            form = fields(page, target)
            response = await client.post(
                target,
                data={**form, "reason": "A reviewer must review the new source snapshot."},
                headers={"Origin": ORIGIN},
            )
            assert response.status_code == 303

    asyncio.run(scenario())
    assert workflow.view()["state"] == "open"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
    assert (
        one(workflow.db, "SELECT count(*) AS n FROM csl.ws_transitions WHERE action='reopen'")["n"]
        == 1
    )


def test_real_https_rejects_changed_evidence_then_preserves_closure_and_audits_reopen(
    workflow,  # noqa: F811
    tmp_path,
):
    from psycopg.conninfo import make_conninfo

    from cloudsecops_live.independent_verifier import source_digest
    from cloudsecops_live.workspace_config import write_private_json
    from cloudsecops_live.workspace_roles import grant_case, provision_verifier
    from scripts.reviewed_workflow_smoke import _late_change, run_smoke

    # Use the later component for the unchanged-case reopening demonstration.
    # Duplicating a new event at the first component's end (40 seconds) would
    # correctly bridge the second component starting at 100, superseding its ID.
    # That lineage/no-inherited-grant behavior has its own acceptance test.
    workflow.workspace.cases.sort(key=lambda case: case["payload"]["window_end"], reverse=True)
    for username in ("alice", "reviewer"):
        grant_case(workflow.db, username, workflow.cid)
    workflow.verifier_account = provision_verifier(workflow.db, workflow.cid, source_digest())
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    web, verifier = workflow.runtime_files(tmp_path, origin=f"https://127.0.0.1:{port}")
    maintenance = tmp_path / "maintenance.json"
    write_private_json(maintenance, {"dsn": make_conninfo(**workflow.db._values)})
    result = run_smoke(
        web,
        verifier,
        "alice",
        PASSWORD,
        "reviewer",
        PASSWORD,
        workflow.cid,
        demonstrate_change=_late_change(maintenance, workflow.cid),
    )
    for key in (
        "https",
        "certificate_verified",
        "distinct_review",
        "independent_verifier",
        "changed_evidence_blocked_closure",
        "closed_history_preserved",
        "audited_reopen",
    ):
        assert result[key] is True
    assert result["final_state"] == "open"
    assert result["authenticated"] is False
    assert result["source_kind"] == "synthetic"
    assert result["secrets_in_receipt"] is False
    assert PASSWORD not in str(result) and workflow.verifier_account["dsn"] not in str(result)
    assert workflow.view()["state"] == "open"
    for table in ("ws_recommendations", "ws_reviews", "ws_verifications"):
        assert one(workflow.db, f"SELECT count(*) AS n FROM csl.{table}")["n"] == 2
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
    assert (
        one(
            workflow.db,
            "SELECT count(*) AS n FROM csl.ws_transitions WHERE action='evidence_invalidated'",
        )["n"]
        == 2
    )
    assert (
        one(workflow.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workflow_reopen'")["n"]
        == 1
    )
