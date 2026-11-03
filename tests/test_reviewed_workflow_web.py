"""Literal HTTP expectations for the new routes; real SQL effects are tested separately."""

from __future__ import annotations

import asyncio
import importlib.util
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_web import SecurityBoundary, _error

CID, RID, HASH = "a" * 64, "b" * 64, "c" * 64
NONCE = "n" * 43
ORIGIN = "https://127.0.0.1:8443"


def application(monkeypatch, *, role="analyst", assigned=True, authenticated=True):
    assert importlib.util.find_spec("cloudsecops_live.workflow_web") is not None, (
        "The reviewed workflow HTTP boundary has not been implemented"
    )
    from cloudsecops_live import workflow_web as module

    calls = []
    state = {
        "case_id": CID,
        "state": "recommended",
        "workflow_version": 2,
        "epoch": 1,
        "eligible": True,
        "case_revision": 1,
        "fingerprint": HASH,
        "policy_version": "offline-no-action/1",
        "current_recommendation": {
            "recommendation_id": RID,
            "version": 1,
            "recommendation_hash": HASH,
            "author_id": "d" * 32,
            "effective": True,
            "payload": {"rationale": '<script>alert("stored")</script>'},
            "review": None,
            "verification": None,
        },
        "recommendations": [],
        "closures": [],
        "transitions": [],
    }

    class Store:
        def __init__(self, *args):
            pass

        def view(self, token, cid):
            return state if assigned and cid == CID else None

        def queue(self, token, offset=0, limit=20):
            return [{"case_id": CID, "state": "recommended"}] if assigned else []

        def recommendation(self, token, cid, version):
            if assigned and cid == CID and version == 1:
                return state["current_recommendation"]
            return None

        def issue_csrf(self, *args):
            calls.append(("csrf", args))

        def recommend(self, *args):
            calls.append(("recommend", args))
            return {"recommendation_id": RID}

        def review(self, *args):
            calls.append(("review", args))
            return {"review_id": "e" * 32}

        def close(self, *args):
            calls.append(("close", args))
            return {"closure_id": "f" * 32}

        def reopen(self, *args):
            calls.append(("reopen", args))
            return {"state": "open"}

    monkeypatch.setattr(module, "WorkflowStore", Store)
    person = SimpleNamespace(
        role=role,
        username="synthetic_user",
        token="opaque-test-token",
        account=SimpleNamespace(auth_db=object(), data_db=object(), user_id="e" * 32),
    )

    async def principal(request):
        return person if authenticated else None

    async def navigation(user):
        return {
            "username": user.username,
            "role": user.role,
            "logout_csrf": NONCE,
            "rotate_csrf": NONCE,
        }

    app = FastAPI()
    app.add_middleware(SecurityBoundary, origin=ORIGIN)

    @app.exception_handler(EvidenceError)
    async def failure(request, error):
        return _error(error)

    module.install_workflow_routes(app, principal=principal, navigation=navigation)
    return app, calls, state


def request(app, method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN, follow_redirects=False
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def recommendation():
    return {
        "csrf_token": NONCE,
        "case_revision": "1",
        "fingerprint": HASH,
        "workflow_version": "2",
        "rationale": "Authorized synthetic inventory exercise; no cloud action proposed.",
        "counterevidence": "Inventory and retries are plausible benign explanations.",
        "visibility_gaps": "Synthetic supplied records cannot establish absence of activity.",
    }


def review():
    return {
        "csrf_token": NONCE,
        "workflow_version": "2",
        "recommendation_hash": HASH,
        "decision": "approve",
        "reason": "Only this bound synthetic exercise is reviewed.",
    }


def test_analyst_recommendation_and_reviewer_decision_are_distinct_routes(monkeypatch):
    app, calls, _ = application(monkeypatch)
    response = request(
        app,
        "POST",
        f"/cases/{CID}/recommendations",
        data=recommendation(),
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/cases/{CID}/workflow"
    assert [name for name, _ in calls] == ["recommend"]
    app, calls, _ = application(monkeypatch, role="reviewer")
    response = request(
        app,
        "POST",
        f"/cases/{CID}/recommendations/{RID}/1/review",
        data=review(),
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 303
    assert [name for name, _ in calls] == ["review"]


@pytest.mark.parametrize("role", ["analyst", "auditor"])
def test_nonreviewer_cannot_review_or_close(monkeypatch, role):
    app, calls, _ = application(monkeypatch, role=role)
    response = request(
        app,
        "POST",
        f"/cases/{CID}/recommendations/{RID}/1/review",
        data=review(),
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 403
    assert not calls
    assert request(app, "GET", "/review-queue").status_code == 403


def test_missing_session_and_assignment_do_not_reach_mutations(monkeypatch):
    app, calls, _ = application(monkeypatch, authenticated=False)
    assert request(app, "GET", f"/cases/{CID}/workflow").status_code == 303
    assert (
        request(
            app,
            "POST",
            f"/cases/{CID}/recommendations",
            data=recommendation(),
            headers={"Origin": ORIGIN},
        ).status_code
        == 401
    )
    assert not calls
    app, calls, _ = application(monkeypatch, assigned=False)
    inaccessible = request(app, "GET", f"/cases/{CID}/workflow")
    unknown = request(app, "GET", f"/cases/{'0' * 64}/workflow")
    assert inaccessible.status_code == unknown.status_code == 404
    assert inaccessible.text == unknown.text == "Not found."
    assert not calls


@pytest.mark.parametrize(
    "field", ["targets", "action", "verified", "role", "author_id", "command", "url"]
)
def test_caller_cannot_supply_execution_or_authority_fields(monkeypatch, field):
    app, calls, _ = application(monkeypatch)
    data = {**recommendation(), field: "forged"}
    assert (
        request(
            app, "POST", f"/cases/{CID}/recommendations", data=data, headers={"Origin": ORIGIN}
        ).status_code
        == 400
    )
    assert not calls


@pytest.mark.parametrize("token", [None, "forged", "\x00"])
def test_missing_or_malformed_csrf_is_rejected(monkeypatch, token):
    app, calls, _ = application(monkeypatch)
    data = recommendation()
    if token is None:
        del data["csrf_token"]
    else:
        data["csrf_token"] = token
    assert request(
        app, "POST", f"/cases/{CID}/recommendations", data=data, headers={"Origin": ORIGIN}
    ).status_code in {400, 403}
    assert not calls


def test_stored_rationale_is_escaped_and_page_preserves_synthetic_limits(monkeypatch):
    app, _, _ = application(monkeypatch, role="auditor")
    response = request(app, "GET", f"/cases/{CID}/workflow")
    assert response.status_code == 200
    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "synthetic" in response.text.lower() and "unauthenticated" in response.text.lower()
    assert "unreviewed synthetic draft" in response.text.lower()
    assert response.headers["cache-control"] == "no-store"


def test_reviewer_can_inspect_a_recommendation_before_any_decision(monkeypatch):
    app, _, _ = application(monkeypatch, role="reviewer")
    response = request(app, "GET", f"/cases/{CID}/workflow")
    assert response.status_code == 200
    assert f'action="/cases/{CID}/recommendations/{RID}/1/review"' in response.text


def test_exact_historical_recommendation_is_authorized_escaped_and_read_only(monkeypatch):
    app, calls, _ = application(monkeypatch, role="auditor")
    response = request(app, "GET", f"/cases/{CID}/recommendations/{RID}/1")
    assert response.status_code == 200
    assert "<script>" not in response.text and "&lt;script&gt;" in response.text
    assert f'action="/cases/{CID}/close"' not in response.text
    assert f'action="/cases/{CID}/recommendations"' not in response.text
    assert not calls
    assert request(app, "GET", f"/cases/{CID}/recommendations/{RID}/2").status_code == 404
    app, _, _ = application(monkeypatch, role="auditor", assigned=False)
    denied = request(app, "GET", f"/cases/{CID}/recommendations/{RID}/1")
    unknown = request(app, "GET", f"/cases/{'0' * 64}/recommendations/{RID}/1")
    assert denied.status_code == unknown.status_code == 404
    assert denied.text == unknown.text


def closure():
    return {
        "csrf_token": NONCE,
        "workflow_version": "2",
        "recommendation_id": RID,
        "recommendation_version": "1",
        "recommendation_hash": HASH,
        "review_id": "d" * 32,
        "verification_id": "e" * 32,
        "reason": "Close this exact synthetic exercise only.",
    }


def test_anonymous_queue_and_historical_pages_require_sign_in(monkeypatch):
    app, calls, _ = application(monkeypatch, authenticated=False)
    for path in ("/review-queue", f"/cases/{CID}/recommendations/{RID}/1"):
        response = request(app, "GET", path)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    assert not calls


def test_invalid_case_and_recommendation_paths_are_non_enumerating(monkeypatch):
    app, calls, _ = application(monkeypatch)
    for path in (
        "/cases/not-an-id/workflow",
        f"/cases/{CID}/recommendations/not-an-id/1",
        f"/cases/{CID}/recommendations/{'0' * 64}/1",
    ):
        response = request(app, "GET", path)
        assert response.status_code == 404 and response.text == "Not found."
    assert not calls


def test_queue_is_paginated_and_invalid_limits_do_not_reach_mutations(monkeypatch):
    app, calls, _ = application(monkeypatch, role="reviewer")
    response = request(app, "GET", "/review-queue?limit=1&offset=0")
    assert response.status_code == 200 and CID in response.text and "offset=1" in response.text
    for query in ("limit=0", "limit=51", "offset=10001", "offset=-1", "limit=1&limit=2"):
        assert request(app, "GET", "/review-queue?" + query).status_code == 400
    assert not calls


@pytest.mark.parametrize(
    ("field", "value"),
    [("fingerprint", "forged"), ("rationale", "  "), ("counterevidence", "x" * 2001)],
)
def test_invalid_recommendation_binding_or_reason_is_rejected(monkeypatch, field, value):
    app, calls, _ = application(monkeypatch)
    response = request(
        app,
        "POST",
        f"/cases/{CID}/recommendations",
        data={**recommendation(), field: value},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 400 and not calls


@pytest.mark.parametrize(
    ("field", "value"),
    [("decision", "verified"), ("recommendation_hash", "forged")],
)
def test_reviewer_cannot_submit_machine_verdict_or_unbound_decision(monkeypatch, field, value):
    app, calls, _ = application(monkeypatch, role="reviewer")
    response = request(
        app,
        "POST",
        f"/cases/{CID}/recommendations/{RID}/1/review",
        data={**review(), field: value},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 400 and not calls


@pytest.mark.parametrize("role", ["analyst", "auditor"])
def test_close_and_reopen_require_reviewer_even_with_well_formed_forms(monkeypatch, role):
    app, calls, _ = application(monkeypatch, role=role)
    for path, form in (
        (f"/cases/{CID}/close", closure()),
        (
            f"/cases/{CID}/reopen",
            {"csrf_token": NONCE, "workflow_version": "2", "reason": "Changed source."},
        ),
    ):
        response = request(app, "POST", path, data=form, headers={"Origin": ORIGIN})
        assert response.status_code == 403
    assert not calls


@pytest.mark.parametrize("field", ["recommendation_hash", "review_id", "verification_id"])
def test_closure_rejects_malformed_receipt_references(monkeypatch, field):
    app, calls, _ = application(monkeypatch, role="reviewer")
    response = request(
        app,
        "POST",
        f"/cases/{CID}/close",
        data={**closure(), field: "../../private"},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 400 and not calls


def test_pages_offer_only_actions_for_current_eligible_state(monkeypatch):
    app, calls, state = application(monkeypatch)
    state["eligible"] = False
    assert request(app, "GET", f"/cases/{CID}/workflow").status_code == 200
    assert not calls
    state["eligible"] = True
    state["state"] = "closed"
    assert request(app, "GET", f"/cases/{CID}/workflow").status_code == 200
    assert not calls
    app, calls, state = application(monkeypatch, role="reviewer")
    state["state"] = "reopen_required"
    state["current_recommendation"]["review"] = {"decision": "approve", "review_id": "d" * 32}
    state["current_recommendation"]["verification"] = {"result": "inconclusive"}
    assert request(app, "GET", f"/cases/{CID}/workflow").status_code == 200
    assert [args[2] for name, args in calls if name == "csrf"] == ["reopen"]
    calls.clear()
    state["state"] = "verified"
    state["current_recommendation"]["verification"] = {
        "result": "verified",
        "verification_id": "e" * 32,
    }
    assert request(app, "GET", f"/cases/{CID}/workflow").status_code == 200
    assert [args[2] for name, args in calls if name == "csrf"] == ["close"]
