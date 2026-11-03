"""Assigned human no-action workflow; no machine-verdict or execution HTTP interface."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request
from starlette.responses import RedirectResponse, Response

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workflow_store import WorkflowStore
from cloudsecops_live.workspace_auth import Principal
from cloudsecops_live.workspace_web import _HEX, _NONCE, _call, _form, _number, _page, _query

_REFERENCE = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{64})\Z", re.ASCII)


def _store(person: Principal) -> WorkflowStore:
    return WorkflowStore(person.account.auth_db, person.account.data_db)


def _reason(value: str) -> str:
    if not value.strip() or len(value) > 2000:
        raise EvidenceError("WS_INVALID")
    return value


def _csrf(value: str) -> str:
    if not _NONCE.fullmatch(value):
        raise EvidenceError("WS_CSRF")
    return value


def _reference(value: str) -> str:
    if not _REFERENCE.fullmatch(value):
        raise EvidenceError("WS_INVALID")
    return value


def _redirect(case_id: str) -> Response:
    return RedirectResponse("/cases/" + case_id + "/workflow", status_code=303)


def install_workflow_routes(
    app: FastAPI,
    *,
    principal: Callable[[Request], Awaitable[Principal | None]],
    navigation: Callable[[Principal], Awaitable[dict[str, str]]],
) -> None:
    async def access(
        request: Request, case_id: str, role: str | None = None, *, mutation: bool = False
    ) -> tuple[Principal, WorkflowStore, dict[str, Any]] | Response:
        if not _HEX.fullmatch(case_id):
            return Response("Not found.", status_code=404)
        person = await principal(request)
        if person is None:
            return (
                Response("Authentication required.", status_code=401)
                if mutation
                else RedirectResponse("/login", status_code=303)
            )
        store = _store(person)
        item = await _call(store.view, person.token, case_id)
        if item is None:
            return Response("Not found.", status_code=404)
        if role is not None and person.role != role:
            return Response("Request rejected.", status_code=403)
        return person, store, item

    @app.get("/review-queue")
    async def review_queue(request: Request) -> Response:
        _query(request, {"offset", "limit"})
        person = await principal(request)
        if person is None:
            return RedirectResponse("/login", status_code=303)
        if person.role != "reviewer":
            return Response("Request rejected.", status_code=403)
        offset = _number(request.query_params.get("offset", "0"), minimum=0, maximum=10000)
        limit = _number(request.query_params.get("limit", "20"), maximum=50)
        records = await _call(_store(person).queue, person.token, offset, limit)
        return _page(
            "review_queue.html",
            navigation=await navigation(person),
            items=[
                {"case_id": row["case_id"], "summary": json.dumps(row, sort_keys=True)}
                for row in records
            ],
            next_offset=offset + limit if len(records) == limit else None,
            limit=limit,
        )

    @app.get("/cases/{case_id}/workflow")
    async def workflow(request: Request, case_id: str) -> Response:
        _query(request, set())
        authorized = await access(request, case_id)
        if isinstance(authorized, Response):
            return authorized
        person, store, item = authorized
        tokens: dict[str, str] = {}
        rec = item.get("current_recommendation")
        actions: list[str] = []
        if item["eligible"]:
            if person.role == "analyst" and item["state"] not in {"closed", "reopen_required"}:
                actions.append("recommend")
            if person.role == "reviewer":
                if item["state"] == "reopen_required":
                    actions.append("reopen")
                if rec and not rec.get("review"):
                    actions.append("review")
                if (
                    rec
                    and (rec.get("review") or {}).get("decision") == "approve"
                    and (rec.get("verification") or {}).get("result") == "verified"
                    and item["state"] != "closed"
                ):
                    actions.append("close")
        for action in actions:
            nonce = secrets.token_urlsafe(32)
            await _call(
                store.issue_csrf,
                person.token,
                nonce,
                action,
                case_id,
                item["workflow_version"],
                rec["version"] if rec and action in {"review", "close"} else None,
            )
            tokens[action] = nonce
        return _page(
            "workflow.html",
            navigation=await navigation(person),
            workflow=item,
            tokens=tokens,
            recommendation=rec,
            workflow_text=json.dumps(item, indent=2, sort_keys=True, ensure_ascii=False),
        )

    @app.post("/cases/{case_id}/recommendations")
    async def recommend(request: Request, case_id: str) -> Response:
        _query(request, set())
        form = await _form(
            request,
            {
                "csrf_token",
                "case_revision",
                "fingerprint",
                "workflow_version",
                "rationale",
                "counterevidence",
                "visibility_gaps",
            },
        )
        authorized = await access(request, case_id, "analyst", mutation=True)
        if isinstance(authorized, Response):
            return authorized
        person, store, _ = authorized
        if not _HEX.fullmatch(form["fingerprint"]):
            raise EvidenceError("WS_INVALID")
        await _call(
            store.recommend,
            person.token,
            _csrf(form["csrf_token"]),
            case_id,
            _number(form["case_revision"]),
            form["fingerprint"],
            _number(form["workflow_version"], minimum=0),
            _reason(form["rationale"]),
            _reason(form["counterevidence"]),
            _reason(form["visibility_gaps"]),
        )
        return _redirect(case_id)

    @app.get("/cases/{case_id}/recommendations/{recommendation_id}/{version}")
    async def recommendation_history(
        request: Request, case_id: str, recommendation_id: str, version: str
    ) -> Response:
        _query(request, set())
        if not _HEX.fullmatch(case_id) or not _HEX.fullmatch(recommendation_id):
            return Response("Not found.", status_code=404)
        person = await principal(request)
        if person is None:
            return RedirectResponse("/login", status_code=303)
        store = _store(person)
        item = await _call(store.recommendation, person.token, case_id, _number(version))
        if item is None or item["recommendation_id"] != recommendation_id:
            return Response("Not found.", status_code=404)
        return _page(
            "workflow_recommendation.html",
            navigation=await navigation(person),
            case_id=case_id,
            recommendation=item,
            recommendation_text=json.dumps(item, sort_keys=True, indent=2, ensure_ascii=False),
        )

    @app.post("/cases/{case_id}/recommendations/{recommendation_id}/{version}/review")
    async def review(
        request: Request, case_id: str, recommendation_id: str, version: str
    ) -> Response:
        _query(request, set())
        form = await _form(
            request, {"csrf_token", "workflow_version", "recommendation_hash", "decision", "reason"}
        )
        authorized = await access(request, case_id, "reviewer", mutation=True)
        if isinstance(authorized, Response):
            return authorized
        person, store, _ = authorized
        if form["decision"] not in {"approve", "reject"} or not _HEX.fullmatch(
            form["recommendation_hash"]
        ):
            raise EvidenceError("WS_INVALID")
        await _call(
            store.review,
            person.token,
            _csrf(form["csrf_token"]),
            case_id,
            _number(form["workflow_version"], minimum=0),
            _reference(recommendation_id),
            _number(version),
            form["recommendation_hash"],
            form["decision"],
            _reason(form["reason"]),
        )
        return _redirect(case_id)

    @app.post("/cases/{case_id}/close")
    async def close(request: Request, case_id: str) -> Response:
        _query(request, set())
        form = await _form(
            request,
            {
                "csrf_token",
                "workflow_version",
                "recommendation_id",
                "recommendation_version",
                "recommendation_hash",
                "review_id",
                "verification_id",
                "reason",
            },
        )
        authorized = await access(request, case_id, "reviewer", mutation=True)
        if isinstance(authorized, Response):
            return authorized
        person, store, _ = authorized
        if not _HEX.fullmatch(form["recommendation_hash"]):
            raise EvidenceError("WS_INVALID")
        await _call(
            store.close,
            person.token,
            _csrf(form["csrf_token"]),
            case_id,
            _number(form["workflow_version"], minimum=0),
            _reference(form["recommendation_id"]),
            _number(form["recommendation_version"]),
            form["recommendation_hash"],
            _reference(form["review_id"]),
            _reference(form["verification_id"]),
            _reason(form["reason"]),
        )
        return _redirect(case_id)

    @app.post("/cases/{case_id}/reopen")
    async def reopen(request: Request, case_id: str) -> Response:
        _query(request, set())
        form = await _form(request, {"csrf_token", "workflow_version", "reason"})
        authorized = await access(request, case_id, "reviewer", mutation=True)
        if isinstance(authorized, Response):
            return authorized
        person, store, _ = authorized
        await _call(
            store.reopen,
            person.token,
            _csrf(form["csrf_token"]),
            case_id,
            _number(form["workflow_version"], minimum=0),
            _reason(form["reason"]),
        )
        return _redirect(case_id)
