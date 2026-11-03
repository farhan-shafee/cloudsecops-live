"""Loopback HTTPS investigation pages with independent HTTP and database authorization."""

from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_auth import (
    Principal,
    authenticate,
    new_session_token,
    resolve_session,
)
from cloudsecops_live.workspace_config import WorkspaceConfig
from cloudsecops_live.workspace_store import GateStore

_COOKIE = "__Host-csl_session"
_LOGIN_COOKIE = "__Host-csl_login"
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_BODY_LIMIT = 16384
_ENV = Environment(
    loader=PackageLoader("cloudsecops_live", "templates"),
    autoescape=select_autoescape(("html",)),
    undefined=StrictUndefined,
)
_HEADERS = {
    "cache-control": "no-store",
    "pragma": "no-cache",
    "content-security-policy": (
        "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'none'; "
        "connect-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "object-src 'none'"
    ),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "strict-transport-security": "max-age=86400",
}


class SecurityBoundary:
    """Check transport/authority before routes; buffer at most 16 KiB and 64 body chunks."""

    def __init__(self, app: ASGIApp, origin: str) -> None:
        self.app, self.origin = app, origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secured(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                protected = {key.encode() for key in _HEADERS}
                headers = [(k, v) for k, v in headers if k.lower() not in protected]
                headers.extend((key.encode(), value.encode()) for key, value in _HEADERS.items())
                message = {**message, "headers": headers}
            await send(message)

        async def reject(status: int, message: str = "Request rejected.") -> None:
            await Response(message, status_code=status)(scope, receive, secured)

        headers = scope.get("headers", [])
        if sum(len(k) + len(v) for k, v in headers) > 16384:
            await reject(431)
            return
        if scope.get("scheme") != "https":
            await reject(400)
            return
        host = [v for k, v in headers if k.lower() == b"host"]
        origin = [v for k, v in headers if k.lower() == b"origin"]
        fetch = [v for k, v in headers if k.lower() == b"sec-fetch-site"]
        if (
            host != [self.origin.removeprefix("https://").encode()]
            or (origin and origin != [self.origin.encode()])
            or (scope["method"] not in {"GET", "HEAD"} and origin != [self.origin.encode()])
            or (fetch and fetch not in [[b"same-origin"], [b"none"]])
        ):
            await reject(403)
            return
        if len(scope.get("path", "")) > 2048 or len(scope.get("query_string", b"")) > 2048:
            await reject(414)
            return
        lengths = [v for k, v in headers if k.lower() == b"content-length"]
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
            await reject(400)
            return
        if lengths and int(lengths[0]) > _BODY_LIMIT:
            await reject(413)
            return
        chunks: list[bytes] = []
        total = 0
        try:
            async with asyncio.timeout(5):
                for _ in range(64):
                    message = await receive()
                    if message["type"] != "http.request":
                        await reject(400)
                        return
                    chunk = message.get("body", b"")
                    total += len(chunk)
                    if total > _BODY_LIMIT:
                        await reject(413)
                        return
                    chunks.append(chunk)
                    if not message.get("more_body", False):
                        break
                else:
                    await reject(413)
                    return
        except TimeoutError:
            await reject(408)
            return
        if total and scope["method"] in {"GET", "HEAD"}:
            await reject(400)
            return
        body = b"".join(chunks)

        async def replay() -> Message:
            return {"type": "http.request", "body": body, "more_body": False}

        try:
            await self.app(scope, replay, secured)
        except Exception:
            # No exception text, credentials, request bodies or tokens go to a logger/client.
            await reject(500, "Request failed.")


def _page(template: str, **context: object) -> Response:
    return HTMLResponse(_ENV.get_template(template).render(**context))


def _cookie(request: Request, name: str) -> str | None:
    found = []
    for header in request.headers.getlist("cookie"):
        for item in header.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key == name:
                found.append(value)
    return found[0] if len(found) == 1 else None


def _set_cookie(response: Response, name: str, value: str, age: int) -> None:
    response.set_cookie(
        name, value, max_age=age, secure=True, httponly=True, samesite="strict", path="/"
    )


def _clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, secure=True, httponly=True, samesite="strict", path="/")


async def _form(request: Request, fields: set[str]) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").lower().replace(" ", "")
    if content_type not in {
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded;charset=utf-8",
    }:
        raise EvidenceError("WS_INVALID")
    try:
        text = (await request.body()).decode("utf-8")
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            raise ValueError
        values = parse_qs(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=6,
            encoding="utf-8",
            errors="strict",
        )
        if "csrf_token" not in values:
            raise EvidenceError("WS_CSRF")
        if set(values) != fields or any(len(value) != 1 for value in values.values()):
            raise ValueError
        if any("\x00" in item for value in values.values() for item in value):
            raise ValueError
        return {key: value[0] for key, value in values.items()}
    except EvidenceError:
        raise
    except (ValueError, UnicodeError):
        raise EvidenceError("WS_INVALID") from None


def _number(value: str, *, minimum: int = 1, maximum: int = 1_000_000) -> int:
    if not re.fullmatch(r"[0-9]{1,7}", value, re.ASCII) or not minimum <= int(value) <= maximum:
        raise EvidenceError("WS_INVALID")
    return int(value)


def _query(request: Request, names: set[str]) -> None:
    if set(request.query_params) - names or any(
        len(request.query_params.getlist(k)) != 1 for k in names if k in request.query_params
    ):
        raise EvidenceError("WS_INVALID")


async def _call(function: Callable[..., Any], *args: object) -> Any:
    return await run_in_threadpool(function, *args)


def _error(error: EvidenceError) -> Response:
    status = {
        "WS_INVALID": 400,
        "WS_DENIED": 403,
        "WS_CSRF": 403,
        "WS_STALE": 409,
        "WS_LIMIT": 429,
        "WS_DATABASE": 503,
        "WS_SCHEMA": 503,
    }.get(error.code, 503)
    message = "Case version changed; reload the case." if status == 409 else "Request rejected."
    return Response(message, status_code=status)


def create_app(config: WorkspaceConfig) -> FastAPI:
    config.validate()
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityBoundary, origin=config.origin)

    @app.exception_handler(EvidenceError)
    async def evidence_error(_: Request, error: EvidenceError) -> Response:
        return _error(error)

    async def principal(request: Request) -> Principal | None:
        return cast(
            Principal | None, await _call(resolve_session, config, _cookie(request, _COOKIE))
        )

    async def navigation(person: Principal) -> dict[str, str]:
        logout, rotate = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        store = person.store()
        await _call(store.issue_csrf, person.token, logout, "logout")
        await _call(store.issue_csrf, person.token, rotate, "rotate")
        return {
            "username": person.username,
            "role": person.role,
            "logout_csrf": logout,
            "rotate_csrf": rotate,
        }

    async def login_page(error: bool = False) -> Response:
        nonce, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        await _call(GateStore(config.gate_db).challenge, nonce, csrf)
        response = _page("login.html", csrf=csrf, error=error)
        if error:
            response.status_code = 401
        _set_cookie(response, _LOGIN_COOKIE, nonce, 300)
        return response

    @app.get("/")
    async def root() -> Response:
        return RedirectResponse("/cases", status_code=303)

    @app.get("/login")
    async def sign_in() -> Response:
        return await login_page()

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await _form(request, {"username", "password", "csrf_token"})
        nonce = _cookie(request, _LOGIN_COOKIE)
        csrf = form["csrf_token"]
        if nonce is None or not _NONCE.fullmatch(nonce) or not _NONCE.fullmatch(csrf):
            return Response("Request rejected.", status_code=403)
        consumed = await _call(GateStore(config.gate_db).consume, nonce, csrf)
        if not consumed:
            return Response("Request rejected.", status_code=403)
        result = await _call(authenticate, config, form["username"], form["password"])
        if result is None:
            return await login_page(True)
        _, token = result
        response = RedirectResponse("/cases", status_code=303)
        _set_cookie(response, _COOKIE, token, 1800)
        _clear_cookie(response, _LOGIN_COOKIE)
        return response

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        form = await _form(request, {"csrf_token"})
        person = await principal(request)
        if person is None:
            return Response("Authentication required.", status_code=401)
        await _call(person.store().revoke, person.token, form["csrf_token"])
        response = RedirectResponse("/login", status_code=303)
        _clear_cookie(response, _COOKIE)
        return response

    @app.post("/session/rotate")
    async def rotate(request: Request) -> Response:
        form = await _form(request, {"csrf_token"})
        person = await principal(request)
        if person is None:
            return Response("Authentication required.", status_code=401)
        token = new_session_token(person.account.user_id)
        await _call(person.store().rotate, person.token, form["csrf_token"], token)
        response = RedirectResponse("/cases", status_code=303)
        _set_cookie(response, _COOKIE, token, 1800)
        return response

    @app.get("/cases")
    async def cases(request: Request) -> Response:
        _query(request, {"offset", "limit"})
        person = await principal(request)
        if person is None:
            return RedirectResponse("/login", status_code=303)
        offset = _number(request.query_params.get("offset", "0"), minimum=0, maximum=10000)
        limit = _number(request.query_params.get("limit", "20"), maximum=50)
        items = await _call(person.store().list_cases, person.token, offset, limit)
        return _page(
            "cases.html",
            navigation=await navigation(person),
            cases=items,
            next_offset=offset + limit if len(items) == limit else None,
            limit=limit,
        )

    async def case_page(
        request: Request, case_id: str, revision: str | None = None, finding_id: str | None = None
    ) -> Response:
        _query(request, {"revision"} if finding_id is not None else set())
        if not _HEX.fullmatch(case_id) or (
            finding_id is not None and not _HEX.fullmatch(finding_id)
        ):
            return Response("Not found.", status_code=404)
        person = await principal(request)
        if person is None:
            return RedirectResponse("/login", status_code=303)
        rev = _number(revision) if revision is not None else None
        item = await _call(person.store().case, person.token, case_id, rev)
        if item is None or (
            finding_id is not None and item["payload"].get("finding_id") != finding_id
        ):
            return Response("Not found.", status_code=404)
        csrf = None
        if (
            person.role == "analyst"
            and item["status"] == "current"
            and item["revision"] == item["current_revision"]
        ):
            csrf = secrets.token_urlsafe(32)
            await _call(
                person.store().issue_csrf, person.token, csrf, "note", case_id, item["revision"]
            )
        return _page("case.html", navigation=await navigation(person), case=item, csrf=csrf)

    @app.get("/cases/{case_id}")
    async def case(request: Request, case_id: str) -> Response:
        return await case_page(request, case_id)

    @app.get("/cases/{case_id}/history/{revision}")
    async def history(request: Request, case_id: str, revision: str) -> Response:
        return await case_page(request, case_id, revision)

    @app.get("/cases/{case_id}/findings/{finding_id}")
    async def finding(request: Request, case_id: str, finding_id: str) -> Response:
        return await case_page(request, case_id, request.query_params.get("revision"), finding_id)

    @app.get("/cases/{case_id}/evidence/{event_key}/{record_hash}")
    async def evidence(
        request: Request, case_id: str, event_key: str, record_hash: str
    ) -> Response:
        _query(request, {"revision"})
        if any(not _HEX.fullmatch(value) for value in (case_id, event_key, record_hash)):
            return Response("Not found.", status_code=404)
        person = await principal(request)
        if person is None:
            return RedirectResponse("/login", status_code=303)
        revision = _number(request.query_params.get("revision", "1"))
        item = await _call(
            person.store().evidence, person.token, case_id, revision, event_key, record_hash
        )
        if item is None:
            return Response("Not found.", status_code=404)
        return _page(
            "evidence.html",
            navigation=await navigation(person),
            evidence=item,
            case_id=case_id,
            revision=revision,
        )

    @app.post("/cases/{case_id}/notes")
    async def note(request: Request, case_id: str) -> Response:
        if not _HEX.fullmatch(case_id):
            return Response("Not found.", status_code=404)
        form = await _form(request, {"csrf_token", "revision", "fingerprint", "body"})
        person = await principal(request)
        if person is None:
            return Response("Authentication required.", status_code=401)
        if person.role != "analyst":
            return Response("Request rejected.", status_code=403)
        revision = _number(form["revision"])
        if (
            not _HEX.fullmatch(form["fingerprint"])
            or not 1 <= len(form["body"]) <= 4000
            or any(char == "\x00" or 0xD800 <= ord(char) <= 0xDFFF for char in form["body"])
        ):
            raise EvidenceError("WS_INVALID")
        item = await _call(person.store().case, person.token, case_id)
        if item is None:
            return Response("Not found.", status_code=404)
        await _call(
            person.store().add_note,
            person.token,
            form["csrf_token"],
            case_id,
            revision,
            form["fingerprint"],
            form["body"],
        )
        return RedirectResponse("/cases/" + case_id, status_code=303)

    return app
