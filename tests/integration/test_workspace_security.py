"""Independent adversarial observations through real restricted PostgreSQL identities."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from threading import Barrier
from typing import Any

import httpx
import psycopg
import pytest
from psycopg import sql

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import ingest
from cloudsecops_live.worker import work_once
from tests.helpers import archive, event
from tests.integration.support import add, current, one, rows

ORIGIN = "https://127.0.0.1:8443"
PASSWORD = "Synthetic workspace acceptance passphrase!"  # pragma: allowlist secret - public fixture
SESSION = "__Host-csl_session"


class Forms(HTMLParser):
    """Read actual HTML forms without duplicating the application's renderer."""

    def __init__(self, html: str):
        super().__init__()
        self.forms: dict[str, dict[str, str]] = {}
        self.active: dict[str, str] | None = None
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.active = self.forms.setdefault(values.get("action") or "", {})
        elif tag == "input" and self.active is not None and values.get("name"):
            self.active[str(values["name"])] = values.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.active = None


def fields(response: httpx.Response, action: str) -> dict[str, str]:
    assert response.status_code == 200
    result = Forms(response.text).forms[action]
    assert len(result["csrf_token"]) >= 32
    return result


@dataclass
class Workspace:
    db: Database
    config: Any = field(repr=False)
    accounts: dict[str, dict[str, str]] = field(repr=False)
    cases: list[dict[str, Any]]
    _app: Any = field(default=None, init=False, repr=False)

    def store(self, username: str = "alice"):
        from cloudsecops_live.workspace_store import WorkspaceStore

        account = self.accounts[username]
        return WorkspaceStore(Database(account["auth_dsn"]), Database(account["data_dsn"]))

    def token(self, username: str = "alice") -> str:
        token = self.accounts[username]["user_id"] + "." + secrets.token_urlsafe(32)
        self.store(username).create_session(token)
        return token

    def client(self, *, app=None) -> httpx.AsyncClient:
        from cloudsecops_live.workspace_web import create_app

        if app is None:
            if self._app is None:
                self._app = create_app(self.config)
            app = self._app
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=ORIGIN,
            follow_redirects=False,
        )


@pytest.fixture(scope="session")
def workspace_password_hash():
    from cloudsecops_live.workspace_auth import hash_password

    return hash_password(PASSWORD)


@pytest.fixture
def workspace(db, tmp_path: Path, workspace_password_hash) -> Workspace:
    from cloudsecops_live.workspace_config import AccountConfig, WorkspaceConfig
    from cloudsecops_live.workspace_roles import grant_case, provision_user, setup_gate
    from cloudsecops_live.workspace_tls import create_tls

    add(db, [0, 20, 40])
    work_once(db)
    add(db, [100, 120, 140], "second")
    work_once(db)
    cases = current(db)
    accounts = {
        name: provision_user(db, name, role, workspace_password_hash)
        for name, role in (
            ("alice", "analyst"),
            ("bob", "analyst"),
            ("reviewer", "reviewer"),
            ("auditor", "auditor"),
        )
    }
    for name in ("alice", "reviewer", "auditor"):
        grant_case(db, name, cases[0]["case_id"])
    certificate, key = create_tls(tmp_path / "tls")
    config = WorkspaceConfig(
        origin=ORIGIN,
        gate_db=Database(setup_gate(db)),
        accounts={
            a["user_id"]: AccountConfig(
                a["user_id"], name, Database(a["auth_dsn"]), Database(a["data_dsn"])
            )
            for name, a in accounts.items()
        },
        certificate=certificate,
        key=key,
    )
    return Workspace(db, config, accounts, cases)


async def login(client: httpx.AsyncClient, username: str = "alice", password: str = PASSWORD):
    page = await client.get("/login")
    form = fields(page, "/login")
    return await client.post(
        "/login",
        data={**form, "username": username, "password": password},
        headers={"Origin": ORIGIN},
    )


def note_count(db) -> int:
    return one(db, "SELECT count(*) AS n FROM csl.ws_notes")["n"]


def audit_count(db) -> int:
    return one(db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workspace_note'")["n"]


def test_http_login_session_cookie_headers_and_no_credential_disclosure(workspace):
    async def scenario():
        async with workspace.client() as client:
            response = await login(client)
            assert response.status_code == 303
            assert response.headers["location"] == "/cases"
            cookie = response.headers["set-cookie"]
            for attribute in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
                assert attribute.lower() in cookie.lower()
            assert "domain=" not in cookie.lower()
            token = client.cookies.get(SESSION)
            shape_valid = re.fullmatch(r"[0-9a-f]{32}\.[A-Za-z0-9_-]{43}", token) is not None
            assert shape_valid
            page = await client.get("/cases")
            assert page.status_code == 200
            public_response_safe = all(
                value not in page.text for value in (token, PASSWORD, "$argon2id$")
            )
            assert public_response_safe
            assert "no-store" in page.headers["cache-control"]
            assert page.headers["x-content-type-options"] == "nosniff"
            assert "default-src 'none'" in page.headers["content-security-policy"]
            assert page.headers["referrer-policy"] == "no-referrer"
            assert "access-control-allow-origin" not in page.headers
            digest = sha256(token.encode()).hexdigest()
            only_digest_persisted = (
                one(workspace.db, "SELECT token_hash FROM csl.ws_sessions")["token_hash"] == digest
            )
            assert only_digest_persisted
            for route in ("/docs", "/redoc", "/openapi.json", "/approve", "/verify", "/close"):
                assert (await client.get(route)).status_code == 404

    asyncio.run(scenario())


def test_login_generic_failures_persisted_throttle_and_preauth_replay(workspace):
    from cloudsecops_live.workspace_web import create_app

    async def scenario():
        async with workspace.client() as client:
            expired_page = await client.get("/login")
            expired_form = fields(expired_page, "/login")
            with workspace.db.connect() as conn:
                conn.execute(
                    "UPDATE csl.ws_preauth SET expires_at=clock_timestamp()-interval '1 second'"
                )
            expired_login = await client.post(
                "/login",
                data={**expired_form, "username": "alice", "password": PASSWORD},
                headers={"Origin": ORIGIN},
            )
            assert expired_login.status_code == 403
            page = await client.get("/login")
            form = fields(page, "/login")
            bad = await client.post(
                "/login",
                data={**form, "username": "alice", "password": "wrong"},  # pragma: allowlist secret
                headers={"Origin": ORIGIN},
            )
            assert bad.status_code == 401
            replay = await client.post(
                "/login",
                data={**form, "username": "alice", "password": PASSWORD},
                headers={"Origin": ORIGIN},
            )
            assert replay.status_code == 403
            unknown = await login(client, "unknown", "wrong")
            assert unknown.status_code == 401

            def scrub(value):
                return re.sub(r"[A-Za-z0-9_-]{32,}", "NONCE", value)

            assert scrub(bad.text) == scrub(unknown.text)
            for _ in range(4):
                assert (await login(client, "alice", "wrong")).status_code == 401
        # A completely new application instance must retain the database throttle.
        async with workspace.client(app=create_app(workspace.config)) as restarted:
            blocked = await login(restarted)
            assert blocked.status_code in (401, 429)
            assert restarted.cookies.get(SESSION) is None
        assert one(workspace.db, "SELECT count(*) AS n FROM csl.ws_sessions")["n"] == 0
        assert one(workspace.db, "SELECT max(attempts) AS n FROM csl.ws_throttle")["n"] >= 6

    asyncio.run(scenario())


def test_session_fixation_forged_role_hash_bearer_expiry_revocation_and_disable(workspace):
    from cloudsecops_live.workspace_roles import disable_user

    async def scenario():
        async with workspace.client() as client:
            client.cookies.set(
                SESSION,
                workspace.accounts["alice"]["user_id"] + "." + "X" * 43,
                domain="127.0.0.1",
                path="/",
            )
            assert (await login(client)).status_code == 303
            token = client.cookies.get(SESSION)
            fixation_replaced = not token.endswith("X" * 43)
            assert fixation_replaced
            digest = sha256(token.encode()).hexdigest()
            for forged in (
                digest,
                workspace.accounts["bob"]["user_id"] + "." + token.split(".")[1],
                "admin",
                "' OR 1=1 --",
            ):
                async with workspace.client() as attacker:
                    attacker.cookies.set(SESSION, forged)
                    response = await attacker.get(
                        "/cases", headers={"X-User": "alice", "X-Role": "analyst"}
                    )
                    assert response.status_code in (303, 401)
            for condition in ("expires_at=clock_timestamp()-interval '1 second'", "revoked=true"):
                fresh = workspace.token()
                with workspace.db.connect() as conn:
                    conn.execute(
                        sql.SQL("UPDATE csl.ws_sessions SET {} WHERE token_hash=%s").format(
                            sql.SQL(condition)
                        ),
                        (sha256(fresh.encode()).hexdigest(),),
                    )
                async with workspace.client() as expired:
                    expired.cookies.set(SESSION, fresh)
                    assert (await expired.get("/cases")).status_code in (303, 401)
            disable_user(workspace.db, "alice")
            assert (await client.get("/cases")).status_code in (303, 401)
            sessions_before = one(workspace.db, "SELECT count(*) AS n FROM csl.ws_sessions")["n"]
            rejected = await login(client)
            assert rejected.status_code == 401
            assert "Sign-in failed." in rejected.text
            assert SESSION not in rejected.headers.get("set-cookie", "")
            assert (
                one(workspace.db, "SELECT count(*) AS n FROM csl.ws_sessions")["n"]
                == sessions_before
            )

    asyncio.run(scenario())


def test_assigned_case_history_exact_evidence_and_no_lineage_inheritance(workspace):
    async def scenario():
        cid, other = (c["case_id"] for c in workspace.cases)
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            page = await client.get("/cases")
            assert cid in page.text and other not in page.text
            unknown = await client.get("/cases/" + "f" * 64)
            denied = await client.get("/cases/" + other)
            assert unknown.status_code == denied.status_code == 404
            assert unknown.text == denied.text
            assert (await client.get(f"/cases/{cid}/history/1")).status_code == 200
            assert (await client.get(f"/cases/{other}/history/1")).status_code == 404
            assert (await client.get(f"/cases/{cid}/history/999")).status_code == 404
            evidence = rows(
                workspace.db,
                "SELECT e.event_key,e.record_hash,r.case_id,r.finding_id "
                "FROM csl.finding_evidence e JOIN csl.case_revisions r "
                "ON r.finding_id=e.finding_id",
            )
            assigned = next(e for e in evidence if e["case_id"] == cid)
            unassigned = next(e for e in evidence if e["case_id"] == other)
            prefix = f"/cases/{cid}/evidence/"
            allowed = await client.get(
                prefix + assigned["event_key"] + "/" + assigned["record_hash"] + "?revision=1"
            )
            assert allowed.status_code == 200
            for ek, rh in (
                (assigned["event_key"], "0" * 64),
                (unassigned["event_key"], unassigned["record_hash"]),
            ):
                assert (await client.get(prefix + ek + "/" + rh + "?revision=1")).status_code == 404
            assert (
                await client.get(f"/cases/{cid}/findings/{assigned['finding_id']}?revision=1")
            ).status_code == 200
            assert (
                await client.get(f"/cases/{cid}/findings/{unassigned['finding_id']}?revision=1")
            ).status_code == 404
            add(workspace.db, [70], "bridge")
            work_once(workspace.db)
            merged = current(workspace.db)[0]["case_id"]
            assert merged not in (cid, other)
            assert (await client.get("/cases/" + merged)).status_code == 404
            assert (await client.get(f"/cases/{cid}/history/1")).status_code == 200
            original = one(
                workspace.db,
                "SELECT canonical_bytes FROM csl.record_variants "
                "WHERE event_key=%s AND record_hash=%s",
                (assigned["event_key"], assigned["record_hash"]),
            )
            changed = json.loads(bytes(original["canonical_bytes"]))
            changed["untrustedFutureField"] = "alternate retained record"
            ingest(
                workspace.db,
                [("synthetic/alternate.gz", archive([changed]))],
                checkpoint="alternate",
            )
            alternative = one(
                workspace.db,
                "SELECT record_hash FROM csl.record_variants "
                "WHERE event_key=%s AND record_hash<>%s",
                (assigned["event_key"], assigned["record_hash"]),
            )
            assert (
                await client.get(
                    prefix
                    + assigned["event_key"]
                    + "/"
                    + alternative["record_hash"]
                    + "?revision=1"
                )
            ).status_code == 404
            assert (
                await client.get(
                    prefix + assigned["event_key"] + "/" + assigned["record_hash"] + "?revision=1"
                )
            ).status_code == 200
            assert (await client.get(f"/cases/{cid}/download")).status_code == 404

    asyncio.run(scenario())


def test_http_csrf_origin_host_body_query_and_path_boundaries(workspace):
    async def scenario():
        cid = workspace.cases[0]["case_id"]
        target = f"/cases/{cid}/notes"
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            form = fields(await client.get(f"/cases/{cid}"), target)
            valid = {**form, "body": "synthetic acceptance note"}
            for inaccessible in (workspace.cases[1]["case_id"], "f" * 64):
                denied = await client.post(
                    f"/cases/{inaccessible}/notes",
                    data=valid,
                    headers={"Origin": ORIGIN},
                )
                assert denied.status_code == 404
                assert denied.text == "Not found."
            async with workspace.client() as anonymous:
                assert (
                    await anonymous.post(target, data=valid, headers={"Origin": ORIGIN})
                ).status_code == 401
            duplicate_cookie = await client.get(
                "/cases",
                headers={"Cookie": f"{SESSION}=forged; {SESSION}={client.cookies.get(SESSION)}"},
            )
            assert duplicate_cookie.status_code == 303
            for headers in (
                {},
                {"Origin": "https://evil.example"},
                {"Origin": "null"},
                {"Origin": ORIGIN, "Host": "evil.example"},
                {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
            ):
                assert (await client.post(target, data=valid, headers=headers)).status_code == 403
            for data in (
                {k: v for k, v in valid.items() if k != "csrf_token"},
                {**valid, "csrf_token": "X" * 43},
            ):
                assert (
                    await client.post(target, data=data, headers={"Origin": ORIGIN})
                ).status_code == 403
            for body in ("", "   ", "x" * 4001):
                response = await client.post(
                    target, data={**valid, "body": body}, headers={"Origin": ORIGIN}
                )
                assert response.status_code in (400, 413)
            assert (
                await client.post(target, json=valid, headers={"Origin": ORIGIN})
            ).status_code == 400
            for malformed in (
                b"csrf_token=%GG",
                b"csrf_token=%FF",
                b"csrf_token=a&csrf_token=b",
                b"csrf_token=a&revision=1&fingerprint=x&body=y&role=analyst",
            ):
                response = await client.post(
                    target,
                    content=malformed,
                    headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
                )
                assert response.status_code == 400
            assert (
                await client.post(
                    target,
                    content=b"x" * 100_000,
                    headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"},
                )
            ).status_code == 413
            for suffix in (
                "?offset=-1",
                "?offset=10001",
                "?limit=0",
                "?limit=51",
                "?limit=x",
                "?role=admin",
                "?limit=1&limit=2",
            ):
                assert (await client.get("/cases" + suffix)).status_code in (400, 404)
            for suffix in ("?path=/etc/passwd", "?revision=0", "?revision=x"):
                assert (await client.get(f"/cases/{cid}" + suffix)).status_code in (400, 404)
            for path in ("/cases/%27%20OR%201=1--", "/cases/..%2F..%2Fetc%2Fpasswd"):
                assert (await client.get(path)).status_code in (400, 404)
            assert (await client.get("http://127.0.0.1:8443/cases")).status_code == 400
            assert (await client.get("/" + "x" * 2049)).status_code == 414
            assert (await client.get("/cases?x=" + "y" * 2049)).status_code == 414
            duplicate_host = await client.get(
                "/cases",
                headers=[("Host", "127.0.0.1:8443"), ("Host", "127.0.0.1:8443")],
            )
            assert duplicate_host.status_code == 403
            assert (await client.get("/cases", headers={"X-Large": "x" * 17000})).status_code == 431
            assert note_count(workspace.db) == audit_count(workspace.db) == 0

    asyncio.run(scenario())


def test_note_append_escaping_nonce_replay_stale_and_pending_revision(workspace):
    async def scenario():
        cid = workspace.cases[0]["case_id"]
        target = f"/cases/{cid}/notes"
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            form = fields(await client.get(f"/cases/{cid}"), target)
            body = '<script>alert("synthetic")</script> \' ; DROP TABLE csl.cases; --'
            response = await client.post(
                target, data={**form, "body": body}, headers={"Origin": ORIGIN}
            )
            assert response.status_code == 303
            assert note_count(workspace.db) == audit_count(workspace.db) == 1
            assert one(workspace.db, "SELECT body FROM csl.ws_notes")["body"] == body
            page = await client.get(f"/cases/{cid}")
            assert "<script>" not in page.text and "&lt;script&gt;" in page.text
            replay = await client.post(
                target, data={**form, "body": "replay"}, headers={"Origin": ORIGIN}
            )
            assert replay.status_code == 403
            expired = fields(page, target)
            with workspace.db.connect() as conn:
                conn.execute(
                    "UPDATE csl.ws_csrf SET expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE nonce_hash=%s",
                    (sha256(expired["csrf_token"].encode()).hexdigest(),),
                )
            assert (
                await client.post(
                    target, data={**expired, "body": "expired"}, headers={"Origin": ORIGIN}
                )
            ).status_code == 403
            stale = fields(await client.get(f"/cases/{cid}"), target)
            # Deliberately change the machine revision through the real collector/worker.
            first_seconds = (
                0 if "e0" in workspace.cases[0]["payload"]["evidence_event_ids"] else 100
            )
            add(workspace.db, [first_seconds + 10], "late")
            assert (
                await client.post(
                    target, data={**stale, "body": "pending"}, headers={"Origin": ORIGIN}
                )
            ).status_code == 409
            work_once(workspace.db)
            assert (
                await client.post(
                    target, data={**stale, "body": "stale"}, headers={"Origin": ORIGIN}
                )
            ).status_code == 409
            assert note_count(workspace.db) == audit_count(workspace.db) == 1

    asyncio.run(scenario())


def test_reviewer_auditor_have_sql_and_http_read_only_assignment(workspace):
    async def scenario():
        cid = workspace.cases[0]["case_id"]
        for username in ("reviewer", "auditor"):
            token = workspace.token(username)
            store = workspace.store(username)
            assert len(store.list_cases(token)) == 1
            nonce = secrets.token_urlsafe(32)
            store.issue_csrf(token, nonce, "note", cid, 1)
            with pytest.raises((EvidenceError, psycopg.Error)):
                store.add_note(token, nonce, cid, 1, workspace.cases[0]["fingerprint"], "forbidden")
            async with workspace.client() as client:
                assert (await login(client, username)).status_code == 303
                page = await client.get(f"/cases/{cid}")
                assert page.status_code == 200
                assert f"/cases/{cid}/notes" not in Forms(page.text).forms
                denied = await client.post(
                    f"/cases/{cid}/notes",
                    data={
                        "csrf_token": nonce,
                        "revision": "1",
                        "fingerprint": workspace.cases[0]["fingerprint"],
                        "body": "forbidden",
                    },
                    headers={"Origin": ORIGIN, "X-Role": "analyst"},
                )
                assert denied.status_code == 403
        assert note_count(workspace.db) == audit_count(workspace.db) == 0

    asyncio.run(scenario())


def test_distinct_concurrent_note_nonces_append_and_shared_nonce_commits_once(workspace):
    cid = workspace.cases[0]["case_id"]
    fp = workspace.cases[0]["fingerprint"]
    token = workspace.token()
    store = workspace.store()

    def race(nonces):
        start = Barrier(2)

        def append(pair):
            index, nonce = pair
            start.wait(timeout=10)
            try:
                workspace.store().add_note(token, nonce, cid, 1, fp, "parallel " + str(index))
                return "committed"
            except EvidenceError as exc:
                assert exc.code == "WS_DENIED"
                return "denied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            return sorted(pool.map(append, enumerate(nonces)))

    distinct = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
    for nonce in distinct:
        store.issue_csrf(token, nonce, "note", cid, 1)
    assert race(distinct) == ["committed", "committed"]
    same = secrets.token_urlsafe(32)
    store.issue_csrf(token, same, "note", cid, 1)
    assert race([same, same]) == ["committed", "denied"]
    assert note_count(workspace.db) == audit_count(workspace.db) == 3


def test_real_audit_failure_rolls_back_note_and_nonce_atomically(workspace):
    cid = workspace.cases[0]["case_id"]
    token, nonce = workspace.token(), secrets.token_urlsafe(32)
    store = workspace.store()
    store.issue_csrf(token, nonce, "note", cid, 1)
    with workspace.db.connect() as conn:
        conn.execute(
            "CREATE FUNCTION public.test_workspace_audit_fault() RETURNS trigger LANGUAGE plpgsql "
            "AS $$ BEGIN RAISE EXCEPTION 'controlled_test_audit_fault'; END $$"
        )
        conn.execute(
            "CREATE TRIGGER test_workspace_audit_fault BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION public.test_workspace_audit_fault()"
        )
    try:
        with pytest.raises((EvidenceError, psycopg.Error)):
            store.add_note(
                token, nonce, cid, 1, workspace.cases[0]["fingerprint"], "must roll back"
            )
        assert note_count(workspace.db) == audit_count(workspace.db) == 0
        assert (
            one(
                workspace.db,
                "SELECT used FROM csl.ws_csrf WHERE nonce_hash=%s",
                (sha256(nonce.encode()).hexdigest(),),
            )["used"]
            is False
        )
    finally:
        with workspace.db.connect() as conn:
            conn.execute("DROP TRIGGER test_workspace_audit_fault ON csl.audit")
            conn.execute("DROP FUNCTION public.test_workspace_audit_fault()")
    store.add_note(token, nonce, cid, 1, workspace.cases[0]["fingerprint"], "retry after repair")
    assert note_count(workspace.db) == audit_count(workspace.db) == 1


def test_session_rotation_logout_and_csrf_action_binding(workspace):
    async def scenario():
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            old = client.cookies.get(SESSION)
            forms = Forms((await client.get("/cases")).text).forms
            wrong = await client.post(
                "/session/rotate", data=forms["/logout"], headers={"Origin": ORIGIN}
            )
            assert wrong.status_code == 403
            rotated = await client.post(
                "/session/rotate", data=forms["/session/rotate"], headers={"Origin": ORIGIN}
            )
            assert rotated.status_code == 303
            new = client.cookies.get(SESSION)
            rotated_material = new != old
            assert rotated_material
            assert workspace.store().session(old) is None
            assert workspace.store().session(new) is not None
            form = fields(await client.get("/cases"), "/logout")
            assert (
                await client.post("/logout", data=form, headers={"Origin": ORIGIN})
            ).status_code == 303
            assert workspace.store().session(new) is None
            assert (await client.get("/cases")).status_code in (303, 401)

    asyncio.run(scenario())


def test_restricted_sql_credentials_cannot_escalate_or_cross_account(workspace):
    token = workspace.token()
    cid = workspace.cases[0]["case_id"]
    for username in ("alice", "reviewer", "auditor"):
        for kind in ("auth_dsn", "data_dsn"):
            restricted = Database(workspace.accounts[username][kind])
            denied = [
                "SELECT * FROM csl.ws_users",
                "SELECT * FROM csl.ws_sessions",
                "SELECT * FROM csl.cases",
                "UPDATE csl.ws_users SET app_role='analyst'",
                "DELETE FROM csl.ws_case_grants",
                "INSERT INTO csl.audit(kind,payload) VALUES('x','{}')",
                "CREATE TABLE public.shadow(value integer)",
                "CREATE TABLE csl.shadow(value integer)",
                "SET ROLE csl_ws_owner",
                "SET ROLE csl_ws_verifier",
                "SET ROLE csl_ws_gate",
                "CREATE ROLE workspace_escalated",
                "ALTER DEFAULT PRIVILEGES FOR ROLE csl_ws_owner IN SCHEMA csl "
                "GRANT ALL ON TABLES TO PUBLIC",
                "SELECT csl.ws_account('" + token + "')",
            ]
            if kind == "auth_dsn":
                denied.append("SELECT csl.ws_list_cases('" + token + "')")
                denied.append("SET ROLE csl_ws_reader")
            else:
                denied.append("SELECT csl.ws_password_hash()")
                denied.append("SET ROLE csl_ws_auth")
                if username != "alice":
                    denied.append("SET ROLE csl_ws_notes")
            for index, statement in enumerate(denied):
                with restricted.connect() as conn:
                    try:
                        conn.execute(statement)
                    except psycopg.Error:
                        pass
                    else:
                        pytest.fail(f"Restricted SQL {index} succeeded ({username}/{kind})")
                    finally:
                        conn.rollback()
            # PUBLIC may retain PostgreSQL's TEMP capability. A shadow relation must
            # never influence any SECURITY DEFINER identity or authorization lookup.
            with restricted.connect() as conn:
                conn.execute("CREATE TEMP TABLE ws_users(user_id text,app_role text)")
                conn.execute("INSERT INTO ws_users VALUES('forged','analyst')")
                identity = conn.execute("SELECT csl.ws_identity() AS value").fetchone()["value"]
                assert identity["username"] == username
                assert identity["user_id"] == workspace.accounts[username]["user_id"]
    bob = workspace.store("bob")
    assert bob.session(token) is None
    with pytest.raises(EvidenceError):
        bob.case(token, cid)
    with workspace.config.gate_db.connect() as conn:
        for name in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"):
            assert (
                conn.execute(
                    "SELECT " + name + " AS allowed FROM pg_roles WHERE rolname=SESSION_USER"
                ).fetchone()["allowed"]
                is False
            )
    for statement in (
        "SELECT * FROM csl.ws_users",
        "SELECT csl.ws_password_hash()",
        "SET ROLE csl_ws_owner",
    ):
        with pytest.raises(psycopg.Error), workspace.config.gate_db.connect() as conn:
            conn.execute(statement)


def test_source_event_html_is_escaped_and_database_outage_mutation_fails_closed(workspace):
    async def scenario():
        cid = workspace.cases[0]["case_id"]
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            target = f"/cases/{cid}/notes"
            form = fields(await client.get(f"/cases/{cid}"), target)
            # Revoke CONNECT and terminate only this account's data backend, never the service.
            role = Database(workspace.accounts["alice"]["data_dsn"])._values["user"]
            with workspace.db.connect() as conn:
                conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(role)))
            try:
                response = await client.post(
                    target, data={**form, "body": "outage"}, headers={"Origin": ORIGIN}
                )
                assert response.status_code == 503
                assert note_count(workspace.db) == audit_count(workspace.db) == 0
                assert "password" not in response.text.lower()
            finally:
                with workspace.db.connect() as conn:
                    conn.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(role)))

    asyncio.run(scenario())
    # The raw malicious source remains exact evidence; its HTML representation must escape it.
    source = event("xss", 500, account="LABACCOUNT_XSS")
    source["untrustedText"] = '<img src=x onerror="alert(1)">'
    others = [
        event("xss2", 520, account="LABACCOUNT_XSS"),
        event("xss3", 540, account="LABACCOUNT_XSS"),
    ]
    ingest(workspace.db, [("synthetic/xss.gz", archive([source, *others]))], checkpoint="xss")
    work_once(workspace.db)
    from cloudsecops_live.workspace_roles import grant_case

    record = one(
        workspace.db,
        "SELECT e.event_key,e.record_hash,r.case_id FROM csl.finding_evidence e "
        "JOIN csl.case_revisions r ON r.finding_id=e.finding_id JOIN csl.record_variants v "
        "ON (v.event_key,v.record_hash)=(e.event_key,e.record_hash) "
        "WHERE convert_from(v.canonical_bytes,'UTF8')::jsonb->>'eventID'='xss'",
    )
    grant_case(workspace.db, "alice", record["case_id"])

    async def escaped():
        async with workspace.client() as client:
            assert (await login(client)).status_code == 303
            page = await client.get(
                f"/cases/{record['case_id']}/evidence/{record['event_key']}/{record['record_hash']}?revision=1"
            )
            assert page.status_code == 200
            assert "<img" not in page.text and "&lt;img" in page.text

    asyncio.run(escaped())
