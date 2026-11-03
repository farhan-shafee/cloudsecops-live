"""A populated v2 identity/session/note workspace survives the forward v3 upgrade."""

from __future__ import annotations

import secrets

from psycopg import sql

from cloudsecops_live.database import Database
from cloudsecops_live.workspace_roles import grant_case, provision_user, setup_gate, setup_roles
from cloudsecops_live.workspace_store import WorkspaceStore, _call
from tests.integration.support import add, current
from tests.integration.test_backup import snapshot
from tests.integration.test_workspace_security import workspace_password_hash  # noqa: F401


def test_v2_accounts_live_sessions_grants_notes_and_throttles_survive_upgrade(
    db_factory,
    monkeypatch,
    workspace_password_hash,  # noqa: F811
):
    import cloudsecops_live.database as database_module
    from cloudsecops_live.worker import work_once

    migrations = database_module._MIGRATIONS
    monkeypatch.setattr(database_module, "_MIGRATIONS", migrations[:2])
    db = db_factory(migrate=False)
    setup_roles(db)
    db.migrate()
    add(db, [0, 20, 40])
    work_once(db)
    case = current(db)[0]
    accounts, tokens = {}, {}
    for role in ("analyst", "reviewer", "auditor"):
        account = provision_user(db, "legacy_" + role, role, workspace_password_hash)
        accounts[role] = account
        grant_case(db, "legacy_" + role, case["case_id"])
        if role == "reviewer":
            # Reproduce the exact v2 membership: reviewers had reader authority only.
            # Current provisioning knows v3; the forward migration must add this capability.
            with db.connect() as conn:
                conn.execute(
                    sql.SQL("REVOKE csl_ws_reviews FROM {}").format(
                        sql.Identifier(Database(account["data_dsn"])._values["user"])
                    )
                )
        token = account["user_id"] + "." + secrets.token_urlsafe(32)
        tokens[role] = token
        # Populate through the original v2 server functions, without a v3 startup validator.
        _call(Database(account["auth_dsn"]), "ws_create_session", (token,))
    analyst = accounts["analyst"]
    note_nonce = secrets.token_urlsafe(32)
    _call(
        Database(analyst["auth_dsn"]),
        "ws_issue_csrf",
        (tokens["analyst"], note_nonce, "note", case["case_id"], case["current_revision"]),
    )
    _call(
        Database(analyst["data_dsn"]),
        "ws_add_note",
        (
            tokens["analyst"],
            note_nonce,
            case["case_id"],
            case["current_revision"],
            case["fingerprint"],
            "A retained v2 analyst observation is not approval.",
        ),
    )
    gate = Database(setup_gate(db))
    _call(gate, "ws_challenge", (secrets.token_urlsafe(32), secrets.token_urlsafe(32)))
    _call(gate, "ws_throttle", ("legacy_analyst",))
    before = snapshot(db)
    assert len(before) == 29
    assert all(
        before[name]
        for name in (
            "ws_users",
            "ws_sessions",
            "ws_csrf",
            "ws_preauth",
            "ws_throttle",
            "ws_case_grants",
            "ws_notes",
            "audit",
        )
    )
    with db.connect() as conn:
        receipts = conn.execute("SELECT * FROM csl.schema_migrations ORDER BY version").fetchall()

    monkeypatch.setattr(database_module, "_MIGRATIONS", migrations)
    db.migrate()
    after = snapshot(db)
    assert len(after) == 41 and set(before) <= set(after)
    for name in before:
        if name != "schema_migrations":
            assert before[name] == after[name], "An existing v2 logical table changed"
    with db.connect() as conn:
        assert (
            conn.execute(
                "SELECT * FROM csl.schema_migrations WHERE version<=2 ORDER BY version"
            ).fetchall()
            == receipts
        )
        reviewer_role = Database(accounts["reviewer"]["data_dsn"])._values["user"]
        assert (
            conn.execute(
                "SELECT pg_has_role(%s,'csl_ws_reviews','MEMBER') AS permitted", (reviewer_role,)
            ).fetchone()["permitted"]
            is True
        )
    for role, account in accounts.items():
        store = WorkspaceStore(Database(account["auth_dsn"]), Database(account["data_dsn"]))
        assert store.session(tokens[role])["username"] == "legacy_" + role
        assert store.password_hash() == workspace_password_hash
        assert store.case(tokens[role], case["case_id"])["case_id"] == case["case_id"]
    db.migrate()
    assert snapshot(db) == after
