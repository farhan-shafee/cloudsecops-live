"""Populated binary backup retains private state and reconstructs least privilege."""

from __future__ import annotations

import secrets
from hashlib import sha256

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import verify_store
from tests.integration.support import one
from tests.integration.test_backup import pg_command, snapshot
from tests.integration.test_workspace_security import (  # noqa: F401
    workspace,
    workspace_password_hash,
)


def test_populated_workspace_dump_restore_rejects_missing_security_and_preserves_every_hash(
    workspace,  # noqa: F811
    db_factory,
):
    from cloudsecops_live.workspace_roles import restore_security
    from cloudsecops_live.workspace_store import WorkspaceStore

    source = workspace.db
    token, nonce = workspace.token(), secrets.token_urlsafe(32)
    store = workspace.store()
    case = workspace.cases[0]
    store.issue_csrf(token, nonce, "note", case["case_id"], 1)
    store.add_note(token, nonce, case["case_id"], 1, case["fingerprint"], "retained restore note")
    expected = snapshot(source)
    assert len(expected["ws_users"]) == 4
    assert len(expected["ws_sessions"]) == len(expected["ws_notes"]) == 1
    assert len(expected["ws_case_grants"]) == 3
    dump = pg_command(source, "pg_dump", ["--format=custom", "--no-owner", "--no-privileges"])
    restored = db_factory(migrate=False)
    pg_command(restored, "pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error"], dump)
    assert snapshot(restored) == expected
    probe_values = Database(workspace.accounts["alice"]["data_dsn"])._values
    quarantined_reader = Database(
        make_conninfo(**{**probe_values, "dbname": restored._values["dbname"]})
    )
    with pytest.raises(psycopg.Error), quarantined_reader.connect() as conn:
        conn.execute("SELECT 1")
    with pytest.raises(EvidenceError):
        verify_store(restored)
    restore_security(restored)
    assert verify_store(restored)["verified"] is True
    assert snapshot(restored) == expected
    assert snapshot(source) == expected

    def destination(dsn):
        original = Database(dsn)
        return Database(make_conninfo(**{**original._values, "dbname": restored._values["dbname"]}))

    account = workspace.accounts["alice"]
    auth, data = destination(account["auth_dsn"]), destination(account["data_dsn"])
    recovered = WorkspaceStore(auth, data)
    assert recovered.session(token)["username"] == "alice"
    assert len(recovered.list_cases(token)) == 1
    assert len(recovered.case(token, case["case_id"])["notes"]) == 1
    for connection, statement in (
        (auth, "SELECT * FROM csl.ws_sessions"),
        (auth, "SELECT * FROM csl.cases"),
        (data, "UPDATE csl.ws_users SET app_role='analyst'"),
        (data, "DELETE FROM csl.ws_notes"),
        (data, "SET ROLE csl_ws_owner"),
    ):
        with pytest.raises(psycopg.Error), connection.connect() as conn:
            conn.execute(statement)
    digest = sha256(token.encode()).hexdigest()
    assert recovered.session(digest) is None
    assert (
        one(restored, "SELECT count(*) AS n FROM csl.audit WHERE kind='workspace_note'")["n"] == 1
    )
    assert snapshot(restored) == expected
