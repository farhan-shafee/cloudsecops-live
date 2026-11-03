"""A killed restricted backend rolls back an in-flight note and its CSRF consumption."""

from __future__ import annotations

import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest
from psycopg import sql

from cloudsecops_live.errors import EvidenceError
from tests.integration.support import one
from tests.integration.test_workspace_security import (  # noqa: F401
    workspace,
    workspace_password_hash,
)


def test_backend_termination_between_note_insert_and_audit_rolls_back_then_retries(
    workspace,  # noqa: F811
):
    store = workspace.store()
    token = workspace.token()
    nonce = secrets.token_urlsafe(32)
    case = workspace.cases[0]
    cid, revision, fingerprint = case["case_id"], case["current_revision"], case["fingerprint"]
    store.issue_csrf(token, nonce, "note", cid, revision)
    nonce_hash = sha256(nonce.encode()).hexdigest()
    lock_key = secrets.randbits(63)
    data_role = store.data_db._values["user"]

    with workspace.db.connect() as control:
        control.autocommit = True
        control.execute("SELECT pg_advisory_lock(%s)", (lock_key,))
        control.execute(
            sql.SQL("""CREATE FUNCTION csl.note_interruption_wait() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
              IF NEW.kind='workspace_note' THEN
                IF NOT EXISTS(SELECT FROM csl.ws_notes
                              WHERE note_id=NEW.payload->>'note_id') THEN
                  RAISE EXCEPTION 'note must exist before audit';
                END IF;
                PERFORM pg_catalog.pg_advisory_xact_lock({});
              END IF;
              RETURN NEW;
            END $$""").format(sql.Literal(lock_key))
        )
        control.execute(
            "CREATE TRIGGER note_interruption_wait BEFORE INSERT ON csl.audit "
            "FOR EACH ROW EXECUTE FUNCTION csl.note_interruption_wait()"
        )
        executor = ThreadPoolExecutor(max_workers=1)
        victim_pid: int | None = None
        try:
            future = executor.submit(
                store.add_note,
                token,
                nonce,
                cid,
                revision,
                fingerprint,
                "note interrupted after insertion",
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                waiting = control.execute(
                    "SELECT pid FROM pg_catalog.pg_stat_activity WHERE datname=%s "
                    "AND usename=%s AND backend_type='client backend' "
                    "AND wait_event_type='Lock' AND lower(wait_event)='advisory' "
                    "AND pid<>pg_backend_pid()",
                    (workspace.db._values["dbname"], data_role),
                ).fetchall()
                assert len(waiting) <= 1, "Only the declared account's note backend may be targeted"
                if waiting:
                    victim_pid = waiting[0]["pid"]
                    break
                if future.done():
                    pytest.fail("Note ended before reaching the controlled audit barrier")
                time.sleep(0.02)
            assert victim_pid is not None, "Note did not reach the audit advisory-lock barrier"
            terminated = control.execute(
                "SELECT pg_terminate_backend(%s) AS stopped", (victim_pid,)
            ).fetchone()
            assert terminated["stopped"] is True
            with pytest.raises(EvidenceError) as failure:
                future.result(timeout=5)
            assert failure.value.code == "WS_DATABASE"
            assert one(workspace.db, "SELECT count(*) AS n FROM csl.ws_notes")["n"] == 0
            assert (
                one(
                    workspace.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workspace_note'"
                )["n"]
                == 0
            )
            assert (
                one(
                    workspace.db, "SELECT used FROM csl.ws_csrf WHERE nonce_hash=%s", (nonce_hash,)
                )["used"]
                is False
            )
        finally:
            control.execute("SELECT pg_advisory_unlock(%s)", (lock_key,))
            executor.shutdown(wait=True, cancel_futures=True)
            control.execute("DROP TRIGGER note_interruption_wait ON csl.audit")
            control.execute("DROP FUNCTION csl.note_interruption_wait()")

    result = store.add_note(
        token, nonce, cid, revision, fingerprint, "retry after backend termination"
    )
    assert result["case_id"] == cid
    assert one(workspace.db, "SELECT count(*) AS n FROM csl.ws_notes")["n"] == 1
    assert (
        one(workspace.db, "SELECT count(*) AS n FROM csl.audit WHERE kind='workspace_note'")["n"]
        == 1
    )
    assert (
        one(workspace.db, "SELECT used FROM csl.ws_csrf WHERE nonce_hash=%s", (nonce_hash,))["used"]
        is True
    )
