"""Complete workflow recovery retains history, originals and least privilege."""

from __future__ import annotations

import secrets

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import verify_store
from cloudsecops_live.worker import work_once
from tests.integration.support import add, one
from tests.integration.test_backup import pg_command, snapshot
from tests.integration.workflow_support import (  # noqa: F401
    workflow,  # noqa: F811
    workspace,
    workspace_password_hash,
)


def test_populated_workflow_binary_restore_preserves_all_rows_and_restricted_authority(
    workflow,  # noqa: F811
    db_factory,  # noqa: F811
):
    from cloudsecops_live.workflow_store import VerifierStore, WorkflowStore
    from cloudsecops_live.workspace_roles import restore_security
    from cloudsecops_live.workspace_store import WorkspaceStore

    source = workflow.db
    token, nonce = workflow.token(), secrets.token_urlsafe(32)
    note_store = workflow.workspace.store()
    note_store.issue_csrf(token, nonce, "note", workflow.cid, workflow.case["current_revision"])
    note_store.add_note(
        token,
        nonce,
        workflow.cid,
        workflow.case["current_revision"],
        workflow.case["fingerprint"],
        "Retained alongside reviewed workflow history.",
    )
    rejected = workflow.recommend()
    workflow.review(rejected, decision="reject")
    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    workflow.close(rec, review, receipt)
    # New duplicate provenance invalidates the closed authority without changing originals.
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    add(source, [base, base + 20, base + 40], "restore-duplicate-context")
    assert workflow.view()["state"] == "reopen_required"
    workflow.reopen()
    work_once(source)
    pending = workflow.recommend()
    workflow.review(pending)
    expected = snapshot(source)
    assert len(expected["ws_recommendations"]) == 3
    assert len(expected["ws_reviews"]) == 3
    assert len(expected["ws_verifications"]) == len(expected["ws_closures"]) == 1
    dump = pg_command(source, "pg_dump", ["--format=custom", "--no-owner", "--no-privileges"])
    assert dump.startswith(b"PGDMP")
    restored = db_factory(migrate=False)
    pg_command(restored, "pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error"], dump)
    assert snapshot(restored) == expected

    def destination(dsn):
        original = Database(dsn)
        return Database(make_conninfo(**{**original._values, "dbname": restored._values["dbname"]}))

    account = workflow.workspace.accounts["reviewer"]
    verifier_db = destination(workflow.verifier_account["dsn"])
    for quarantined in (destination(account["data_dsn"]), verifier_db):
        with pytest.raises(psycopg.Error), quarantined.connect() as conn:
            conn.execute("SELECT 1")
    with pytest.raises(EvidenceError):
        verify_store(restored)
    restore_security(restored)
    assert verify_store(restored)["verified"] is True
    assert snapshot(restored) == expected
    assert snapshot(source) == expected
    auth, data = destination(account["auth_dsn"]), destination(account["data_dsn"])
    recovered = WorkflowStore(auth, data)
    reviewer_token = workflow.token("reviewer")
    assert recovered.view(reviewer_token, workflow.cid)["state"] == "approved"
    assert WorkspaceStore(auth, data).session(reviewer_token)["username"] == "reviewer"
    verifier = VerifierStore(verifier_db)
    assert verifier.identity()["case_id"] == workflow.cid
    for restricted in (auth, data, verifier_db):
        for query in (
            "SELECT archive_bytes FROM csl.raw_objects",
            "DELETE FROM csl.ws_verifications",
            "INSERT INTO csl.ws_verifications DEFAULT VALUES",
            "SET ROLE csl_ws_owner",
            "SET ROLE csl_vf_owner",
            "SELECT * FROM csl.ws_users",
        ):
            with pytest.raises(psycopg.Error), restricted.connect() as conn:
                conn.execute(query)
    request = verifier.begin(pending["recommendation_id"], pending["version"])
    assert verifier.original(request["request_id"], "f" * 64) is None
    raw_id = request["manifest"]["raw_objects"][0]["raw_id"]
    assert isinstance(verifier.original(request["request_id"], raw_id), bytes)
    assert snapshot(source) == expected, "Recovery must never mutate its retained source database"


def test_corrupt_original_content_hash_cannot_yield_verified_or_close(workflow):  # noqa: F811
    with workflow.db.connect() as conn:
        conn.execute("ALTER TABLE csl.raw_objects DISABLE TRIGGER USER")
        conn.execute("UPDATE csl.raw_objects SET content_hash=repeat('0',64)")
        conn.execute("ALTER TABLE csl.raw_objects ENABLE TRIGGER USER")
    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    assert receipt["result"] == "inconclusive"
    assert workflow.view()["state"] == "inconclusive"
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 1


def test_later_contradiction_blocks_using_an_older_verified_receipt(workflow):  # noqa: F811
    rec = workflow.recommend()
    review = workflow.review(rec)
    verified = workflow.verify(rec)
    assert verified["result"] == "verified"
    # This privileged projection-corruption fixture leaves every original intact.
    # An independent proof must discover that the stored semantic claim is false.
    with workflow.db.connect() as conn:
        conn.execute("ALTER TABLE csl.findings DISABLE TRIGGER USER")
        conn.execute("UPDATE csl.findings SET payload=jsonb_set(payload,'{count}','999'::jsonb)")
        conn.execute("ALTER TABLE csl.findings ENABLE TRIGGER USER")
    contradicted = workflow.verify(rec, run_id=secrets.token_hex(16))
    assert contradicted["result"] == "contradicted"
    assert workflow.view()["state"] == "contradicted"
    for receipt in (verified, contradicted):
        with pytest.raises(EvidenceError):
            workflow.close(rec, review, receipt)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
