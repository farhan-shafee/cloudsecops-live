"""Real PostgreSQL observations of the reviewed workflow and service boundary."""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import psycopg
import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.worker import work_once
from cloudsecops_live.workspace_roles import grant_case, provision_user
from tests.integration.support import add, current, one


def test_forward_workflow_schema_is_latest_and_keeps_machine_drafts(db):
    assert one(db, "SELECT max(version) AS version FROM csl.schema_migrations")["version"] == 3
    add(db, [0, 20, 40])
    work_once(db)
    assert current(db)[0]["payload"]["unreviewed"] is True


@pytest.fixture
def reviewed(db):
    from cloudsecops_live.workflow_store import WorkflowStore
    from cloudsecops_live.workspace_store import WorkspaceStore

    add(db, [0, 20, 40])
    work_once(db)
    case = current(db)[0]
    users = {}
    for username, role in (
        ("author", "analyst"),
        ("reviewer", "reviewer"),
        ("other", "reviewer"),
        ("auditor", "auditor"),
    ):
        account = provision_user(db, username, role, "x" * 64)
        grant_case(db, username, case["case_id"])
        auth, data = Database(account["auth_dsn"]), Database(account["data_dsn"])
        token = account["user_id"] + "." + secrets.token_urlsafe(32)
        WorkspaceStore(auth, data).create_session(token)
        users[username] = (WorkflowStore(auth, data), token, account)
    return db, case, users


def propose(reviewed):
    _, case, users = reviewed
    store, token, _ = users["author"]
    view = store.view(token, case["case_id"])
    nonce = secrets.token_urlsafe(32)
    store.issue_csrf(token, nonce, "recommend", case["case_id"], view["workflow_version"])
    return store.recommend(
        token,
        nonce,
        case["case_id"],
        case["current_revision"],
        case["fingerprint"],
        view["workflow_version"],
        "Authorized synthetic lab exercise",
        "Inventory tools can look similar",
        "Synthetic observations only",
    )


def approve(reviewed, recommendation):
    _, case, users = reviewed
    store, token, _ = users["reviewer"]
    view = store.view(token, case["case_id"])
    nonce = secrets.token_urlsafe(32)
    store.issue_csrf(
        token, nonce, "review", case["case_id"], view["workflow_version"], recommendation["version"]
    )
    return store.review(
        token,
        nonce,
        case["case_id"],
        view["workflow_version"],
        recommendation["recommendation_id"],
        recommendation["version"],
        recommendation["recommendation_hash"],
        "approve",
        "Exact synthetic evidence reviewed",
    )


def test_recommendation_review_authority_immutable_and_pending_batch(reviewed):
    db, case, users = reviewed
    rec = propose(reviewed)
    assert rec["payload"]["action"] == "NO_ACTION_AUTHORIZED_EXERCISE"
    assert rec["payload"]["execution_targets"] == []
    assert rec["payload"]["authenticated"] is False
    approval = approve(reviewed, rec)
    assert approval["reviewer_id"] != rec["author_id"]
    assert users["reviewer"][0].view(users["reviewer"][1], case["case_id"])["state"] == "approved"
    for username in ("author", "reviewer", "auditor"):
        data = Database(users[username][2]["data_dsn"])
        for statement in (
            "SELECT * FROM csl.ws_recommendations",
            "INSERT INTO csl.ws_verifications DEFAULT VALUES",
            "SELECT csl.vf_identity()",
            "SET ROLE csl_vf_owner",
        ):
            with pytest.raises(psycopg.Error), data.connect() as conn:
                conn.execute(statement)
    with pytest.raises(psycopg.Error), db.connect() as conn:
        conn.execute("UPDATE csl.ws_recommendations SET payload='{}'::jsonb")
    add(db, [10], "late")
    view = users["reviewer"][0].view(users["reviewer"][1], case["case_id"])
    assert view["state"] == "open"
    assert view["current_recommendation"]["effective"] is False
    assert one(db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 1


def test_two_reviewers_cannot_overwrite_a_final_decision(reviewed):
    db, case, users = reviewed
    rec = propose(reviewed)
    start = Barrier(2)
    prepared = []
    for name in ("reviewer", "other"):
        store, token, _ = users[name]
        view = store.view(token, case["case_id"])
        nonce = secrets.token_urlsafe(32)
        store.issue_csrf(
            token, nonce, "review", case["case_id"], view["workflow_version"], rec["version"]
        )
        prepared.append((store, token, nonce, view["workflow_version"]))

    def decide(item):
        store, token, nonce, version = item
        start.wait(timeout=10)
        try:
            store.review(
                token,
                nonce,
                case["case_id"],
                version,
                rec["recommendation_id"],
                rec["version"],
                rec["recommendation_hash"],
                "approve",
                "Reviewed",
            )
            return "committed"
        except EvidenceError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(decide, prepared))
    assert sorted(result) == ["WS_STALE", "committed"]
    assert one(db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 1


def test_verifier_case_credential_can_only_fetch_pinned_originals_and_receipt(reviewed):
    from cloudsecops_live.workflow_store import VerifierStore
    from cloudsecops_live.workspace_roles import provision_verifier

    db, case, users = reviewed
    rec = propose(reviewed)
    approve(reviewed, rec)
    identity = provision_verifier(db, case["case_id"], "a" * 64)
    verifier = VerifierStore(Database(identity["dsn"]))
    assert verifier.identity()["case_id"] == case["case_id"]
    request = verifier.begin(rec["recommendation_id"], rec["version"])
    raw_id = request["manifest"]["raw_objects"][0]["raw_id"]
    assert verifier.original(request["request_id"], raw_id)
    assert verifier.original(request["request_id"], "f" * 64) is None
    for query in (
        "SELECT archive_bytes FROM csl.raw_objects",
        "SELECT * FROM csl.ws_users",
        "SELECT csl.ws_identity()",
        "SET ROLE csl_ws_owner",
    ):
        with pytest.raises(psycopg.Error), verifier.db.connect() as conn:
            conn.execute(query)
    report = {
        "checker_version": "1.0",
        "checker_digest": (
            "41f0cb578bf05c42"  # pragma: allowlist secret - public checker definition SHA-256
            "e39053fa5b41f1aa"  # pragma: allowlist secret - public checker definition SHA-256
            "02408117286401e6"  # pragma: allowlist secret - public checker definition SHA-256
            "365ddb19fcd71627"  # pragma: allowlist secret - public checker definition SHA-256
        ),
        "source_digest": "a" * 64,
        "checks": {
            key: "pass"
            for key in (
                "integrity",
                "completeness",
                "canonical_records",
                "conflicts",
                "evidence_binding",
                "predicate",
                "case_binding",
            )
        },
        "details": {"scope": "offline_synthetic_only"},
        "result": "verified",
        "scope": "offline_synthetic_only",
        "source_kind": "synthetic",
        "authenticated": False,
    }
    receipt = verifier.finish(request["request_id"], report)
    assert receipt["result"] == "verified"
    assert verifier.finish(request["request_id"], report) == receipt
    assert one(db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 1
    assert users["reviewer"][0].view(users["reviewer"][1], case["case_id"])["state"] == "verified"
    reviewer, token, _ = users["reviewer"]
    view = reviewer.view(token, case["case_id"])
    nonce = secrets.token_urlsafe(32)
    reviewer.issue_csrf(
        token, nonce, "close", case["case_id"], view["workflow_version"], rec["version"]
    )
    closure = reviewer.close(
        token,
        nonce,
        case["case_id"],
        view["workflow_version"],
        rec["recommendation_id"],
        rec["version"],
        rec["recommendation_hash"],
        receipt["review_id"],
        receipt["verification_id"],
        "Synthetic consistency verified; no action performed",
    )
    assert closure["reviewer_id"] == users["reviewer"][2]["user_id"]
    assert current(db)[0]["payload"]["unreviewed"] is True
    # A duplicate-only new batch has the same generation, but a changed full manifest.
    add(db, [0, 20, 40], "redelivery")
    invalidated = reviewer.view(token, case["case_id"])
    assert invalidated["state"] == "reopen_required"
    assert invalidated["current_recommendation"]["effective"] is False
    nonce = secrets.token_urlsafe(32)
    reviewer.issue_csrf(token, nonce, "reopen", case["case_id"], invalidated["workflow_version"])
    opened = reviewer.reopen(
        token,
        nonce,
        case["case_id"],
        invalidated["workflow_version"],
        "Review new duplicate delivery provenance",
    )
    assert opened["state"] == "open" and opened["epoch"] == 2
    assert one(db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1


def test_populated_v2_upgrade_preserves_every_legacy_row_and_uuid(db_factory, monkeypatch):
    import cloudsecops_live.database as module
    from cloudsecops_live.workspace_roles import setup_roles
    from tests.integration.test_backup import snapshot

    migrations = module._MIGRATIONS
    monkeypatch.setattr(module, "_MIGRATIONS", migrations[:2])
    db = db_factory(migrate=False)
    setup_roles(db)
    db.migrate()
    add(db, [0, 20, 40])
    work_once(db)
    before = snapshot(db)
    uuid = one(db, "SELECT database_id FROM csl.schema_migrations WHERE version=2")["database_id"]
    monkeypatch.setattr(module, "_MIGRATIONS", migrations)
    db.migrate()
    after = snapshot(db)
    for table, value in before.items():
        if table != "schema_migrations":
            assert after[table] == value
    assert (
        one(db, "SELECT database_id FROM csl.schema_migrations WHERE version=2")["database_id"]
        == uuid
    )
    assert one(db, "SELECT count(*) AS n FROM csl.schema_migrations")["n"] == 3


def test_failed_third_migration_keeps_v2_catalog_and_receipts(db_factory, monkeypatch, tmp_path):
    import cloudsecops_live.database as module
    from cloudsecops_live.workspace_roles import setup_roles

    migrations = module._MIGRATIONS
    db = db_factory(migrate=False)
    setup_roles(db)
    db.migrate(target_version=2)
    with db.connect() as conn:
        original = conn.execute("SELECT * FROM csl.schema_migrations ORDER BY version").fetchall()
        catalog = module._receipt_hash(conn, 2)
    broken = tmp_path / "003_broken.sql"
    broken.write_text(migrations[2].read_text() + "\nSELECT no_such_workflow_function();")
    monkeypatch.setattr(module, "_MIGRATIONS", (*migrations[:2], broken))
    with pytest.raises(psycopg.Error):
        db.migrate()
    with db.connect() as conn:
        assert (
            conn.execute("SELECT * FROM csl.schema_migrations ORDER BY version").fetchall()
            == original
        )
        assert module._receipt_hash(conn, 2) == catalog
        assert (
            conn.execute("SELECT to_regclass('csl.ws_workflows') AS present").fetchone()["present"]
            is None
        )
