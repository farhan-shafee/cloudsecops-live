"""Literal HTTP outcomes and actual restricted PostgreSQL workflow observations."""

from __future__ import annotations

import asyncio
import secrets
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Barrier

import psycopg
import pytest
from psycopg import sql

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.worker import work_once
from tests.integration.support import add, current, one, rows
from tests.integration.test_workspace_security import ORIGIN, SESSION, fields, login
from tests.integration.workflow_support import (  # noqa: F401
    machine_snapshot,
    workflow,
    workspace,
    workspace_password_hash,
)


def test_http_recommend_review_verify_close_preserves_machine_evidence(workflow):  # noqa: F811
    before = machine_snapshot(workflow.db)

    async def scenario():
        cid = workflow.cid
        recommend_target = f"/cases/{cid}/recommendations"
        async with workflow.workspace.client() as analyst:
            assert (await login(analyst)).status_code == 303
            page = await analyst.get(f"/cases/{cid}/workflow")
            form = fields(page, recommend_target)
            assert (await analyst.get("/review-queue")).status_code == 403
            response = await analyst.post(
                recommend_target,
                data={
                    **form,
                    "rationale": "Authorized synthetic exercise <script>test</script>",
                    "counterevidence": "Inventory pagination and SDK retries are plausible.",
                    "visibility_gaps": "No authenticated AWS source or unseen-activity visibility.",
                },
                headers={"Origin": ORIGIN},
            )
            assert response.status_code == 303
            page = await analyst.get(f"/cases/{cid}/workflow")
            assert "<script>test</script>" not in page.text
            assert "&lt;script&gt;test&lt;/script&gt;" in page.text
            assert "NO_ACTION_AUTHORIZED_EXERCISE" in page.text
        rec = one(workflow.db, "SELECT * FROM csl.ws_recommendations")
        assert rec["payload"]["execution_targets"] == []
        assert rec["payload"]["source_kind"] == "synthetic"
        assert rec["payload"]["authenticated"] is False
        assert rec["payload"]["conclusion"] == "authorized_synthetic_exercise"
        review_target = (
            f"/cases/{cid}/recommendations/{rec['recommendation_id']}/{rec['version']}/review"
        )
        async with workflow.workspace.client() as reviewer:
            assert (await login(reviewer, "reviewer")).status_code == 303
            queue = await reviewer.get("/review-queue")
            assert queue.status_code == 200 and cid in queue.text
            form = fields(await reviewer.get(f"/cases/{cid}/workflow"), review_target)
            response = await reviewer.post(
                review_target,
                data={
                    **form,
                    "decision": "approve",
                    "reason": "Exact evidence and limitations reviewed.",
                },
                headers={"Origin": ORIGIN},
            )
            assert response.status_code == 303
            receipt = workflow.verify(rec)
            assert receipt["result"] == "verified"
            close_target = f"/cases/{cid}/close"
            page = await reviewer.get(f"/cases/{cid}/workflow")
            assert "synthetic" in page.text.lower()
            assert "unreviewed" in page.text.lower()
            form = fields(page, close_target)
            response = await reviewer.post(
                close_target,
                data={**form, "reason": "No-action synthetic exercise closure."},
                headers={"Origin": ORIGIN},
            )
            assert response.status_code == 303
            replay = await reviewer.post(
                close_target,
                data={**form, "reason": "Replay must not append another closure."},
                headers={"Origin": ORIGIN},
            )
            assert replay.status_code in (403, 409)
        assert workflow.view()["state"] == "closed"
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
        assert (
            one(workflow.db, "SELECT reviewer_id FROM csl.ws_reviews")["reviewer_id"]
            != rec["author_id"]
        )
        assert (
            one(workflow.db, "SELECT status FROM csl.cases WHERE case_id=%s", (cid,))["status"]
            == "current"
        )

    asyncio.run(scenario())
    assert machine_snapshot(workflow.db) == before


def test_http_role_object_and_forged_authority_denials(workflow):  # noqa: F811
    async def scenario():
        rec = workflow.recommend()
        cid = workflow.cid
        target = f"/cases/{cid}/recommendations/{rec['recommendation_id']}/{rec['version']}/review"
        for name in ("alice", "auditor", "unassigned_reviewer"):
            async with workflow.workspace.client() as client:
                assert (await login(client, name)).status_code == 303
                expected = 404 if name == "unassigned_reviewer" else 403
                if name == "unassigned_reviewer":
                    absent = await client.get(f"/cases/{'f' * 64}/workflow")
                    denied = await client.get(f"/cases/{cid}/workflow")
                    assert absent.status_code == denied.status_code == 404
                    assert absent.text == denied.text
                response = await client.post(
                    target,
                    data={
                        "csrf_token": secrets.token_urlsafe(32),
                        "workflow_version": "1",
                        "recommendation_hash": rec["recommendation_hash"],
                        "decision": "approve",
                        "reason": "Forged review",
                    },
                    headers={"Origin": ORIGIN, "X-Role": "reviewer", "X-User": "reviewer"},
                )
                assert response.status_code == expected
                close = await client.post(
                    f"/cases/{cid}/close",
                    data={
                        "csrf_token": secrets.token_urlsafe(32),
                        "workflow_version": "1",
                        "recommendation_id": rec["recommendation_id"],
                        "recommendation_version": str(rec["version"]),
                        "recommendation_hash": rec["recommendation_hash"],
                        "review_id": "f" * 32,
                        "verification_id": "f" * 32,
                        "reason": "Forged closure",
                    },
                    headers={"Origin": ORIGIN, "X-Role": "reviewer"},
                )
                assert close.status_code == expected
        async with workflow.workspace.client() as analyst:
            assert (await login(analyst)).status_code == 303
            target = f"/cases/{cid}/recommendations"
            form = fields(await analyst.get(f"/cases/{cid}/workflow"), target)
            valid = {
                **form,
                "rationale": "Exercise",
                "counterevidence": "Benign inventory",
                "visibility_gaps": "Only synthetic input",
            }
            for forged in (
                {"action": "DeleteTrail"},
                {"execution_targets": '["arn:aws:fake"]'},
                {"source_kind": "aws"},
                {"authenticated": "true"},
                {"result": "verified"},
                {"author_id": workflow.workspace.accounts["reviewer"]["user_id"]},
                {"command": "ignored-command"},
                {"role": "reviewer"},
            ):
                response = await analyst.post(
                    target, data={**valid, **forged}, headers={"Origin": ORIGIN}
                )
                assert response.status_code == 400
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_recommendations")["n"] == 1
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 0
        assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0

    asyncio.run(scenario())


def test_http_csrf_transport_session_and_stale_binding_denials(workflow):  # noqa: F811
    async def scenario():
        cid = workflow.cid
        target = f"/cases/{cid}/recommendations"
        async with workflow.workspace.client() as client:
            assert (await login(client)).status_code == 303
            form = fields(await client.get(f"/cases/{cid}/workflow"), target)
            valid = {
                **form,
                "rationale": "Synthetic exercise",
                "counterevidence": "Benign tool",
                "visibility_gaps": "Supplied data only",
            }
            for headers in (
                {},
                {"Origin": "null"},
                {"Origin": "https://evil.example"},
                {"Origin": ORIGIN, "Host": "evil.example"},
                {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
            ):
                assert (await client.post(target, data=valid, headers=headers)).status_code == 403
            for changed in ({"csrf_token": "X" * 43}, {"csrf_token": ""}):
                assert (
                    await client.post(target, data={**valid, **changed}, headers={"Origin": ORIGIN})
                ).status_code == 403
            for changed in (
                {"fingerprint": "0" * 64},
                {"case_revision": "999"},
                {"workflow_version": "999"},
            ):
                assert (
                    await client.post(target, data={**valid, **changed}, headers={"Origin": ORIGIN})
                ).status_code == 409
            assert (
                await client.post(target, json=valid, headers={"Origin": ORIGIN})
            ).status_code == 400
            assert (
                await client.post(
                    target, data={**valid, "rationale": "x" * 4001}, headers={"Origin": ORIGIN}
                )
            ).status_code in (400, 413)
            nonce = form["csrf_token"]
            with workflow.db.connect() as conn:
                conn.execute(
                    "UPDATE csl.ws_workflow_csrf "
                    "SET expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE nonce_hash=%s",
                    (sha256(nonce.encode()).hexdigest(),),
                )
            assert (
                await client.post(target, data=valid, headers={"Origin": ORIGIN})
            ).status_code == 403
            fresh = fields(await client.get(f"/cases/{cid}/workflow"), target)
            raw = client.cookies.get(SESSION)
            with workflow.db.connect() as conn:
                conn.execute(
                    "UPDATE csl.ws_sessions SET expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE token_hash=%s",
                    (sha256(raw.encode()).hexdigest(),),
                )
            assert (
                await client.post(target, data={**valid, **fresh}, headers={"Origin": ORIGIN})
            ).status_code == 401
        assert all(n == 0 for n in workflow.counts().values())

    asyncio.run(scenario())


def test_restricted_sql_cannot_insert_receipts_escalate_or_read_verifier_archives(workflow):  # noqa: F811
    identities = [workflow.workspace.config.gate_db, Database(workflow.verifier_account["dsn"])]
    for account in workflow.workspace.accounts.values():
        identities.extend((Database(account["auth_dsn"]), Database(account["data_dsn"])))
    statements = (
        "INSERT INTO csl.ws_verifications DEFAULT VALUES",
        "DELETE FROM csl.ws_reviews",
        "UPDATE csl.ws_recommendations SET payload='{}'::jsonb",
        "DELETE FROM csl.ws_closures",
        "SELECT archive_bytes FROM csl.raw_objects",
        "SELECT * FROM csl.ws_users",
        "UPDATE csl.cases SET status='superseded'",
        "DELETE FROM csl.audit",
        "SET ROLE csl_ws_owner",
        "SET ROLE csl_vf_owner",
        "CREATE TABLE public.workflow_escalation(id integer)",
    )
    for identity in identities:
        for statement in statements:
            with (
                pytest.raises(psycopg.Error, match="permission denied"),
                identity.connect() as conn,
            ):
                conn.execute(statement)
        if identity is not identities[1]:
            with pytest.raises(psycopg.Error), identity.connect() as conn:
                conn.execute("SET ROLE csl_ws_verifier")
    verifier = workflow.verifier()
    assert verifier.identity()["case_id"] == workflow.cid
    rec = workflow.recommend()
    workflow.review(rec)
    request = verifier.begin(rec["recommendation_id"], rec["version"])
    assert verifier.original(request["request_id"], "f" * 64) is None
    assert workflow.verifier_account["dsn"] not in repr(workflow.workspace.config)


def test_rejection_disabled_unassigned_and_other_approver_cannot_close(workflow):  # noqa: F811
    from cloudsecops_live.workspace_roles import disable_user

    rec = workflow.recommend()
    review = workflow.review(rec, decision="reject")
    with pytest.raises(EvidenceError):
        workflow.verify(rec)
    assert workflow.view()["state"] == "rejected"
    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        workflow.close(rec, review, receipt, "reviewer_two")
    store, token, nonce, version = workflow.prepare("close", "reviewer", rec["version"])
    reviewer_id = workflow.workspace.accounts["reviewer"]["user_id"]
    with workflow.db.connect() as conn:
        conn.execute(
            "DELETE FROM csl.ws_case_grants WHERE user_id=%s AND case_id=%s",
            (reviewer_id, workflow.cid),
        )
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        store.close(
            token,
            nonce,
            workflow.cid,
            version,
            rec["recommendation_id"],
            rec["version"],
            rec["recommendation_hash"],
            review["review_id"],
            receipt["verification_id"],
            "Grant was removed after this challenge was issued",
        )
    from cloudsecops_live.workspace_roles import grant_case

    grant_case(workflow.db, "reviewer", workflow.cid)
    disable_user(workflow.db, "reviewer")
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0


def test_self_review_guard_and_disable_after_challenge_recheck_live_authority(workflow):  # noqa: F811
    from cloudsecops_live.workspace_roles import disable_user

    rec = workflow.recommend()
    author_store, author_token = workflow.store(), workflow.token()
    account = workflow.workspace.accounts["alice"]
    data_role = Database(account["data_dsn"])._values["user"]
    # A privileged role change cannot turn the original analyst's recommendation
    # into current self-review authority. Its author binding must become stale.
    with workflow.db.connect() as conn:
        conn.execute(
            "UPDATE csl.ws_users SET app_role='reviewer' WHERE user_id=%s", (account["user_id"],)
        )
        conn.execute(
            sql.SQL("GRANT csl_ws_reviews TO {} WITH ADMIN FALSE").format(sql.Identifier(data_role))
        )
    try:
        nonce = secrets.token_urlsafe(32)
        version = author_store.view(author_token, workflow.cid)["workflow_version"]
        author_store.issue_csrf(
            author_token, nonce, "review", workflow.cid, version, rec["version"]
        )
        with pytest.raises(EvidenceError, match="WS_STALE"):
            author_store.review(
                author_token,
                nonce,
                workflow.cid,
                version,
                rec["recommendation_id"],
                rec["version"],
                rec["recommendation_hash"],
                "approve",
                "Self review must fail",
            )
    finally:
        with workflow.db.connect() as conn:
            conn.execute(sql.SQL("REVOKE csl_ws_reviews FROM {}").format(sql.Identifier(data_role)))
            conn.execute(
                "UPDATE csl.ws_users SET app_role='analyst' WHERE user_id=%s", (account["user_id"],)
            )
    store, token, nonce, version = workflow.prepare("review", "reviewer_two", rec["version"])
    disable_user(workflow.db, "reviewer_two")
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        store.review(
            token,
            nonce,
            workflow.cid,
            version,
            rec["recommendation_id"],
            rec["version"],
            rec["recommendation_hash"],
            "approve",
            "Disabled after challenge",
        )
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 0


def test_batch_duplicate_provenance_and_late_bridge_invalidate_authority(workflow):  # noqa: F811
    from cloudsecops_live.storage import ingest
    from tests.helpers import archive, event

    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    workflow.close(rec, review, receipt)
    current_case = workflow.case
    base = 0 if "e0" in current_case["payload"]["evidence_event_ids"] else 100
    add(workflow.db, [base, base + 20, base + 40], "additional-duplicate-delivery")
    assert workflow.view()["state"] == "reopen_required"
    assert workflow.view()["current_recommendation"]["effective"] is False
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    workflow.reopen()
    assert workflow.view()["state"] == "open"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1
    work_once(workflow.db)
    # The byte-identical checkpoint replay creates no batch and therefore no invalidation.
    rec = workflow.recommend()
    batches_before = one(workflow.db, "SELECT count(*) AS n FROM csl.batches")["n"]
    ingest(
        workflow.db,
        [
            (
                "synthetic/additional-duplicate-delivery.json.gz",
                archive([event(f"e{t}", t) for t in [base, base + 20, base + 40]]),
            )
        ],
        checkpoint="additional-duplicate-delivery",
    )
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.batches")["n"] == batches_before
    assert workflow.view()["current_recommendation"]["effective"] is True
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    workflow.close(rec, review, receipt)
    add(workflow.db, [70], "late-bridge")
    assert workflow.view()["state"] == "reopen_required"
    work_once(workflow.db)
    merged = current(workflow.db)[0]["case_id"]
    assert merged not in [case["case_id"] for case in workflow.workspace.cases]
    assert workflow.store().view(workflow.token(), merged) is None
    with pytest.raises(EvidenceError):
        workflow.reopen()
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 2
    assert rows(workflow.db, "SELECT * FROM csl.case_lineage WHERE child_case_id=%s", (merged,))


def test_pending_worker_stale_review_and_verifier_finish_fail_closed(workflow):  # noqa: F811
    from cloudsecops_live.independent_verifier import verify_snapshot

    rec = workflow.recommend()
    workflow.review(rec)
    verifier = workflow.verifier()
    request = verifier.begin(rec["recommendation_id"], rec["version"])
    report = verify_snapshot(
        request, lambda raw_id: verifier.original(request["request_id"], raw_id)
    )
    assert report["result"] == "verified"
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    add(workflow.db, [base + 10], "pending-snapshot")
    with pytest.raises(EvidenceError):
        workflow.verify(rec)
    with pytest.raises(EvidenceError):
        verifier.begin(rec["recommendation_id"], rec["version"])
    with pytest.raises(EvidenceError, match="WS_STALE"):
        verifier.finish(request["request_id"], report)
    assert request["request_id"]
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 0
    work_once(workflow.db)
    with pytest.raises(EvidenceError):
        workflow.review(rec, "reviewer_two")
    assert workflow.view()["current_recommendation"]["effective"] is False


def test_actual_concurrent_review_decisions_and_shared_nonce_commit_once(workflow):  # noqa: F811
    rec = workflow.recommend()
    prepared = [
        workflow.prepare("review", name, rec["version"]) for name in ("reviewer", "reviewer_two")
    ]
    barrier = Barrier(2)

    def decide(item):
        store, token, nonce, version = item
        barrier.wait(timeout=10)
        try:
            store.review(
                token,
                nonce,
                workflow.cid,
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
        assert sorted(pool.map(decide, prepared)) == ["WS_STALE", "committed"]
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 1
    rec = workflow.recommend()
    same = workflow.prepare("review", "reviewer", rec["version"])
    barrier = Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(decide, [same, same]))
    assert result.count("committed") == 1
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_reviews")["n"] == 2
    review = one(workflow.db, "SELECT * FROM csl.ws_reviews WHERE version=%s", (rec["version"],))
    receipt = workflow.verify(rec)
    closing = workflow.prepare("close", "reviewer", rec["version"])
    barrier = Barrier(2)

    def close_once(_):
        store, token, nonce, version = closing
        barrier.wait(timeout=10)
        try:
            store.close(
                token,
                nonce,
                workflow.cid,
                version,
                rec["recommendation_id"],
                rec["version"],
                rec["recommendation_hash"],
                review["review_id"],
                receipt["verification_id"],
                "Close once",
            )
            return "committed"
        except EvidenceError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(close_once, range(2))).count("committed") == 1
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 1


def test_review_and_close_forms_bind_nonce_exact_recommendation_and_receipt(workflow):  # noqa: F811
    async def scenario():
        rec = workflow.recommend()
        cid = workflow.cid
        target = f"/cases/{cid}/recommendations/{rec['recommendation_id']}/{rec['version']}/review"
        async with workflow.workspace.client() as client:
            assert (await login(client, "reviewer")).status_code == 303
            form = fields(await client.get(f"/cases/{cid}/workflow"), target)
            valid = {**form, "decision": "approve", "reason": "Evidence reviewed"}
            for changed, expected in (
                ({"recommendation_hash": "0" * 64}, 409),
                ({"workflow_version": "999"}, 409),
                ({"csrf_token": "X" * 43}, 403),
                ({"result": "verified"}, 400),
                ({"reviewer_id": "f" * 32}, 400),
            ):
                response = await client.post(
                    target, data={**valid, **changed}, headers={"Origin": ORIGIN}
                )
                assert response.status_code == expected
            raw = client.cookies.get(SESSION)
            other_action = secrets.token_urlsafe(32)
            workflow.store("reviewer").issue_csrf(
                raw, other_action, "close", cid, int(form["workflow_version"]), rec["version"]
            )
            assert (
                await client.post(
                    target, data={**valid, "csrf_token": other_action}, headers={"Origin": ORIGIN}
                )
            ).status_code == 403
            assert (
                await client.post(target, data=valid, headers={"Origin": ORIGIN})
            ).status_code == 303
            assert (
                await client.post(target, data=valid, headers={"Origin": ORIGIN})
            ).status_code in (403, 409)
            workflow.verify(rec)
            close_target = f"/cases/{cid}/close"
            form = fields(await client.get(f"/cases/{cid}/workflow"), close_target)
            valid = {**form, "reason": "No-action synthetic closure"}
            for changed in (
                {"review_id": "f" * 32},
                {"verification_id": "f" * 32},
                {"recommendation_hash": "0" * 64},
                {"recommendation_version": "2"},
                {"workflow_version": "999"},
            ):
                response = await client.post(
                    close_target, data={**valid, **changed}, headers={"Origin": ORIGIN}
                )
                assert response.status_code == 409
            assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0
            assert (
                await client.post(close_target, data=valid, headers={"Origin": ORIGIN})
            ).status_code == 303

    asyncio.run(scenario())


def test_conflicting_source_and_differently_scoped_verifier_cannot_authorize_closure(workflow):  # noqa: F811
    from cloudsecops_live.independent_verifier import source_digest
    from cloudsecops_live.storage import ingest
    from cloudsecops_live.workflow_store import VerifierStore
    from cloudsecops_live.workspace_roles import provision_verifier
    from tests.helpers import archive, event

    rec = workflow.recommend()
    review = workflow.review(rec)
    receipt = workflow.verify(rec)
    other = workflow.workspace.cases[1]["case_id"]
    account = provision_verifier(workflow.db, other, source_digest())
    with pytest.raises(EvidenceError):
        VerifierStore(Database(account["dsn"])).begin(rec["recommendation_id"], rec["version"])
    base = 0 if "e0" in workflow.case["payload"]["evidence_event_ids"] else 100
    conflicting = event(f"e{base}", base)
    conflicting["requestParameters"] = {"untrustedExtra": "conflicting full record"}
    ingest(
        workflow.db,
        [("synthetic/conflicting-original.gz", archive([conflicting]))],
        checkpoint="conflicting-original",
    )
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.conflicts")["n"] == 1
    with pytest.raises(EvidenceError):
        workflow.close(rec, review, receipt)
    with pytest.raises(EvidenceError):
        workflow.verify(rec)
    work_once(workflow.db)
    assert workflow.view()["state"] != "closed"
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_closures")["n"] == 0


def test_http_genuine_database_outage_is_sanitized_and_leaves_no_mutation(workflow):  # noqa: F811
    async def scenario():
        target = f"/cases/{workflow.cid}/recommendations"
        async with workflow.workspace.client() as client:
            assert (await login(client)).status_code == 303
            form = fields(await client.get(f"/cases/{workflow.cid}/workflow"), target)
            role = Database(workflow.workspace.accounts["alice"]["data_dsn"])._values["user"]
            with workflow.db.connect() as conn:
                conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(role)))
            try:
                response = await client.post(
                    target,
                    data={
                        **form,
                        "rationale": "Exercise",
                        "counterevidence": "Benign",
                        "visibility_gaps": "Synthetic",
                    },
                    headers={"Origin": ORIGIN},
                )
                assert response.status_code == 503
                assert role not in response.text and "postgres" not in response.text.lower()
                assert all(n == 0 for n in workflow.counts().values())
            finally:
                with workflow.db.connect() as conn:
                    conn.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(role)))

    asyncio.run(scenario())
