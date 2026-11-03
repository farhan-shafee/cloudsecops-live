"""Independent workflow fixtures and literal database observations.

The old four-account workspace fixture stays unchanged. These helpers perform
real restricted operations; expected decisions belong in the acceptance tests.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from tests.integration.support import one, rows
from tests.integration.test_workspace_security import (  # noqa: F401
    PASSWORD,
    Workspace,
    workspace,
    workspace_password_hash,
)

WORKFLOW_TABLES = (
    "ws_recommendations",
    "ws_reviews",
    "ws_verifications",
    "ws_closures",
    "ws_transitions",
)


@dataclass
class Workflow:
    workspace: Workspace
    verifier_account: dict[str, str] = field(repr=False)
    tokens: dict[str, str] = field(default_factory=dict, repr=False)

    @property
    def db(self):
        return self.workspace.db

    @property
    def case(self):
        return self.workspace.cases[0]

    @property
    def cid(self):
        return self.case["case_id"]

    def token(self, username="alice"):
        if username not in self.tokens:
            self.tokens[username] = self.workspace.token(username)
        return self.tokens[username]

    def store(self, username="alice"):
        from cloudsecops_live.workflow_store import WorkflowStore

        account = self.workspace.accounts[username]
        return WorkflowStore(Database(account["auth_dsn"]), Database(account["data_dsn"]))

    def view(self, username="alice"):
        return self.store(username).view(self.token(username), self.cid)

    def prepare(self, action, username="alice", recommendation_version=None):
        store, token = self.store(username), self.token(username)
        version = store.view(token, self.cid)["workflow_version"]
        nonce = secrets.token_urlsafe(32)
        store.issue_csrf(token, nonce, action, self.cid, version, recommendation_version)
        return store, token, nonce, version

    def recommend(self, **overrides):
        store, token, nonce, version = self.prepare("recommend")
        arguments = {
            "rawtoken": token,
            "nonce": nonce,
            "case_id": self.cid,
            "revision": self.case["current_revision"],
            "fingerprint": self.case["fingerprint"],
            "workflow_version": version,
            "rationale": "Authorized synthetic exercise; no action is requested.",
            "counterevidence": "Inventory tools, pagination and retries can cause this burst.",
            "visibility_gaps": "Synthetic supplied records authenticate no AWS activity.",
        }
        arguments.update(overrides)
        # Positional arguments keep this helper independent of Python parameter names.
        return store.recommend(*arguments.values())

    def review(self, recommendation, username="reviewer", decision="approve"):
        store, token, nonce, version = self.prepare("review", username, recommendation["version"])
        return store.review(
            token,
            nonce,
            self.cid,
            version,
            recommendation["recommendation_id"],
            recommendation["version"],
            recommendation["recommendation_hash"],
            decision,
            "Reviewed the exact synthetic evidence and its limitations.",
        )

    def verifier(self):
        from cloudsecops_live.workflow_store import VerifierStore

        return VerifierStore(Database(self.verifier_account["dsn"]))

    def verifier_config(self):
        from cloudsecops_live.verifier_runtime import VerifierConfig

        account = self.verifier_account
        return VerifierConfig(Database(account["dsn"]), account["verifier_id"], self.cid)

    def verify(self, recommendation, run_id=None):
        from cloudsecops_live.verifier_runtime import run_verification

        return run_verification(
            self.verifier_config(),
            recommendation["recommendation_id"],
            recommendation["version"],
            run_id=run_id,
        )

    def close(self, recommendation, review, verification, username="reviewer"):
        store, token, nonce, version = self.prepare("close", username, recommendation["version"])
        return store.close(
            token,
            nonce,
            self.cid,
            version,
            recommendation["recommendation_id"],
            recommendation["version"],
            recommendation["recommendation_hash"],
            review["review_id"],
            verification["verification_id"],
            "Close the no-action synthetic exercise only.",
        )

    def reopen(self, username="reviewer"):
        store, token, nonce, version = self.prepare("reopen", username)
        return store.reopen(token, nonce, self.cid, version, "Review the changed source snapshot.")

    def counts(self):
        counts = {
            table: one(self.db, f"SELECT count(*) AS n FROM csl.{table}")["n"]
            for table in WORKFLOW_TABLES
        }
        counts["workflow_audit"] = one(
            self.db, "SELECT count(*) AS n FROM csl.audit WHERE left(kind,9)=%s", ("workflow_",)
        )["n"]
        return counts

    def runtime_files(self, directory: Path, *, origin=None):
        from cloudsecops_live.workspace_config import write_private_json

        web, verifier = directory / "web.json", directory / "verifier.json"
        config = self.workspace.config
        write_private_json(
            web,
            {
                "origin": origin or config.origin,
                "gate_dsn": make_conninfo(**config.gate_db._values),
                "certificate": str(config.certificate),
                "key": str(config.key),
                "accounts": list(self.workspace.accounts.values()),
            },
        )
        write_private_json(verifier, self.verifier_account)
        return web, verifier


@pytest.fixture
def workflow(workspace, workspace_password_hash):  # noqa: F811
    from cloudsecops_live.independent_verifier import source_digest
    from cloudsecops_live.workspace_config import AccountConfig
    from cloudsecops_live.workspace_roles import grant_case, provision_user, provision_verifier

    for username in ("reviewer_two", "unassigned_reviewer"):
        account = provision_user(workspace.db, username, "reviewer", workspace_password_hash)
        workspace.accounts[username] = account
        workspace.config.accounts[account["user_id"]] = AccountConfig(
            account["user_id"],
            username,
            Database(account["auth_dsn"]),
            Database(account["data_dsn"]),
        )
    cid = workspace.cases[0]["case_id"]
    grant_case(workspace.db, "reviewer_two", cid)
    verifier = provision_verifier(workspace.db, cid, source_digest())
    return Workflow(workspace, verifier)


def machine_snapshot(db):
    """Whole logical machine projection, excluding human/session/audit state."""
    from tests.integration.test_backup import snapshot

    return {
        name: values
        for name, values in snapshot(db).items()
        if not name.startswith("ws_") and name != "audit"
    }


def workflow_audits(db):
    return rows(
        db,
        "SELECT kind,payload FROM csl.audit WHERE left(kind,9)=%s "
        "OR left(kind,13)=%s ORDER BY audit_id",
        ("workflow_", "verification_"),
    )
