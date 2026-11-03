"""Named SQL workflow operations through restricted human and verifier identities."""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from cloudsecops_live.database import (
    LATEST_SCHEMA_VERSION,
    Database,
    _receipt_hash,
    _validate_prefix,
)
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import validate_verifier_identity
from cloudsecops_live.workspace_store import WorkspaceStore, _call


class WorkflowStore:
    """A mapped account, with every permission and binding rechecked by PostgreSQL."""

    def __init__(self, auth_db: Database, data_db: Database) -> None:
        WorkspaceStore(auth_db, data_db)
        self.auth_db, self.data_db = auth_db, data_db

    def view(self, token: str, case_id: str) -> dict[str, Any] | None:
        result = _call(self.data_db, "wf_view", (token, case_id))
        return dict(result) if result else None

    def recommendation(self, token: str, case_id: str, version: int) -> dict[str, Any] | None:
        result = _call(self.data_db, "wf_recommendation", (token, case_id, version))
        return dict(result) if result else None

    def queue(self, token: str, offset: int = 0, limit: int = 20) -> list[dict[str, Any]]:
        return list(_call(self.data_db, "wf_queue", (token, offset, limit)))

    def issue_csrf(
        self,
        token: str,
        nonce: str,
        action: str,
        case_id: str,
        workflow_version: int,
        rec_version: int | None = None,
    ) -> None:
        _call(
            self.auth_db,
            "wf_issue_csrf",
            (token, nonce, action, case_id, workflow_version, rec_version),
        )

    def recommend(
        self,
        token: str,
        nonce: str,
        case_id: str,
        case_revision: int,
        case_fingerprint: str,
        workflow_version: int,
        rationale: str,
        counterevidence: str,
        visibility_gaps: str,
    ) -> dict[str, Any]:
        return dict(
            _call(
                self.data_db,
                "wf_recommend",
                (
                    token,
                    nonce,
                    case_id,
                    case_revision,
                    case_fingerprint,
                    workflow_version,
                    rationale,
                    counterevidence,
                    visibility_gaps,
                ),
            )
        )

    def review(
        self,
        token: str,
        nonce: str,
        case_id: str,
        workflow_version: int,
        recommendation_id: str,
        rec_version: int,
        rec_hash: str,
        decision: str,
        reason: str,
    ) -> dict[str, Any]:
        return dict(
            _call(
                self.data_db,
                "wf_review",
                (
                    token,
                    nonce,
                    case_id,
                    workflow_version,
                    recommendation_id,
                    rec_version,
                    rec_hash,
                    decision,
                    reason,
                ),
            )
        )

    def close(
        self,
        token: str,
        nonce: str,
        case_id: str,
        workflow_version: int,
        recommendation_id: str,
        rec_version: int,
        rec_hash: str,
        review_id: str,
        verification_id: str,
        reason: str,
    ) -> dict[str, Any]:
        return dict(
            _call(
                self.data_db,
                "wf_close",
                (
                    token,
                    nonce,
                    case_id,
                    workflow_version,
                    recommendation_id,
                    rec_version,
                    rec_hash,
                    review_id,
                    verification_id,
                    reason,
                ),
            )
        )

    def reopen(
        self, token: str, nonce: str, case_id: str, workflow_version: int, reason: str
    ) -> dict[str, Any]:
        return dict(
            _call(self.data_db, "wf_reopen", (token, nonce, case_id, workflow_version, reason))
        )


class VerifierStore:
    """A dedicated case-scoped service; never an account or maintenance connection."""

    def __init__(self, db: Database) -> None:
        self.db = db
        try:
            with db.connect() as conn:
                row = conn.execute("SELECT csl.ws_schema_receipt() AS value").fetchone()
                receipt = row["value"] if row else []
                _validate_prefix(receipt)
                if len(receipt) != LATEST_SCHEMA_VERSION or receipt[-1][
                    "schema_hash"
                ] != _receipt_hash(conn, len(receipt)):
                    raise EvidenceError("WS_SCHEMA")
                validate_verifier_identity(conn)
        except psycopg.Error:
            raise EvidenceError("WS_SCHEMA") from None

    def identity(self) -> dict[str, Any]:
        value = _call(self.db, "vf_identity")
        if not value:
            raise EvidenceError("WS_DENIED")
        return dict(value)

    def begin(
        self, recommendation_id: str, version: int, run_id: str | None = None
    ) -> dict[str, Any]:
        return dict(_call(self.db, "vf_begin", (recommendation_id, version, run_id)))

    def original(self, request_id: str, raw_id: str) -> bytes | None:
        result = _call(self.db, "vf_original", (request_id, raw_id))
        return bytes(result) if result is not None else None

    def finish(self, request_id: str, report: dict[str, Any]) -> dict[str, Any]:
        return dict(_call(self.db, "vf_finish", (request_id, Jsonb(report))))
