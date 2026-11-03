"""Synchronous parameterized entry points for the SQL workspace boundary.

Connections use per-account restricted identities; bearer hashes never cross this API.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg import sql

from cloudsecops_live.database import Database, _security_hash, _validate_prefix
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import validate_identity

_ERRORS = {"WS_INVALID", "WS_DENIED", "WS_STALE", "WS_LIMIT"}


def _call(db: Database, function: str, args: tuple[object, ...] = ()) -> Any:
    try:
        with db.connect() as conn, conn.transaction():
            statement = sql.SQL("SELECT csl.{}({}) AS value").format(
                sql.Identifier(function), sql.SQL(",").join(sql.Placeholder() for _ in args)
            )
            row = conn.execute(statement, args).fetchone()
            value = row["value"] if row else None
            if isinstance(value, dict):
                value.pop("identity_kind", None)
            return value
    except psycopg.Error as exc:
        code = exc.diag.message_primary
        raise EvidenceError(code if code in _ERRORS else "WS_DATABASE") from None


def _validate(db: Database, identity: str) -> dict[str, Any] | None:
    try:
        with db.connect() as conn, conn.transaction():
            row = conn.execute("SELECT csl.ws_schema_receipt() AS value").fetchone()
            receipt = row["value"] if row and row["value"] else []
            _validate_prefix(receipt)
            if len(receipt) != 2 or receipt[-1]["schema_hash"] != _security_hash(conn):
                raise EvidenceError("WS_SCHEMA")
            validate_identity(conn, identity)
            if identity == "gate":
                return None
            row = conn.execute("SELECT csl.ws_identity() AS value").fetchone()
            if not row or not row["value"]:
                return None
            value = dict(row["value"])
            value.pop("identity_kind", None)
            return value
    except psycopg.Error:
        raise EvidenceError("WS_SCHEMA") from None


class GateStore:
    """Pre-login nonce and rate-limit functions, with no account or evidence authority."""

    def __init__(self, gate_db: Database) -> None:
        self.db = gate_db
        self.validate()

    def validate(self) -> None:
        _validate(self.db, "gate")

    def challenge(self, nonce: str, csrf: str) -> None:
        _call(self.db, "ws_challenge", (nonce, csrf))

    def consume(self, nonce: str, csrf: str) -> bool:
        return bool(_call(self.db, "ws_consume", (nonce, csrf)))

    def throttle(self, username: str) -> bool:
        return bool(_call(self.db, "ws_throttle", (username,)))


class WorkspaceStore:
    """One mapped account's independent authentication and assigned-case identities."""

    def __init__(self, auth_db: Database, data_db: Database) -> None:
        self.auth_db, self.data_db = auth_db, data_db
        self.validate()

    def validate(self) -> None:
        auth = _validate(self.auth_db, "auth")
        data = _validate(self.data_db, "data")
        if not auth or auth != data:
            raise EvidenceError("WS_DENIED")

    def identity(self) -> dict[str, Any]:
        result = _call(self.auth_db, "ws_identity")
        if not result:
            raise EvidenceError("WS_DENIED")
        return dict(result)

    def password_hash(self) -> str:
        result = _call(self.auth_db, "ws_password_hash")
        if not isinstance(result, str):
            raise EvidenceError("WS_DENIED")
        return result

    def create_session(self, rawtoken: str) -> dict[str, Any]:
        return dict(_call(self.auth_db, "ws_create_session", (rawtoken,)))

    def session(self, rawtoken: str) -> dict[str, Any] | None:
        value = _call(self.data_db, "ws_session", (rawtoken,))
        return dict(value) if value else None

    def issue_csrf(
        self,
        rawtoken: str,
        nonce: str,
        action: str,
        case_id: str | None = None,
        revision: int | None = None,
    ) -> None:
        _call(self.auth_db, "ws_issue_csrf", (rawtoken, nonce, action, case_id, revision))

    def revoke(self, rawtoken: str, nonce: str) -> None:
        _call(self.auth_db, "ws_revoke", (rawtoken, nonce))

    def rotate(self, rawtoken: str, nonce: str, newtoken: str) -> dict[str, Any]:
        return dict(_call(self.auth_db, "ws_rotate", (rawtoken, nonce, newtoken)))

    def list_cases(self, rawtoken: str, offset: int = 0, limit: int = 20) -> list[dict[str, Any]]:
        if (
            type(offset) is not int
            or type(limit) is not int
            or not (0 <= offset <= 10000 and 1 <= limit <= 50)
        ):
            raise EvidenceError("WS_INVALID")
        return list(_call(self.data_db, "ws_list_cases", (rawtoken, offset, limit)))

    def case(
        self, rawtoken: str, case_id: str, revision: int | None = None
    ) -> dict[str, Any] | None:
        value = _call(self.data_db, "ws_case", (rawtoken, case_id, revision))
        return dict(value) if value else None

    def evidence(
        self, rawtoken: str, case_id: str, revision: int, event_key: str, record_hash: str
    ) -> dict[str, Any] | None:
        value = _call(
            self.data_db, "ws_evidence", (rawtoken, case_id, revision, event_key, record_hash)
        )
        return dict(value) if value else None

    def add_note(
        self, rawtoken: str, nonce: str, case_id: str, revision: int, fingerprint: str, body: str
    ) -> dict[str, Any]:
        return dict(
            _call(
                self.data_db, "ws_add_note", (rawtoken, nonce, case_id, revision, fingerprint, body)
            )
        )
