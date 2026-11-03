"""Workspace boundary rejects unsafe arguments before opening a connection."""

from unittest.mock import MagicMock

import psycopg
import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import provision_user
from cloudsecops_live.workspace_store import WorkspaceStore


def test_provision_rejects_invalid_identity() -> None:
    with pytest.raises(EvidenceError, match="WS_INVALID"):
        provision_user(None, "bad name", "analyst", "hash")  # type: ignore[arg-type]


def test_store_rejects_unbounded_pagination() -> None:
    store = object.__new__(WorkspaceStore)
    with pytest.raises(EvidenceError, match="WS_INVALID"):
        store.list_cases("x", limit=1000)


@pytest.mark.parametrize("offset,limit", [(-1, 20), (10001, 20), (0, 0), (0, True)])
def test_store_pagination_uses_fixed_server_bounds(offset: int, limit: int) -> None:
    store = object.__new__(WorkspaceStore)
    with pytest.raises(EvidenceError, match="WS_INVALID"):
        store.list_cases("private", offset, limit)


def test_driver_failure_is_redacted_and_tokens_are_bound_parameters() -> None:
    from cloudsecops_live.workspace_store import _call

    db, conn = MagicMock(), MagicMock()
    db.connect.return_value.__enter__.return_value = conn
    conn.execute.side_effect = psycopg.OperationalError("private DSN and bearer")
    token = "' OR 1=1 --private"
    with pytest.raises(EvidenceError) as rejected:
        _call(db, "ws_session", (token,))
    assert rejected.value.code == "WS_DATABASE"
    statement, arguments = conn.execute.call_args.args
    assert token not in statement.as_string()
    assert arguments == (token,)
    assert "private" not in str(rejected.value)


def test_no_account_may_pair_another_accounts_data_identity(monkeypatch) -> None:
    import cloudsecops_live.workspace_store as module

    monkeypatch.setattr(module, "_validate", lambda db, kind: {"user_id": kind})
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        WorkspaceStore(MagicMock(), MagicMock())


def test_disabled_auth_identity_never_returns_a_hash(monkeypatch) -> None:
    import cloudsecops_live.workspace_store as module

    monkeypatch.setattr(module, "_call", lambda *args: None)
    store = object.__new__(WorkspaceStore)
    store.auth_db = MagicMock()
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        store.identity()
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        store.password_hash()


@pytest.mark.parametrize(
    "username,role,password_hash",
    [
        ("Alice", "analyst", "x" * 64),
        ("alice", "admin", "x" * 64),
        ("alice", "analyst", "x"),
    ],
)
def test_provision_cannot_accept_role_labels_or_unbounded_names(
    username: str,
    role: str,
    password_hash: str,
) -> None:
    with pytest.raises(EvidenceError, match="WS_INVALID"):
        provision_user(MagicMock(), username, role, password_hash)
