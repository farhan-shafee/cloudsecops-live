"""Bounded Argon2id authentication and opaque session selection; no HTTP authority labels."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from threading import BoundedSemaphore
from typing import TYPE_CHECKING

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_store import GateStore, WorkspaceStore

if TYPE_CHECKING:
    from cloudsecops_live.workspace_config import AccountConfig, WorkspaceConfig

_HASHER = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
)
_HASH_CAPACITY = BoundedSemaphore(2)
_USERNAME = re.compile(r"[a-z][a-z0-9_]{0,31}\Z", re.ASCII)
_TOKEN = re.compile(r"([0-9a-f]{32})\.[A-Za-z0-9_-]{43}\Z", re.ASCII)
_DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(32))


def _valid_password(password: str) -> bool:
    return (
        isinstance(password, str)
        and 12 <= len(password) <= 128
        and not password.isspace()
        and "\x00" not in password
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in password)
    )


def hash_password(password: str) -> str:
    if not _valid_password(password):
        raise EvidenceError("WS_PASSWORD_POLICY")
    if not _HASH_CAPACITY.acquire(timeout=1):
        raise EvidenceError("WS_LIMIT")
    try:
        return _HASHER.hash(password)
    finally:
        _HASH_CAPACITY.release()


def verify_password(encoded: str, password: str) -> bool:
    if not _valid_password(password) or len(encoded) > 512:
        return False
    try:
        parameters = extract_parameters(encoded)
        if (
            parameters.type != Type.ID
            or parameters.version != 19
            or parameters.memory_cost != 65536
            or parameters.time_cost != 3
            or parameters.parallelism != 1
            or parameters.hash_len != 32
            or parameters.salt_len != 16
        ):
            return False
    except (InvalidHashError, ValueError):
        return False
    if not _HASH_CAPACITY.acquire(timeout=1):
        return False
    try:
        return _HASHER.verify(encoded, password)
    except (InvalidHashError, VerificationError):
        return False
    finally:
        _HASH_CAPACITY.release()


def new_session_token(user_id: str) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", user_id, re.ASCII) is None:
        raise EvidenceError("WS_CONFIG")
    # The random identifier selects a configured connection; it is never proof of identity.
    return user_id + "." + secrets.token_urlsafe(32)


@dataclass(frozen=True, slots=True)
class Principal:
    account: AccountConfig = field(repr=False)
    token: str = field(repr=False)
    username: str
    role: str
    expires_at: str

    def store(self) -> WorkspaceStore:
        return WorkspaceStore(self.account.auth_db, self.account.data_db)


def authenticate(
    config: WorkspaceConfig, username: str, password: str
) -> tuple[AccountConfig, str] | None:
    normalized = username.lower()
    valid_name = _USERNAME.fullmatch(normalized) is not None
    if not GateStore(config.gate_db).throttle(normalized if valid_name else "invalid"):
        return None
    account = config.by_username(normalized) if valid_name else None
    encoded = _DUMMY_HASH
    if account is not None:
        try:
            encoded = WorkspaceStore(account.auth_db, account.data_db).password_hash()
        except EvidenceError as error:
            if error.code != "WS_DENIED":
                raise
            account = None
    verified = verify_password(encoded, password)
    if account is None or not verified:
        return None
    token = new_session_token(account.user_id)
    WorkspaceStore(account.auth_db, account.data_db).create_session(token)
    return account, token


def resolve_session(config: WorkspaceConfig, token: str | None) -> Principal | None:
    if token is None:
        return None
    match = _TOKEN.fullmatch(token)
    if match is None:
        return None
    account = config.accounts.get(match.group(1))
    if account is None:
        return None
    try:
        identity = WorkspaceStore(account.auth_db, account.data_db).session(token)
    except EvidenceError as error:
        if error.code == "WS_DENIED":
            return None
        raise
    if identity is None:
        return None
    if (
        identity["user_id"] != account.user_id
        or identity["username"] != account.username
        or identity["app_role"] not in {"analyst", "reviewer", "auditor"}
        or identity["enabled"] is not True
    ):
        raise EvidenceError("WS_CONFIG")
    return Principal(account, token, account.username, identity["app_role"], identity["expires_at"])
