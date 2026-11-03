"""Trusted private runtime settings contain restricted identities only."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudsecops_live.database import Database
from cloudsecops_live.workspace_tls import private_file, restrict_private, safe_path, validate_tls

MAX_ACCOUNTS = 100


def origin_port(origin: str) -> int:
    if not isinstance(origin, str) or not re.fullmatch(
        r"https://127\.0\.0\.1:[1-9][0-9]{0,4}", origin
    ):
        raise ValueError("unsafe_workspace_origin")
    port = int(origin.rsplit(":", 1)[1])
    if port > 65535:
        raise ValueError("unsafe_workspace_origin")
    return port


@dataclass(frozen=True)
class AccountConfig:
    user_id: str
    username: str
    auth_db: Database = field(repr=False)
    data_db: Database = field(repr=False)


@dataclass(frozen=True)
class WorkspaceConfig:
    origin: str
    gate_db: Database = field(repr=False)
    accounts: dict[str, AccountConfig] = field(repr=False)
    certificate: Path
    key: Path = field(repr=False)

    def by_username(self, username: str) -> AccountConfig | None:
        return next((item for item in self.accounts.values() if item.username == username), None)

    def validate_settings_without_db(self) -> None:
        origin_port(self.origin)
        validate_tls(self.certificate, self.key)
        if len(self.accounts) > MAX_ACCOUNTS:
            raise ValueError("invalid_workspace_accounts")
        names: set[str] = set()
        for user_id, account in self.accounts.items():
            if (
                user_id != account.user_id
                or not isinstance(user_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", user_id) is None
                or not isinstance(account.username, str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", account.username)
                or account.username in names
            ):
                raise ValueError("invalid_workspace_accounts")
            names.add(account.username)

    def validate(self) -> None:
        self.validate_settings_without_db()
        if not self.accounts:
            raise ValueError("workspace_accounts_required")
        from cloudsecops_live.workspace_store import GateStore, WorkspaceStore

        GateStore(self.gate_db).validate()
        for account in self.accounts.values():
            store = WorkspaceStore(account.auth_db, account.data_db)
            store.validate()
            identity = store.identity()
            if identity["user_id"] != account.user_id or identity["username"] != account.username:
                raise ValueError("workspace_identity_mismatch")


def read_runtime_json(path: Path) -> dict[str, Any]:
    value = json.loads(private_file(path, max_bytes=1024 * 1024))
    if not isinstance(value, dict) or set(value) != {
        "origin",
        "gate_dsn",
        "certificate",
        "key",
        "accounts",
    }:
        raise ValueError("invalid_workspace_config")
    return value


def load_config(path: Path) -> WorkspaceConfig:
    value = read_runtime_json(path)
    if (
        not isinstance(value["accounts"], list)
        or len(value["accounts"]) > MAX_ACCOUNTS
        or any(
            not isinstance(value[key], str) for key in ("origin", "gate_dsn", "certificate", "key")
        )
    ):
        raise ValueError("invalid_workspace_config")
    accounts: dict[str, AccountConfig] = {}
    for item in value["accounts"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"user_id", "username", "auth_dsn", "data_dsn"}
            or any(not isinstance(entry, str) for entry in item.values())
            or item["user_id"] in accounts
        ):
            raise ValueError("invalid_workspace_accounts")
        accounts[item["user_id"]] = AccountConfig(
            item["user_id"],
            item["username"],
            Database(item["auth_dsn"]),
            Database(item["data_dsn"]),
        )
    config = WorkspaceConfig(
        value["origin"],
        Database(value["gate_dsn"]),
        accounts,
        Path(value["certificate"]),
        Path(value["key"]),
    )
    if not config.certificate.is_absolute() or not config.key.is_absolute():
        raise ValueError("invalid_workspace_tls_path")
    config.validate_settings_without_db()
    return config


def write_private_json(path: Path, value: dict[str, Any], *, replace: bool = False) -> None:
    safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    restrict_private(path.parent, directory=True)
    if path.exists():
        private_file(path, max_bytes=1024 * 1024)
        if not replace:
            raise ValueError("workspace_config_exists")
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    try:
        with os.fdopen(
            os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8"
        ) as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        restrict_private(temporary)
        if replace:
            os.replace(temporary, path)
        else:
            # A hard link claims the destination atomically, without overwrite.
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
