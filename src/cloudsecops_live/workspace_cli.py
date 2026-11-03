"""Explicit offline owner provisioning and loopback-only TLS serving."""

from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import sys
from pathlib import Path
from typing import Never

import psycopg

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_config import (
    MAX_ACCOUNTS,
    load_config,
    origin_port,
    read_runtime_json,
    write_private_json,
)
from cloudsecops_live.workspace_tls import create_tls, private_file


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        # argparse normally echoes unexpected values, possibly a mistyped secret.
        raise ValueError("invalid_workspace_arguments")


def parser() -> argparse.ArgumentParser:
    result = _Parser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in (
        "roles-setup",
        "init",
        "user-add",
        "grant-case",
        "disable-user",
        "restore-security",
    ):
        command = commands.add_parser(name)
        command.add_argument("--maintenance-config", required=True, type=Path)
        if name in {"init", "user-add", "disable-user"}:
            command.add_argument("--config", required=True, type=Path)
        if name == "init":
            command.add_argument("--tls-dir", required=True, type=Path)
            command.add_argument("--port", type=int, default=8443)
        if name in {"user-add", "grant-case", "disable-user"}:
            command.add_argument("--username", required=True)
        if name == "user-add":
            command.add_argument(
                "--role", choices=("analyst", "reviewer", "auditor"), required=True
            )
        if name == "grant-case":
            command.add_argument("--case-id", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--config", required=True, type=Path)
    return result


def _maintenance(path: Path) -> Database:
    value = json.loads(private_file(path, max_bytes=65536))
    if not isinstance(value, dict) or not isinstance(value.get("dsn"), str):
        raise ValueError("invalid_maintenance_config")
    return Database(value["dsn"])


def _serve(path: Path) -> None:
    import uvicorn

    from cloudsecops_live.workspace_web import create_app

    config = load_config(path)
    config.validate()
    uvicorn.run(
        create_app(config),
        host="127.0.0.1",
        port=origin_port(config.origin),
        ssl_certfile=str(config.certificate),
        ssl_keyfile=str(config.key),
        proxy_headers=False,
        forwarded_allow_ips="",
        access_log=False,
        log_level="critical",
        server_header=False,
        limit_concurrency=8,
        timeout_keep_alive=5,
        h11_max_incomplete_event_size=16384,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        options = parser().parse_args(argv)
        if options.command == "serve":
            _serve(options.config)
            return 0
        from cloudsecops_live import workspace_roles as roles

        db = _maintenance(options.maintenance_config)
        if options.command == "roles-setup":
            roles.setup_roles(db)
        elif options.command == "restore-security":
            roles.restore_security(db)
        elif options.command == "init":
            origin = f"https://127.0.0.1:{options.port}"
            origin_port(origin)
            if options.config.exists():
                raise ValueError("workspace_config_exists")
            db.migrate()
            gate_dsn = roles.setup_gate(db)
            certificate, key = create_tls(options.tls_dir.absolute())
            write_private_json(
                options.config,
                {
                    "origin": origin,
                    "gate_dsn": gate_dsn,
                    "certificate": str(certificate),
                    "key": str(key),
                    "accounts": [],
                },
            )
        elif options.command == "user-add":
            from cloudsecops_live.workspace_auth import hash_password

            config = load_config(options.config)
            if config.by_username(options.username) or len(config.accounts) >= MAX_ACCOUNTS:
                raise ValueError("workspace_account_unavailable")
            # Only a protected interactive terminal can supply provisioning secrets.
            # getpass falls back with a warning on non-TTY input; turn that into an error.
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("New password: ")
                confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                raise ValueError("password_confirmation_failed")
            password_hash = hash_password(password)
            password = confirmation = ""
            account = roles.provision_user(db, options.username, options.role, password_hash)
            document = read_runtime_json(options.config)
            document["accounts"].append(account)
            write_private_json(options.config, document, replace=True)
        elif options.command == "grant-case":
            roles.grant_case(db, options.username, options.case_id)
        elif options.command == "disable-user":
            config = load_config(options.config)
            if config.by_username(options.username) is None:
                raise ValueError("workspace_account_unavailable")
            roles.disable_user(db, options.username)
            document = read_runtime_json(options.config)
            document["accounts"] = [
                account
                for account in document["accounts"]
                if account["username"] != options.username
            ]
            write_private_json(options.config, document, replace=True)
        print(json.dumps({"state": "complete", "command": options.command}))
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        EOFError,
        getpass.GetPassWarning,
        subprocess.SubprocessError,
        psycopg.Error,
        EvidenceError,
    ):
        print('{"error":"workspace_operation_failed"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
