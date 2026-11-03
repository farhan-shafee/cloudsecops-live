"""Start/status/stop one isolated local lab; never delete databases or volumes.

The generated password is confined to ignored private files and a Compose secret.
No existing Docker credential configuration is read. Output never contains a DSN.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "cloudsecops-live-phase1a2"
IMAGE = (
    "postgres:17.11-alpine3.24@sha256:"
    "266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b"  # pragma: allowlist secret  # noqa: E501 - public official image digest
)
MIN_FREE_BYTES = 2 * 1024**3


class LocalPostgresError(Exception):
    """A fixed, non-sensitive failure reason suitable for CLI output."""


def require_local_docker(environment: Mapping[str, str] | None = None) -> None:
    """Reject daemon/context/auth overrides before any local Docker operation."""
    local_hosts = {"", "unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"}
    forbidden = {"DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_AUTH_CONFIG"}
    for key, value in (os.environ if environment is None else environment).items():
        name = key.upper()
        if (name == "DOCKER_HOST" and value not in local_hosts) or (name in forbidden and value):
            raise LocalPostgresError("unsafe_docker_environment")


def _safe_path(root: Path, relative: str) -> Path:
    path = root
    if not root.is_dir() or root.is_symlink():
        raise LocalPostgresError("unsafe_private_path")
    parts = Path(relative).parts
    for index, part in enumerate(parts):
        path /= part
        if path.is_symlink():
            raise LocalPostgresError("unsafe_private_path")
        if path.exists() and index < len(parts) - 1 and not path.is_dir():
            raise LocalPostgresError("unsafe_private_path")
    return path


def _restrict_directory(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o700)
        return
    # chmod(0600) does not remove inherited Windows ACL access.
    result = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    sid = next(csv.reader(io.StringIO(result.stdout)))[1]
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise LocalPostgresError("private_acl_failed")
    subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
        capture_output=True,
        check=True,
        timeout=10,
    )


def _write_private(path: Path, value: str) -> None:
    # O_EXCL protects against a racing launch or unexpected pre-existing file.
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(value.encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def _config(password: str) -> dict[str, str | int]:
    return {
        "schema": 1,
        "project": PROJECT,
        "dsn": (
            f"postgresql://cloudsecops_local:{password}@127.0.0.1:55432/cloudsecops_lab"
            f"?connect_timeout=5&application_name={PROJECT}"
        ),
    }


def prepare_secrets(root: Path) -> Path:
    """Create a private pair once; refuse incomplete/tampered state without rotating."""
    private = _safe_path(root, ".tools/private")
    if private.exists() and not private.is_dir():
        raise LocalPostgresError("unsafe_private_path")
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    _restrict_directory(private)
    password_path = _safe_path(root, ".tools/private/postgres-password")
    config_path = _safe_path(root, ".tools/private/local-postgres.json")
    if password_path.exists() != config_path.exists():
        raise LocalPostgresError("secret_state_incomplete")
    if password_path.exists():
        if not password_path.is_file() or not config_path.is_file():
            raise LocalPostgresError("secret_state_invalid")
        if password_path.stat().st_size > 128 or config_path.stat().st_size > 1024:
            raise LocalPostgresError("secret_state_invalid")
        try:
            password = password_path.read_text(encoding="utf-8").strip()
            existing = json.loads(config_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise LocalPostgresError("secret_state_invalid") from exc
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", password) or existing != _config(password):
            raise LocalPostgresError("secret_state_invalid")
        if os.name != "nt":
            password_path.chmod(0o600)
            config_path.chmod(0o600)
        return config_path
    password = secrets.token_urlsafe(32)
    _write_private(password_path, password + "\n")
    _write_private(config_path, json.dumps(_config(password), sort_keys=True) + "\n")
    return config_path


def require_project_labels(labels: dict[str, str]) -> None:
    if labels.get("com.docker.compose.project") != PROJECT:
        raise LocalPostgresError("resource_name_collision")


def require_free_space(root: Path, *, free_bytes: int | None = None) -> None:
    if (shutil.disk_usage(root).free if free_bytes is None else free_bytes) < MIN_FREE_BYTES:
        raise LocalPostgresError("insufficient_free_space")


class Docker:
    def __init__(self, root: Path) -> None:
        require_local_docker()
        self.root = root
        config = _safe_path(root, ".tools/docker-client")
        if config.exists() and not config.is_dir():
            raise LocalPostgresError("unsafe_private_path")
        if (config / "config.json").exists():
            raise LocalPostgresError("docker_config_not_empty")
        config.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.prefix = ["docker", "--config", str(config)]

    def run(self, arguments: list[str], *, missing_ok: bool = False) -> str | None:
        environment = dict(os.environ)
        require_local_docker(environment)
        result = subprocess.run(
            [*self.prefix, *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
            timeout=180,
            check=False,
        )
        if result.returncode:
            if missing_ok and any(
                reason in result.stderr.lower()
                for reason in ("no such container", "no such volume", "not found")
            ):
                return None
            raise LocalPostgresError("docker_operation_failed")
        return result.stdout

    def compose(self, arguments: list[str]) -> str | None:
        return self.run(
            ["compose", "--project-name", PROJECT, "--file", "compose.phase1a2.yml", *arguments]
        )

    def verify_scope(self) -> bool:
        """Reject collisions without reading container environment or other projects."""
        found = False
        for kind, name, template in (
            ("container", f"{PROJECT}-postgres-1", "{{json .Config.Labels}}"),
            ("volume", f"{PROJECT}-evidence", "{{json .Labels}}"),
            ("network", f"{PROJECT}-loopback", "{{json .Labels}}"),
        ):
            raw = self.run([kind, "inspect", name, "--format", template], missing_ok=True)
            if raw is not None:
                labels = json.loads(raw)
                if not isinstance(labels, dict):
                    raise LocalPostgresError("resource_name_collision")
                require_project_labels(labels)
                found = True
        return found


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("action", choices=["start", "status", "stop"])
    return result


def main(argv: list[str] | None = None) -> int:
    options = parser().parse_args(argv)
    try:
        docker = Docker(ROOT)
        info = json.loads(
            docker.run(["info", "--format", '{"OSType":"{{.OSType}}","MemTotal":{{.MemTotal}}}'])
            or "{}"
        )
        if info.get("OSType") != "linux" or info.get("MemTotal", 0) < 1024**3:
            raise LocalPostgresError("docker_capacity_unavailable")
        existing = docker.verify_scope()
        if options.action == "start":
            require_free_space(ROOT)
            secret_path = _safe_path(ROOT, ".tools/private/postgres-password")
            if existing and not secret_path.is_file():
                raise LocalPostgresError("existing_resources_without_secret")
            config_path = prepare_secrets(ROOT)
            docker.compose(["up", "--detach", "--wait", "--wait-timeout", "90", "postgres"])
            # Check the executable in the pinned image, beyond a pg_isready health probe.
            version = docker.compose(["exec", "--no-TTY", "postgres", "postgres", "--version"])
            if version is None or "PostgreSQL) 17.11" not in version:
                raise LocalPostgresError("postgres_version_mismatch")
            print(
                json.dumps({"state": "ready", "config_path": str(config_path), "project": PROJECT})
            )
        elif options.action == "stop":
            docker.compose(["stop", "--timeout", "30", "postgres"])
            print(json.dumps({"state": "stopped", "data_retained": True, "project": PROJECT}))
        else:
            rows: list[dict[str, Any]] = []
            raw = docker.compose(["ps", "--all", "--format", "json"]) or ""
            for line in raw.splitlines():
                item = json.loads(line)
                if isinstance(item, list):
                    rows.extend(item)
                else:
                    rows.append(item)
            print(
                json.dumps(
                    {
                        "project": PROJECT,
                        "services": [
                            {key: row.get(key) for key in ("Service", "State", "Health")}
                            for row in rows
                        ],
                    },
                    sort_keys=True,
                )
            )
        return 0
    except (LocalPostgresError, OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, LocalPostgresError) else "local_operation_failed"
        print(json.dumps({"error": reason, "project": PROJECT}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
