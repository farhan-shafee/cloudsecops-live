"""Genuine PostgreSQL binary dump/restore into a second retained empty database."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any

import pytest
from psycopg import sql

from cloudsecops_live.outbox import deliver_once
from cloudsecops_live.storage import verify_store
from cloudsecops_live.worker import work_once
from scripts.local_postgres import Docker, require_local_docker
from tests.integration.conftest import ROOT
from tests.integration.support import add, current


def pg_environment(db) -> dict[str, str]:
    """Do not let host libpq environment redirect backup tools or load private files."""
    return {
        **{key: value for key, value in os.environ.items() if not key.upper().startswith("PG")},
        "PGPASSWORD": db._values.get("password", ""),
        "PGPASSFILE": os.devnull,
        "PGHOSTADDR": db._values["host"],
        "PGSSLMODE": "disable",
        "PGGSSENCMODE": "disable",
        "PGCONNECT_TIMEOUT": "5",
        "PGOPTIONS": "-c search_path=pg_catalog",
    }


def pg_command(db, program: str, arguments: list[str], data: bytes | None = None) -> bytes:
    values = db._values
    env = pg_environment(db)
    common = ["--username", values["user"], "--dbname", values["dbname"]]
    executable = shutil.which(program)
    container = os.environ.get("CSL_POSTGRES_CONTAINER")
    if container:
        require_local_docker(env)
        if not re.fullmatch(r"[a-f0-9]{12,64}", container):
            pytest.fail("CI PostgreSQL container must be an explicit Docker container id")
        command = [
            *Docker(ROOT).prefix,
            "exec",
            "--interactive",
            "--env",
            "PGPASSWORD",
            container,
            program,
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
        ]
    elif executable:
        command = [executable, "--host", values["host"], "--port", values.get("port", "5432")]
    else:
        require_local_docker(env)
        docker = shutil.which("docker")
        if not docker:
            pytest.fail(
                "Required backup test needs pg_dump/pg_restore or the project Docker service"
            )
        command = [
            *Docker(ROOT).prefix,
            "compose",
            "--project-name",
            "cloudsecops-live-phase1a2",
            "--file",
            str(ROOT / "compose.phase1a2.yml"),
            "exec",
            "--no-TTY",
            "--env",
            "PGPASSWORD",
            "postgres",
            program,
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
        ]
    result = subprocess.run(
        [*command, *common, *arguments],
        input=data,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, "Required PostgreSQL backup/restore command failed"
    return result.stdout


def snapshot(db) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    with db.connect() as conn:
        names = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='csl' ORDER BY tablename"
        ).fetchall()
        for row in names:
            name = row["tablename"]
            records: list[dict[str, Any]] = conn.execute(
                sql.SQL("SELECT row_to_json(t) AS value FROM csl.{} t").format(sql.Identifier(name))
            ).fetchall()
            result[name] = sorted(json.dumps(record["value"], sort_keys=True) for record in records)
    return result


def test_real_pg_dump_restore_validates_every_table_and_original_byte(db, db_factory):
    add(db, [0, 20, 40])
    work_once(db)
    deliver_once(db)
    add(db, [100, 120, 140], "second")
    work_once(db)
    add(db, [70], "bridge")
    work_once(db)
    before = snapshot(db)
    archive = pg_command(db, "pg_dump", ["--format=custom", "--no-owner", "--no-privileges"])
    assert archive.startswith(b"PGDMP")
    restored = db_factory(migrate=False)
    pg_command(
        restored, "pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error"], archive
    )
    assert verify_store(restored)["verified"] is True
    assert snapshot(restored) == before
    assert current(restored)[0]["payload"]["evidence_event_ids"] == [
        "e0",
        "e20",
        "e40",
        "e70",
        "e100",
        "e120",
        "e140",
    ]
    assert snapshot(db) == before, "Backup/restore must leave source evidence untouched"
