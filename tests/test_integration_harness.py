"""The privileged test harness must reject routing overrides before connecting."""

import os

import psycopg
import pytest

from cloudsecops_live.errors import EvidenceError
from tests.integration.conftest import admin_database
from tests.integration.test_backup import pg_environment

SAFE = "host=127.0.0.1 dbname=cloudsecops_lab user=unit"


@pytest.mark.parametrize(
    "override",
    [
        "hostaddr=203.0.113.10",
        "options='-c search_path=untrusted'",
        "service=outside",
        "sslcert=private-file",
        "passfile=private-file",
        "dbname=postgres",
        "host=localhost",
    ],
)
def test_admin_harness_rejects_unsafe_dsn_before_any_connect(monkeypatch, override):
    def unexpected(*args, **kwargs):
        pytest.fail("Unsafe administrative DSN reached psycopg.connect")

    monkeypatch.setattr(psycopg, "connect", unexpected)
    with pytest.raises(EvidenceError, match="UNSAFE_DATABASE_DSN"):
        admin_database(SAFE + " " + override).connect()


@pytest.mark.parametrize("key", ["PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"])
def test_admin_harness_rejects_ambient_routes_before_any_connect(monkeypatch, key):
    monkeypatch.setenv(key, "untrusted")

    def unexpected(*args, **kwargs):
        pytest.fail("Unsafe administrative environment reached psycopg.connect")

    monkeypatch.setattr(psycopg, "connect", unexpected)
    with pytest.raises(EvidenceError, match="UNSAFE_DATABASE_ENVIRONMENT"):
        admin_database(SAFE).connect()


def test_backup_environment_does_not_inherit_libpq_overrides_or_password(monkeypatch):
    db = admin_database(SAFE)
    for key in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR", "PGOPTIONS", "PGPASSWORD"):
        monkeypatch.setenv(key, "untrusted")
    env = pg_environment(db)
    assert "PGSERVICE" not in env and "PGSERVICEFILE" not in env
    assert env["PGHOSTADDR"] == "127.0.0.1"
    assert env["PGPASSWORD"] == ""
    assert env["PGPASSFILE"] == os.devnull
    assert env["PGOPTIONS"] == "-c search_path=pg_catalog"
    assert env["PGSSLMODE"] == env["PGGSSENCMODE"] == "disable"


def test_ci_backup_uses_empty_explicit_docker_config(monkeypatch, tmp_path):
    from subprocess import CompletedProcess

    from tests.integration import test_backup

    monkeypatch.setenv("CSL_POSTGRES_CONTAINER", "a" * 64)
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "unrelated-default-context"))
    monkeypatch.setattr(test_backup, "ROOT", tmp_path)
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        return CompletedProcess(command, 0, stdout=b"dump", stderr=b"")

    monkeypatch.setattr(test_backup.subprocess, "run", capture)
    assert test_backup.pg_command(admin_database(SAFE), "pg_dump", []) == b"dump"
    assert commands[0][:3] == ["docker", "--config", str(tmp_path / ".tools" / "docker-client")]
    assert not (tmp_path / ".tools" / "docker-client" / "config.json").exists()
