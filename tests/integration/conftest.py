"""Small, retained, explicitly named databases; credentials never enter reports."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError

ROOT = Path(__file__).resolve().parents[2]


def admin_database(value: str) -> Database:
    """Validate every admin connection with the same boundary as application SQL."""
    db = Database(value)
    if any(os.environ.get(key) for key in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR")):
        raise EvidenceError("UNSAFE_DATABASE_ENVIRONMENT")
    return db


@pytest.fixture(scope="session")
def admin_db(record_testsuite_property) -> Database:
    value = os.environ.get("CSL_TEST_DSN")
    if not value:
        for name in ("phase1a2-dsn.json", "local-postgres.json"):
            path = ROOT / ".tools" / "private" / name
            if path.is_file():
                value = json.loads(path.read_text(encoding="utf-8"))["dsn"]
                break
    if not value:
        pytest.fail("PostgreSQL required: set CSL_TEST_DSN to the isolated loopback test service")
    try:
        db = admin_database(value)
    except EvidenceError:
        pytest.fail("Invalid test database configuration", pytrace=False)
    # Do not interpolate connection exceptions: drivers may include private DSNs.
    try:
        with db.connect() as conn:
            version = conn.execute("SHOW server_version").fetchone()["server_version"]
            record_testsuite_property("postgresql_version", version)
    except psycopg.Error:
        pytest.fail("Required isolated PostgreSQL service is unavailable", pytrace=False)
    return db


@pytest.fixture(scope="session")
def db_factory(admin_db: Database) -> Callable[..., Database]:
    created: list[str] = []

    def create(*, migrate: bool = True) -> Database:
        # The expanded workspace suite needs over 96 fresh databases. Retain a finite
        # 128-database ceiling; local host/project-volume capacity was rechecked.
        if len(created) >= 128:
            pytest.fail("Per-run retained test database cap reached")
        name = "csl_test_" + uuid.uuid4().hex
        try:
            with admin_db.connect() as conn:
                conn.autocommit = True
                conn.execute(
                    sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name))
                )
                # Quarantine fresh/restore targets before any definer functions exist.
                # Only the maintenance owner can connect until security is reconstructed.
                conn.execute(
                    sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(
                        sql.Identifier(name)
                    )
                )
        except psycopg.Error:
            pytest.fail("Could not create retained scoped test database", pytrace=False)
        created.append(name)
        db = Database(make_conninfo(**{**admin_db._values, "dbname": name}))
        if migrate:
            from cloudsecops_live.workspace_roles import setup_roles

            setup_roles(db)
            db.migrate()
        return db

    return create


@pytest.fixture
def db(db_factory: Callable[..., Database]) -> Database:
    return db_factory()
