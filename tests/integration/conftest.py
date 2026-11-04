"""Small, retained, explicitly named databases; credentials never enter reports."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import psycopg
import pytest

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from scripts.test_capacity import CapacityError
from scripts.test_journal import JournalError
from scripts.test_provision import build_provisioner
from scripts.test_service import admin_from_environment, load

ROOT = Path(__file__).resolve().parents[2]


def admin_database(value: str) -> Database:
    """Validate every admin connection with the same boundary as application SQL."""
    db = Database(value)
    if any(os.environ.get(key) for key in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR")):
        raise EvidenceError("UNSAFE_DATABASE_ENVIRONMENT")
    return db


@pytest.fixture(scope="session")
def admin_db(record_testsuite_property) -> Database:
    try:
        db = admin_from_environment()
        load(ROOT)
    except (EvidenceError, CapacityError, OSError):
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
def db_factory(
    admin_db: Database, request: pytest.FixtureRequest, record_testsuite_property
) -> Callable[..., Database]:
    # No implicit local enrollment: runner must have enrolled a fresh hosted service.
    try:
        provisioner = build_provisioner(ROOT)
        provisioner.__enter__()
    except (CapacityError, JournalError, EvidenceError, psycopg.Error, OSError) as exc:
        code = (
            str(exc) if isinstance(exc, (CapacityError, JournalError)) else "TEST_DATABASE_FAILURE"
        )
        pytest.fail("Required test capacity or provenance unavailable: " + code, pytrace=False)

    def finish() -> None:
        record_testsuite_property("retained_databases_created", len(provisioner.created))
        record_testsuite_property("capacity_summary", json.dumps(provisioner.public_summary()))
        provisioner.__exit__(None, None, None)

    request.addfinalizer(finish)

    def create(*, migrate: bool = True) -> Database:
        try:
            # pytest's current node includes setup/call phase; bounded private journal only.
            test = os.environ.get("PYTEST_CURRENT_TEST", "session_fixture")
            return provisioner.create(
                migrate=migrate,
                test=test,
                purpose="migration" if migrate else "restore_upgrade",
            )
        except (CapacityError, JournalError, EvidenceError, psycopg.Error, OSError):
            pytest.fail("Test creation blocked; private provenance requires review", pytrace=False)

    return create


@pytest.fixture
def db(db_factory: Callable[..., Database]) -> Database:
    return db_factory()
