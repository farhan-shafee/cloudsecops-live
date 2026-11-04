"""Real PostgreSQL acceptance for isolated disposable hosted services only.

This directory is deliberately outside ordinary pytest discovery. The required
CI job enrolls its own newly created service before running these tests. Nothing
here enrolls, adopts, cleans up or operates on retained workstation databases.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from scripts.test_capacity import CapacityError, Limits
from scripts.test_journal import JournalError, read_records
from scripts.test_provision import build_provisioner
from scripts.test_service import require_hosted

ROOT = Path(__file__).resolve().parents[2]


class InjectedFailure(Exception):
    """Fixed test-only failure without an embedded database identifier."""


@pytest.fixture
def tmp_path() -> Path:
    """Keep interrupted journals outside pytest temporary-directory cleanup."""
    require_hosted()
    directory = ROOT / ".tools/private/harness-fault-tests" / uuid.uuid4().hex
    directory.mkdir(parents=True, mode=0o700)
    return directory


def inventory(directory: Path) -> dict[str, int]:
    with build_provisioner(ROOT, journal_directory=directory) as harness:
        return harness.conn.execute(
            "SELECT (SELECT count(*) FROM pg_catalog.pg_database)::int AS database_count,"
            "(SELECT count(*) FROM pg_catalog.pg_roles)::int AS role_count"
        ).fetchone()


def creation_records(directory: Path) -> list[dict]:
    return [record for record in read_records(directory) if "creation_id" in record]


def test_database_global_cap_prevents_creation_in_real_catalog(tmp_path: Path) -> None:
    before = inventory(tmp_path / "before")
    with pytest.raises(CapacityError, match="CAPACITY_DATABASE_LIMIT"):
        with build_provisioner(
            ROOT,
            journal_directory=tmp_path / "denied",
            limits=replace(Limits(), max_databases=before["database_count"]),
        ) as harness:
            harness.create(migrate=False, test="database-cap", purpose="capacity_probe")
    assert inventory(tmp_path / "after") == before


def test_global_role_reserve_prevents_creation_in_real_catalog(tmp_path: Path) -> None:
    before = inventory(tmp_path / "before")
    with pytest.raises(CapacityError, match="CAPACITY_ROLE_LIMIT"):
        with build_provisioner(
            ROOT,
            journal_directory=tmp_path / "denied",
            limits=replace(Limits(), max_roles=before["role_count"] + 31),
        ) as harness:
            harness.create(migrate=False, test="role-cap", purpose="capacity_probe")
    assert inventory(tmp_path / "after") == before


@pytest.mark.parametrize("field", ["data_free_bytes", "shm_free_bytes", "memory_current_bytes"])
def test_low_capacity_rejected_before_real_creation(tmp_path: Path, field: str) -> None:
    directory = tmp_path / "journal"
    with build_provisioner(ROOT, journal_directory=directory) as harness:
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        observed = harness.observe()
        observed[field] = observed["memory_limit_bytes"] if field == "memory_current_bytes" else 0
        if field == "memory_current_bytes":
            observed["inactive_file_bytes"] = 0
        harness.observe = lambda: observed
        with pytest.raises(CapacityError):
            harness.create(migrate=False, test="capacity", purpose="capacity_probe")
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before
    assert len(creation_records(directory)) == 0


def test_missing_resource_observation_rejects_before_real_creation(tmp_path: Path) -> None:
    directory = tmp_path / "journal"
    with build_provisioner(ROOT, journal_directory=directory) as harness:
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        observed = harness.observe()
        del observed["shm_free_bytes"]
        harness.observe = lambda: observed
        with pytest.raises(CapacityError, match="INVALID_CAPACITY_OBSERVATION"):
            harness.create(migrate=False, test="missing", purpose="capacity_probe")
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before


def test_journal_failure_before_create_cannot_create_database(tmp_path: Path, monkeypatch) -> None:
    with build_provisioner(ROOT, journal_directory=tmp_path / "journal") as harness:
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        original = harness.journal.append

        def reject_intent(record: dict) -> None:
            if record["event"] == "intent":
                raise JournalError("journal_write_failed")
            original(record)

        monkeypatch.setattr(harness.journal, "append", reject_intent)
        with pytest.raises((CapacityError, JournalError)):
            harness.create(migrate=False, test="journal-failure", purpose="capacity_probe")
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before


def test_new_database_catalog_identity_and_maintenance_only_acl_are_recorded(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "journal"
    with build_provisioner(ROOT, journal_directory=directory) as harness:
        db = harness.create(migrate=False, test="identity", purpose="restore_upgrade")
        row = harness.conn.execute(
            "SELECT d.oid::bigint AS oid,d.datname,d.datallowconn,r.rolname AS owner "
            "FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=%s",
            (db._values["dbname"],),
        ).fetchone()
        public_connect = harness.conn.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_database d CROSS JOIN LATERAL "
            "aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a "
            "WHERE d.datname=%s AND a.grantee=0 AND a.privilege_type='CONNECT') AS allowed",
            (db._values["dbname"],),
        ).fetchone()["allowed"]
        assert public_connect is False
        assert row["datallowconn"] is True
        with db.connect() as conn:
            assert conn.execute("SELECT 1 AS n").fetchone()["n"] == 1
    records = creation_records(directory)
    created = [record for record in records if record["event"] == "created"]
    assert len(created) == 1
    identity_matches = all(created[0][key] == row[key] for key in ("oid", "owner"))
    assert identity_matches is True
    name_matches = created[0]["database_name"] == row["datname"]
    assert name_matches is True
    assert records[-1]["event"] == "provisioned"
    assert records[0]["retention"] == "retain_operator_review"


@pytest.mark.parametrize("stage", ["created", "acl", "quarantined"])
def test_post_create_failure_keeps_connections_disabled_and_requires_review(
    tmp_path: Path, stage: str
) -> None:
    directory = tmp_path / "journal"
    observed = {}

    def fail(target: str) -> None:
        if target == stage:
            records = creation_records(directory)
            observed["name"] = records[-1]["database_name"]
            raise InjectedFailure()

    with build_provisioner(ROOT, journal_directory=directory, fault=fail) as harness:
        with pytest.raises((CapacityError, InjectedFailure)):
            harness.create(migrate=False, test="post-create-failure", purpose="capacity_probe")
        row = harness.conn.execute(
            "SELECT datallowconn FROM pg_database WHERE datname=%s", (observed["name"],)
        ).fetchone()
        assert row is not None and row["datallowconn"] is False
        quarantined = Database(
            make_conninfo(**{**harness.admin._values, "dbname": observed["name"]})
        )
        with pytest.raises(psycopg.Error):
            quarantined.connect()
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        with pytest.raises(CapacityError):
            harness.create(migrate=False, test="forbidden-retry", purpose="capacity_probe")
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before
    assert creation_records(directory)[-1]["event"] == "uncertain"
    with pytest.raises((CapacityError, JournalError)):
        with build_provisioner(ROOT, journal_directory=directory):
            pytest.fail("Uncertain creation was silently adopted")


CHILD = r"""
import os,sys
from pathlib import Path
from scripts.test_capacity import CapacityError
from scripts.test_journal import JournalError
from scripts.test_provision import build_provisioner
stage=sys.argv[2]
def fault(current):
    if current==stage:
        os._exit(73)
try:
    with build_provisioner(Path.cwd(),journal_directory=Path(sys.argv[1]),fault=fault) as harness:
        harness.create(migrate=False,test='child-interruption',purpose='capacity_probe')
except (CapacityError,JournalError) as exc:
    sys.stdout.write(str(exc))
    sys.exit(72)
sys.exit(0)
"""


def child(directory: Path, stage: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", CHILD, str(directory), stage],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_concurrent_run_cannot_create_while_cluster_admission_lock_is_held(tmp_path: Path) -> None:
    with build_provisioner(ROOT, journal_directory=tmp_path / "first") as harness:
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        result = child(tmp_path / "second", "never")
        assert result.returncode == 72
        assert result.stdout == b"HARNESS_BUSY"
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before


@pytest.mark.parametrize("stage", ["intent", "created", "enabled"])
def test_process_termination_retains_an_accurate_unresolved_private_receipt(
    tmp_path: Path, stage: str
) -> None:
    before = inventory(tmp_path / "before")
    directory = tmp_path / "interrupted"
    result = child(directory, stage)
    assert result.returncode == 73
    records = creation_records(directory)
    assert len(records) > 0
    name = records[-1]["database_name"]
    with build_provisioner(ROOT, journal_directory=tmp_path / "inspect") as harness:
        row = harness.conn.execute(
            "SELECT oid::bigint AS oid,datallowconn FROM pg_database WHERE datname=%s", (name,)
        ).fetchone()
        if stage == "intent":
            assert row is None
        else:
            assert row is not None
            recorded_oid_matches = any(record.get("oid") == row["oid"] for record in records)
            assert recorded_oid_matches is True
            assert row["datallowconn"] is (stage == "enabled")
    after = inventory(tmp_path / "after")
    expected_change = 0 if stage == "intent" else 1
    assert after["database_count"] - before["database_count"] == expected_change
    assert after["role_count"] == before["role_count"]
    with pytest.raises((CapacityError, JournalError)):
        with build_provisioner(ROOT, journal_directory=directory):
            pytest.fail("Interrupted creation was silently adopted")


def test_creation_failure_is_not_reported_as_success(tmp_path: Path) -> None:
    directory = tmp_path / "journal"

    def fail(stage: str) -> None:
        if stage == "intent":
            raise InjectedFailure()

    before = inventory(tmp_path / "before")
    with build_provisioner(ROOT, journal_directory=directory, fault=fail) as harness:
        with pytest.raises((CapacityError, InjectedFailure)):
            harness.create(migrate=False, test="pre-create-failure", purpose="capacity_probe")
        assert harness.blocked is True
    assert inventory(tmp_path / "after") == before
    assert not any(record["event"] == "provisioned" for record in creation_records(directory))


def test_actual_duplicate_database_error_never_adopts_or_alters_existing_target(
    tmp_path: Path, monkeypatch
) -> None:
    import scripts.test_provision as provision

    directory = tmp_path / "journal"
    with build_provisioner(ROOT, journal_directory=directory) as harness:
        first = harness.create(migrate=False, test="collision-original", purpose="restore_upgrade")
        name = first._values["dbname"]
        before = harness.conn.execute(
            "SELECT oid::bigint AS oid,datdba,datallowconn,datacl::text AS acl "
            "FROM pg_database WHERE datname=%s",
            (name,),
        ).fetchone()
        count_before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        values = iter(
            [SimpleNamespace(hex=name.removeprefix("csl_test_")), SimpleNamespace(hex="f" * 32)]
        )
        monkeypatch.setattr(provision.uuid, "uuid4", lambda: next(values))
        with pytest.raises(CapacityError, match="CREATION_OPERATOR_REVIEW_REQUIRED"):
            harness.create(migrate=False, test="collision-attempt", purpose="capacity_probe")
        after = harness.conn.execute(
            "SELECT oid::bigint AS oid,datdba,datallowconn,datacl::text AS acl "
            "FROM pg_database WHERE datname=%s",
            (name,),
        ).fetchone()
        identity_unchanged = before == after
        assert identity_unchanged is True
        count_after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert count_before == count_after
        assert harness.blocked is True
    attempts = [
        record for record in creation_records(directory) if record["creation_id"] == "f" * 32
    ]
    assert [record["event"] for record in attempts] == ["intent", "uncertain"]
    assert not any("oid" in record for record in attempts)


def test_cluster_identity_disappearance_fails_before_creation(tmp_path: Path, monkeypatch) -> None:
    import scripts.test_provision as provision

    with build_provisioner(ROOT, journal_directory=tmp_path / "journal") as harness:
        before = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        original = provision.sql_identity

        def missing_identity(conn):
            return {**original(conn), "cluster_id": ""}

        monkeypatch.setattr(provision, "sql_identity", missing_identity)
        with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
            harness.create(migrate=False, test="identity-missing", purpose="capacity_probe")
        after = harness.conn.execute("SELECT count(*) AS n FROM pg_database").fetchone()["n"]
        assert after == before


def test_public_receipt_has_no_exact_private_database_or_service_identity(tmp_path: Path) -> None:
    with build_provisioner(ROOT, journal_directory=tmp_path / "journal") as harness:
        db = harness.create(migrate=False, test="public-receipt", purpose="restore_upgrade")
        summary = json.dumps(harness.public_summary(), sort_keys=True)
        private_values = [
            db._values["dbname"],
            harness.service.cluster_id,
            harness.service.container_id,
            harness.service.volume_id,
            harness.admin._values["user"],
            harness.admin._values["password"],
        ]
        contains_private_value = any(value and value in summary for value in private_values)
        assert contains_private_value is False
        assert "postgresql://" not in summary
