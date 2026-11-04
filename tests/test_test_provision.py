"""Offline boundary tests; real PostgreSQL tests run only in disposable CI."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest

from scripts.test_capacity import DEFAULT_LIMITS, CapacityError, Limits
from scripts.test_journal import Journal, JournalError, pending_creations, read_records
from scripts.test_provision import Provisioner
from scripts.test_service import sanitized
from tests.test_capacity_policy import resources


def metadata():
    return {
        "source_revision": "a" * 40,
        "harness_version": "ops1/1",
        "cluster_id": "123",
        "service_id": "b" * 64,
        "volume_id": "c" * 64,
    }


class Connection:
    def __init__(self):
        self.commands = []
        self.created = 0
        self.last = None
        self.autocommit = False
        self.closed = False
        self.lock = True

    def execute(self, command, params=()):
        text = str(command)
        self.commands.append(text)
        if "pg_control_system" in text:
            self.last = {
                "cluster_id": "123",
                "postmaster_started": "now",
                "owner": "cloudsecops_ci",
                "database": "cloudsecops_lab",
            }
        elif "pg_try_advisory_lock" in text:
            self.last = {"held": self.lock}
        elif "database_count" in text:
            self.last = {"database_count": 4 + self.created, "role_count": 14}
        elif "CREATE DATABASE" in text:
            self.created += 1
        elif "AS oid" in text:
            self.last = {"oid": 12345, "owner": "cloudsecops_ci", "datallowconn": False}
        elif "public_access" in text:
            self.last = {"datallowconn": False, "public_access": False}
        return self

    def fetchone(self):
        return self.last

    def close(self):
        self.closed = True


def harness(tmp_path: Path, *, fault=None, limits=DEFAULT_LIMITS):
    conn = Connection()
    admin = SimpleNamespace(
        connect=lambda: conn,
        _values={"host": "127.0.0.1", "dbname": "cloudsecops_lab", "user": "cloudsecops_ci"},
    )
    service = SimpleNamespace(validate=lambda: None, cluster_id="123", postmaster_started="now")
    journal = Journal(tmp_path, "d" * 32, metadata())
    return Provisioner(
        admin,
        service,
        journal,
        resources,
        limits=limits,
        fault=fault,
        mask=lambda name: None,
    ), conn


def test_connection_quarantine_is_part_of_create_and_precedes_acl(tmp_path):
    owner, conn = harness(tmp_path)
    with owner:
        owner.create(migrate=False, test="test-create", purpose="restore_upgrade")
    commands = "\n".join(conn.commands)
    assert "ALLOW_CONNECTIONS false" in commands
    assert commands.index("ALLOW_CONNECTIONS false") < commands.index("REVOKE ALL")
    assert commands.index("REVOKE ALL") < commands.index("ALLOW_CONNECTIONS true")
    records = read_records(tmp_path)
    assert [r["event"] for r in records] == [
        "run_started",
        "intent",
        "created",
        "quarantined",
        "ready",
        "provisioned",
        "run_finished",
    ]
    assert pending_creations(records) == []
    assert conn.closed


@pytest.mark.parametrize("stage", ["intent", "created", "acl", "quarantined", "enabled", "ready"])
def test_fault_poisoning_is_persistent_and_never_silently_retries(tmp_path, stage):
    def fail(actual):
        if actual == stage:
            raise RuntimeError("private-payload-is-not-a-public-reason")

    owner, conn = harness(tmp_path, fault=fail)
    with owner:
        with pytest.raises(CapacityError, match="^CREATION_OPERATOR_REVIEW_REQUIRED$"):
            owner.create(migrate=False)
        before = conn.created
        with pytest.raises(CapacityError):
            owner.create(migrate=False)
        assert conn.created == before
    records = read_records(tmp_path)
    assert pending_creations(records)
    assert "private-payload" not in json.dumps(records)
    with pytest.raises(JournalError, match="journal_operator_review_required"):
        with Journal(tmp_path, "e" * 32, metadata()):
            pytest.fail("Uncertain creation was admitted")


def test_busy_cluster_lock_does_not_create(tmp_path):
    owner, conn = harness(tmp_path)
    conn.lock = False
    with pytest.raises(CapacityError, match="HARNESS_BUSY"):
        with owner:
            pytest.fail("Busy cluster admitted")
    assert conn.created == 0 and conn.closed


def test_per_run_counter_remains_an_additional_bound(tmp_path):
    owner, conn = harness(tmp_path, limits=replace(Limits(), max_per_run=1))
    with owner:
        owner.create(migrate=False)
        with pytest.raises(CapacityError, match="CAPACITY_RUN_LIMIT"):
            owner.create(migrate=False)
    assert conn.created == 1


@pytest.mark.parametrize("error", [psycopg.OperationalError, psycopg.Error, OSError])
def test_enrollment_errors_never_disclose_driver_or_os_payload(error):
    @sanitized
    def broken():
        value = "postgresql://fake:fake@127.0.0.1/fake"  # pragma: allowlist secret - fake DSN
        raise error(value)

    with pytest.raises(CapacityError) as caught:
        broken()
    assert str(caught.value) == "TEST_SERVICE_OBSERVATION_FAILED"
    assert caught.value.__cause__ is None


def test_runner_refuses_local_invocation_before_connect(monkeypatch, capsys, tmp_path):
    from scripts import run_integration

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr("sys.argv", ["run_integration", "--receipt", str(tmp_path / "public.json")])
    monkeypatch.setattr(
        psycopg, "connect", lambda *a, **k: pytest.fail("Local connection attempted")
    )
    assert run_integration.main() == 2
    output = capsys.readouterr()
    assert "TEST_SERVICE_PREFLIGHT_FAILED" in output.out and output.err == ""


def test_runner_rejects_pytest_options_that_could_delete_or_export_private_files(
    monkeypatch,
    capsys,
    tmp_path,
):
    from scripts import run_integration

    monkeypatch.setattr(
        "sys.argv",
        [
            "run_integration",
            "--receipt",
            str(tmp_path / "public.json"),
            "--",
            "--basetemp=unrelated-existing-data",
        ],
    )
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: pytest.fail("Connection attempted"))
    assert run_integration.main() == 2
    assert "UNSUPPORTED_TEST_RUNNER_ARGUMENT" in capsys.readouterr().out


@pytest.mark.parametrize(
    "limits,code",
    [
        (replace(Limits(), max_databases=4), "CAPACITY_DATABASE_LIMIT"),
        (replace(Limits(), max_roles=45), "CAPACITY_ROLE_LIMIT"),
    ],
)
def test_global_caps_prevent_even_the_first_creation(tmp_path, limits, code):
    owner, conn = harness(tmp_path, limits=limits)
    with pytest.raises(CapacityError, match=code):
        with owner:
            pytest.fail("At-cap cluster admitted")
    assert conn.created == 0 and conn.closed


def test_changed_cluster_identity_blocks_creation(tmp_path, monkeypatch):
    import scripts.test_provision as api

    owner, conn = harness(tmp_path)
    with owner:
        monkeypatch.setattr(
            api,
            "sql_identity",
            lambda conn: {
                "cluster_id": "different",
                "postmaster_started": "now",
            },
        )
        with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
            owner.create(migrate=False)
    assert conn.created == 0


def test_arbitrary_purpose_is_rejected_without_intent_or_create(tmp_path):
    owner, conn = harness(tmp_path)
    with owner:
        with pytest.raises(CapacityError, match="INVALID_CREATION_PURPOSE"):
            owner.create(purpose="https://outside.invalid/command")
    assert conn.created == 0
    assert len(read_records(tmp_path)) == 2


@pytest.mark.parametrize("changed", [{"owner": "other"}, {"datallowconn": True}, None])
def test_unexpected_created_catalog_identity_never_enables_connections(
    tmp_path, monkeypatch, changed
):
    owner, conn = harness(tmp_path)
    original = conn.fetchone

    def wrong():
        row = original()
        if row and "oid" in row:
            return None if changed is None else {**row, **changed}
        return row

    monkeypatch.setattr(conn, "fetchone", wrong)
    with owner:
        with pytest.raises(CapacityError, match="CREATION_OPERATOR_REVIEW_REQUIRED"):
            owner.create(migrate=False)
    assert not any("ALLOW_CONNECTIONS true" in cmd for cmd in conn.commands)
    assert pending_creations(read_records(tmp_path))


@pytest.mark.parametrize("changed", [{"public_access": True}, {"datallowconn": True}, None])
def test_failed_acl_confirmation_never_enables_connections(tmp_path, monkeypatch, changed):
    owner, conn = harness(tmp_path)
    original = conn.fetchone

    def wrong():
        row = original()
        if row and "public_access" in row:
            return None if changed is None else {**row, **changed}
        return row

    monkeypatch.setattr(conn, "fetchone", wrong)
    with owner:
        with pytest.raises(CapacityError):
            owner.create(migrate=False)
    assert not any("ALLOW_CONNECTIONS true" in cmd for cmd in conn.commands)


def test_migration_outcome_is_distinct_from_target_creation(tmp_path, monkeypatch):
    from cloudsecops_live import workspace_roles
    from cloudsecops_live.database import Database

    called = []
    monkeypatch.setattr(workspace_roles, "setup_roles", lambda db: called.append("roles"))
    monkeypatch.setattr(Database, "migrate", lambda db: called.append("migration"))
    owner, _ = harness(tmp_path)
    with owner:
        owner.create(migrate=True)
    assert called == ["roles", "migration"]
    assert read_records(tmp_path)[-2]["outcome"] == "migration_complete"


def test_failed_initial_journal_write_cannot_reach_create(tmp_path, monkeypatch):
    owner, conn = harness(tmp_path)
    with owner:

        def fail(record):
            raise JournalError("journal_write_failed")

        monkeypatch.setattr(owner.journal, "append", fail)
        with pytest.raises(CapacityError):
            owner.create(migrate=False)
        assert conn.created == 0
        monkeypatch.undo()


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_interruption_is_not_misrepresented_as_success(tmp_path, failure):
    def stop(stage):
        if stage == "created":
            raise failure()

    owner, conn = harness(tmp_path, fault=stop)
    with owner:
        with pytest.raises(failure):
            owner.create(migrate=False)
    assert conn.created == 1 and pending_creations(read_records(tmp_path))


def test_source_fingerprint_binds_current_files_without_private_configuration():
    from scripts.test_provision import source_metadata

    root = Path(__file__).resolve().parents[1]
    meta = source_metadata(
        root,
        SimpleNamespace(
            cluster_id="123",
            container_id="b" * 64,
            volume_id="c" * 64,
            postmaster_started="now",
        ),
    )
    assert len(meta["harness_sha256"]) == 64
    assert len(meta["source_revision"]) == len(meta["source_tree"]) == 40
    assert "dsn" not in meta and "password" not in meta


def test_public_summary_does_not_inherit_extra_observer_fields(tmp_path):
    owner, _ = harness(tmp_path)
    owner.observe = lambda: {**resources(), "private_unknown_identifier": "must-stay-private"}
    with owner:
        public = json.dumps(owner.public_summary())
    assert "private_unknown_identifier" not in public and "must-stay-private" not in public


def test_service_admin_route_must_match_inspected_ipv4_service(monkeypatch):
    from scripts.test_service import admin_from_environment

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("CSL_TEST_DSN", "host=::1 dbname=cloudsecops_lab user=cloudsecops_ci")
    with pytest.raises(CapacityError, match="TEST_SERVICE_DSN_MISMATCH"):
        admin_from_environment()


def test_runner_rejects_ambient_test_selection_before_service_enrollment(
    monkeypatch,
    capsys,
    tmp_path,
):
    from scripts import run_integration

    monkeypatch.setenv("PYTEST_ADDOPTS", "-k one_test")
    monkeypatch.setattr("sys.argv", ["run_integration", "--receipt", str(tmp_path / "public.json")])
    monkeypatch.setattr(run_integration, "enroll", lambda root: pytest.fail("Service accessed"))
    assert run_integration.main() == 2
    assert "UNSUPPORTED_TEST_RUNNER_ARGUMENT" in capsys.readouterr().out
