"""Private pipeline configuration and explicit maintenance routing fail closed."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import psycopg
import pytest

from cloudsecops_live.cli import main
from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_config import write_private_json


def config():
    # Public, nonworking local fixture; no PostgreSQL connection is made by units.
    return {
        "pipeline_id": "a" * 32,
        "kind": "collector",
        "dsn": "host=127.0.0.1 dbname=csl_test_pipeline user=csl_fixture connect_timeout=1",
    }


@pytest.mark.parametrize(
    "change",
    (
        {"kind": "owner"},
        {"kind": "reviewer"},
        {"kind": None},
        {"pipeline_id": "f" * 31},
        {"pipeline_id": "f" * 33},
        {"pipeline_id": None},
        {"dsn": None},
        {"dsn": 3},
        {"dsn": "host=external.invalid dbname=csl_test_pipeline"},
        {"owner": True},
    ),
)
def test_private_pipeline_config_rejects_invalid_shape_identity_and_external_dsn(tmp_path, change):
    from cloudsecops_live.pipeline_roles import load_pipeline_config

    path = tmp_path / "private-configuration-marker.json"
    write_private_json(path, {**config(), **change})
    with pytest.raises(EvidenceError) as rejected:
        load_pipeline_config(path, "collector")
    assert "private-configuration-marker" not in str(rejected.value)
    assert "external.invalid" not in str(rejected.value)
    assert "csl_fixture" not in str(rejected.value)


def test_private_pipeline_config_requires_complete_exact_keys_and_expected_kind(tmp_path):
    from cloudsecops_live.pipeline_roles import load_pipeline_config

    for index, value in enumerate(
        (
            {key: val for key, val in config().items() if key != "pipeline_id"},
            [],
            {**config(), "kind": "worker"},
        )
    ):
        path = tmp_path / f"pipeline-{index}.json"
        write_private_json(path, value)
        with pytest.raises(EvidenceError):
            load_pipeline_config(path, "collector")
    path = tmp_path / "pipeline-valid.json"
    write_private_json(path, config())
    for kind in ("owner", "reviewer", "", None):
        with pytest.raises(EvidenceError):
            load_pipeline_config(path, kind)


def test_valid_private_pipeline_config_constructs_bounded_database_without_network(
    tmp_path, monkeypatch
):
    from cloudsecops_live.pipeline_roles import load_pipeline_config

    def connection_forbidden(_):
        raise AssertionError("Configuration parsing must not silently perform maintenance work")

    monkeypatch.setattr(Database, "connect", connection_forbidden)
    path = tmp_path / "collector.json"
    write_private_json(path, config())
    assert isinstance(load_pipeline_config(path, "collector"), Database)


def test_missing_malformed_and_oversized_private_pipeline_files_are_sanitized(tmp_path):
    from cloudsecops_live.pipeline_roles import load_pipeline_config

    path = tmp_path / "private-pipeline-marker.json"
    with pytest.raises(EvidenceError) as rejected:
        load_pipeline_config(path, "collector")
    assert "private-pipeline-marker" not in str(rejected.value)
    for data in (b"{private-invalid-json", b"x" * 100_001):
        path.write_bytes(data)
        from cloudsecops_live.workspace_tls import restrict_private

        restrict_private(path)
        with pytest.raises(EvidenceError):
            load_pipeline_config(path, "collector")


@pytest.mark.parametrize("kind", ("owner", "reviewer", "", None, True))
def test_pipeline_provisioning_rejects_arbitrary_capability_before_maintenance_connection(kind):
    from cloudsecops_live.pipeline_roles import provision_pipeline

    maintenance = MagicMock()
    maintenance.connect.side_effect = AssertionError("Invalid kind must not reach maintenance SQL")
    with pytest.raises(EvidenceError, match="PIPE_INVALID"):
        provision_pipeline(maintenance, kind)
    maintenance.connect.assert_not_called()


@pytest.mark.parametrize("pipeline_id", ("", "f" * 31, "f" * 33, "' OR 1=1 --", None))
def test_disable_pipeline_requires_exact_identifier_before_maintenance_connection(pipeline_id):
    from cloudsecops_live.pipeline_roles import disable_pipeline

    maintenance = MagicMock()
    maintenance.connect.side_effect = AssertionError(
        "Invalid identity must not reach maintenance SQL"
    )
    with pytest.raises(EvidenceError, match="PIPE_INVALID"):
        disable_pipeline(maintenance, pipeline_id)
    maintenance.connect.assert_not_called()


@pytest.mark.parametrize(
    "command,kind",
    (
        ("db-ingest", "collector"),
        ("db-work", "worker"),
        ("db-deliver", "worker"),
        ("db-status", "worker"),
        ("db-cases", "worker"),
        ("db-verify", "worker"),
    ),
)
def test_normal_cli_default_routes_to_restricted_config_and_never_maintenance(
    monkeypatch, capsys, command, kind
):
    from cloudsecops_live import durable_cli, pipeline_roles

    observed = {}

    def restricted(path, expected_kind):
        observed.update(path=str(path).replace("\\", "/"), kind=expected_kind)
        raise EvidenceError("PIPE_CONFIG")

    def maintenance(_):
        raise AssertionError("Normal commands must never choose maintenance credentials")

    monkeypatch.setattr(pipeline_roles, "load_pipeline_config", restricted)
    monkeypatch.setattr(durable_cli, "load_pipeline_config", restricted, raising=False)
    monkeypatch.setattr(durable_cli, "_database", maintenance)
    arguments = [command]
    if command == "db-ingest":
        arguments += ["synthetic.gz", "--checkpoint", "unit-checkpoint"]
    assert main(arguments) == 2
    captured = capsys.readouterr()
    assert not captured.out
    assert json.loads(captured.err)["error"]["code"] == "PIPE_CONFIG"
    assert observed == {"path": f".tools/private/{kind}.json", "kind": kind}


def test_migration_cli_requires_explicit_maintenance_before_opening_any_database(
    monkeypatch, capsys
):
    from cloudsecops_live import durable_cli

    def forbidden(_):
        raise AssertionError("A migration without maintenance opt-in must not open a connection")

    monkeypatch.setattr(durable_cli, "_database", forbidden)
    assert main(["db-migrate"]) == 64
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["error"]["code"] == "USAGE"


def test_explicit_maintenance_flag_routes_only_to_maintenance_loader(monkeypatch, capsys):
    from cloudsecops_live import durable_cli

    def maintenance(_):
        raise EvidenceError("EXPLICIT_MAINTENANCE_FIXTURE")

    monkeypatch.setattr(durable_cli, "_database", maintenance)
    assert main(["db-work", "--maintenance", "--config", "private-maintenance-marker.json"]) == 2
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["error"]["code"] == "EXPLICIT_MAINTENANCE_FIXTURE"
    assert "private-maintenance-marker" not in output.err


def test_runtime_connection_failure_is_sanitized_without_owner_fallback(monkeypatch, capsys):
    from cloudsecops_live import durable_cli, pipeline_roles

    def fail(*_):
        raise psycopg.OperationalError("private-driver-detail-must-not-appear")

    monkeypatch.setattr(pipeline_roles, "load_pipeline_config", fail)
    monkeypatch.setattr(durable_cli, "load_pipeline_config", fail, raising=False)
    assert main(["db-work", "--config", "private-worker-marker.json"]) == 75
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["error"]["code"] == "DATABASE_OPERATION_FAILED"
    assert "private-driver-detail" not in output.err and "private-worker-marker" not in output.err


def test_pipeline_provision_cli_rejects_owner_kind_and_secret_arguments(capsys):
    for arguments in (
        ["workspace", "pipeline-add", "--kind", "owner"],
        ["workspace", "pipeline-add", "--password", "private-argument-marker"],
    ):
        assert main(arguments) == 2
        output = capsys.readouterr()
        assert not output.out
        assert "private-argument-marker" not in output.err


def safe_role(*, login=False):
    return {
        "oid": 123,
        "rolcanlogin": login,
        "rolinherit": True,
        "rolsuper": False,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolreplication": False,
        "rolbypassrls": False,
    }


class UnsafeCatalog:
    """Expose one unsafe fact; no subsequent authority use may follow that fact."""

    def __init__(self, hazard):
        from hashlib import sha256

        self.hazard, self.must_reject, self.await_capability = hazard, False, False
        self.database_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.capability = "csl_pc_" + sha256(self.database_id.encode()).hexdigest()[:12]
        self.conn = MagicMock()
        self.conn.execute.side_effect = self.execute

    def execute(self, statement, parameters=()):
        from types import SimpleNamespace

        assert not self.must_reject, "Unsafe catalog fact was ignored before further authority use"
        query, row, records = str(statement), None, []
        if "SELECT database_id FROM csl.schema_migrations WHERE version=2" in query:
            row = {"database_id": self.database_id}
        elif query.startswith("SELECT * FROM pg_catalog.pg_roles WHERE rolname=%s"):
            row = safe_role()
            if parameters == ("csl_ws_owner",) and self.hazard in (
                "missing_global",
                "login_global",
            ):
                row = None if self.hazard == "missing_global" else safe_role(login=True)
                self.must_reject = True
        elif query.startswith("SELECT 1 FROM pg_catalog.pg_auth_members WHERE member="):
            if parameters == ("csl_ws_owner",) and self.hazard == "global_inheritance":
                row, self.must_reject = {"present": 1}, True
        elif query.startswith("SELECT * FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER"):
            row = safe_role(login=True)
            if self.hazard == "missing_login":
                row, self.must_reject = None, True
            elif self.hazard in (
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
            ):
                row[self.hazard], self.must_reject = True, True
            elif self.hazard == "no_inherit":
                row["rolinherit"], self.must_reject = False, True
        elif query.startswith("SELECT r.rolname,m.admin_option"):
            records = [{"rolname": self.capability, "admin_option": False}]
            if self.hazard == "missing_membership":
                records, self.must_reject = [], True
            elif self.hazard == "foreign_membership":
                records.append({"rolname": "csl_ws_reviews", "admin_option": False})
                self.must_reject = True
            elif self.hazard == "membership_admin":
                records[0]["admin_option"], self.must_reject = True, True
        elif query.startswith("SELECT 1 FROM pg_catalog.pg_database"):
            if self.hazard == "database_or_schema_authority":
                row, self.must_reject = {"present": 1}, True
        elif query.startswith("SELECT 1 FROM pg_catalog.pg_class"):
            if self.hazard == "object_or_definer_authority":
                row, self.must_reject = {"present": 1}, True
        elif "WITH allowed AS" in query:
            assert self.hazard == "missing_exact_grants"
            self.await_capability = True
        elif query.startswith("SELECT oid FROM pg_catalog.pg_roles"):
            assert self.await_capability
            row, self.must_reject = {"oid": 123}, True
        else:
            raise AssertionError("Unexpected authority lookup after an unsafe observation")
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: records)


@pytest.mark.parametrize(
    "hazard",
    (
        "missing_global",
        "login_global",
        "global_inheritance",
        "missing_login",
        "rolsuper",
        "rolcreaterole",
        "rolcreatedb",
        "rolreplication",
        "rolbypassrls",
        "no_inherit",
        "missing_membership",
        "foreign_membership",
        "membership_admin",
        "database_or_schema_authority",
        "object_or_definer_authority",
        "missing_exact_grants",
    ),
)
def test_runtime_catalog_rejects_unsafe_authority_before_use(hazard):
    from cloudsecops_live.pipeline_roles import validate_pipeline_identity

    with pytest.raises(EvidenceError, match="PIPE_ROLES_UNSAFE"):
        validate_pipeline_identity(UnsafeCatalog(hazard).conn, "collector")


def test_pipeline_account_limit_precedes_login_creation(monkeypatch):
    from cloudsecops_live import pipeline_roles

    maintenance, connection = MagicMock(), MagicMock()
    maintenance.connect.return_value.__enter__.return_value = connection
    connection.execute.return_value.fetchone.return_value = {"n": 100}
    monkeypatch.setattr(Database, "check_schema", lambda _: None)
    monkeypatch.setattr(
        pipeline_roles,
        "_login",
        MagicMock(
            side_effect=AssertionError("The finite account limit must precede credential creation")
        ),
    )
    with pytest.raises(EvidenceError, match="PIPE_LIMIT"):
        pipeline_roles.provision_pipeline(maintenance, "collector")


def test_pipeline_maintenance_driver_errors_do_not_expose_private_detail():
    from cloudsecops_live.pipeline_roles import disable_pipeline, provision_pipeline

    maintenance = MagicMock()
    maintenance.connect.side_effect = psycopg.OperationalError("private-pipeline-driver-marker")
    for operation, arguments in (
        (provision_pipeline, ("collector",)),
        (disable_pipeline, ("a" * 32,)),
    ):
        with pytest.raises(EvidenceError, match="PIPE_DATABASE") as rejected:
            operation(maintenance, *arguments)
        assert "private-pipeline-driver-marker" not in str(rejected.value)
