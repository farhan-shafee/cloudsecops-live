"""Independent malformed-catalog and private-file boundary cases; no live role changes."""

from __future__ import annotations

import os
import stat
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import psycopg
import pytest

from cloudsecops_live.errors import EvidenceError


def safe_role(*, login=False):
    return {
        "rolcanlogin": login,
        "rolinherit": True,
        "rolsuper": False,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolreplication": False,
        "rolbypassrls": False,
    }


class Catalog:
    """Supply explicit trusted catalog observations, then change one security fact."""

    def __init__(self, hazard):
        self.hazard = hazard
        self.conn = MagicMock()
        self.conn.execute.side_effect = self.execute

    def execute(self, statement, parameters=()):
        text = str(statement)
        row, records = None, []
        if "pg_advisory_xact_lock" in text:
            pass
        elif "CREATE ROLE" in text:
            pass
        elif "SELECT * FROM pg_catalog.pg_roles WHERE rolname=%s" in text:
            row = safe_role()
            if parameters == ("csl_ws_owner",):
                if self.hazard == "missing_owner":
                    row = None
                elif self.hazard == "login_owner":
                    row["rolcanlogin"] = True
                elif self.hazard == "superuser_owner":
                    row["rolsuper"] = True
        elif text.startswith("SELECT * FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER"):
            row = safe_role(login=True)
            if self.hazard == "missing_login":
                row = None
            elif self.hazard in {
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
            }:
                row[self.hazard] = True
            elif self.hazard == "no_inherit":
                row["rolinherit"] = False
        elif "SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=" in text:
            if self.hazard == "owner_inherits" and parameters == ("csl_ws_owner",):
                row = {"present": 1}
        elif "FROM pg_catalog.pg_database" in text:
            row = {"present": 1} if self.hazard == "database_or_schema_create" else None
        elif text == "SELECT csl.ws_identity() AS value":
            identity = {"identity_kind": "data", "app_role": "auditor"}
            if self.hazard == "wrong_identity_kind":
                identity["identity_kind"] = "auth"
            row = {"value": None if self.hazard == "unmapped_login" else identity}
        elif text.startswith("SELECT r.rolname,m.admin_option"):
            records = [{"rolname": "csl_ws_reader", "admin_option": self.hazard == "admin_option"}]
            if self.hazard == "unexpected_membership":
                records.append({"rolname": "csl_ws_notes", "admin_option": False})
        elif "FROM pg_catalog.pg_class" in text:
            row = {"present": 1} if self.hazard == "direct_object_privilege" else None
        elif "FROM pg_catalog.pg_proc" in text:
            row = {"present": 1} if self.hazard == "object_owner" else None
        else:
            raise AssertionError("Unexpected catalog probe")
        return SimpleNamespace(fetchone=lambda: row, fetchall=lambda: records)


@pytest.mark.parametrize(
    "hazard",
    [
        "missing_owner",
        "login_owner",
        "superuser_owner",
        "owner_inherits",
        "missing_login",
        "rolsuper",
        "rolcreaterole",
        "rolcreatedb",
        "rolreplication",
        "rolbypassrls",
        "no_inherit",
        "database_or_schema_create",
        "unexpected_membership",
        "admin_option",
        "direct_object_privilege",
        "object_owner",
    ],
)
def test_privilege_drift_cannot_validate_as_a_restricted_auditor(hazard):
    from cloudsecops_live.workspace_roles import validate_identity

    with pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"):
        validate_identity(Catalog(hazard).conn, "data")


@pytest.mark.parametrize("hazard", ["unmapped_login", "wrong_identity_kind"])
def test_unmapped_or_wrong_kind_login_cannot_gain_a_data_identity(hazard):
    from cloudsecops_live.workspace_roles import validate_identity

    with pytest.raises(EvidenceError, match="WS_DENIED"):
        validate_identity(Catalog(hazard).conn, "data")


def test_exact_auditor_catalog_is_accepted_without_note_capability():
    from cloudsecops_live.workspace_roles import validate_identity

    validate_identity(Catalog(None).conn, "data")


@pytest.mark.parametrize("hazard", ["login_owner", "owner_inherits"])
def test_setup_cannot_silently_repair_an_existing_unsafe_cluster_role(hazard):
    from cloudsecops_live.workspace_roles import setup_roles

    catalog, db = Catalog(hazard), MagicMock()
    db.connect.return_value.__enter__.return_value = catalog.conn
    with pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"):
        setup_roles(db)
    assert not any(
        "ALTER ROLE" in str(call.args[0]) for call in catalog.conn.execute.call_args_list
    )


def test_missing_owner_is_bootstrapped_as_nonlogin_without_administrative_attributes():
    from cloudsecops_live.workspace_roles import setup_roles

    catalog, db = Catalog("missing_owner"), MagicMock()
    db.connect.return_value.__enter__.return_value = catalog.conn
    setup_roles(db)
    created = [
        call.args[0].as_string()
        for call in catalog.conn.execute.call_args_list
        if "CREATE ROLE" in str(call.args[0])
    ]
    assert created == [
        'CREATE ROLE "csl_ws_owner" NOLOGIN NOSUPERUSER NOCREATEROLE '
        "NOCREATEDB NOREPLICATION NOBYPASSRLS"
    ]


def test_provisioning_limit_is_checked_before_creating_any_login(monkeypatch):
    from cloudsecops_live import workspace_roles as module

    db, conn = MagicMock(), MagicMock()
    db.connect.return_value.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = {"n": 100}
    monkeypatch.setattr(module.Database, "check_schema", lambda conn: None)
    login = MagicMock(side_effect=AssertionError("Account limit must precede role creation"))
    monkeypatch.setattr(module, "_login", login)
    with pytest.raises(EvidenceError, match="WS_LIMIT"):
        module.provision_user(db, "bounded", "analyst", "x" * 64)
    login.assert_not_called()


@pytest.mark.parametrize("receipt", [None, {"database_id": None}])
def test_missing_database_identity_never_generates_a_cluster_role_prefix(receipt):
    from cloudsecops_live.workspace_roles import _database_prefix

    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = receipt
    with pytest.raises(EvidenceError, match="WS_SCHEMA"):
        _database_prefix(conn)


@pytest.mark.parametrize(
    "operation", ["setup_roles", "setup_gate", "provision_user", "grant_case", "disable_user"]
)
def test_owner_operations_redact_driver_errors(operation):
    from cloudsecops_live import workspace_roles as module

    db = MagicMock()
    db.connect.side_effect = psycopg.OperationalError("synthetic private connection detail")
    arguments = {
        "provision_user": ("bounded", "analyst", "x" * 64),
        "grant_case": ("bounded", "a" * 64),
        "disable_user": ("bounded",),
    }
    with pytest.raises(EvidenceError) as rejected:
        getattr(module, operation)(db, *arguments.get(operation, ()))
    assert rejected.value.code == "WS_DATABASE"
    assert "private" not in str(rejected.value)


@pytest.mark.parametrize("operation", ["grant_case", "disable_user"])
def test_owner_account_operations_reject_unknown_user(monkeypatch, operation):
    from cloudsecops_live import workspace_roles as module

    db, conn = MagicMock(), MagicMock()
    db.connect.return_value.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = None
    monkeypatch.setattr(module.Database, "check_schema", lambda conn: None)
    args = ("unknown", "a" * 64) if operation == "grant_case" else ("unknown",)
    with pytest.raises(EvidenceError, match="WS_INVALID"):
        getattr(module, operation)(db, *args)


@pytest.mark.parametrize("filename", ["loopback-cert.pem", "loopback-key.pem"])
def test_real_junction_or_symlink_ancestor_cannot_supply_tls_material(tmp_path, filename):
    from cloudsecops_live.workspace_tls import safe_path

    target, alias = tmp_path / "real", tmp_path / "alias"
    target.mkdir()
    (target / filename).write_bytes(b"synthetic path fixture")
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, "Required local junction fixture could not be created"
    else:
        alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe_private_path"):
        safe_path(alias / filename)


def test_malformed_current_user_sid_cannot_authorize_private_files(monkeypatch):
    from cloudsecops_live import workspace_tls as module

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout='"user","invalid-sid"'),
    )
    with pytest.raises(ValueError, match="private_acl_failed"):
        module._current_sid()


@pytest.mark.parametrize("directory,expected", [(False, 0o600), (True, 0o700)])
def test_posix_private_mode_policy_does_not_leave_group_or_other_access(
    monkeypatch, directory, expected
):
    from cloudsecops_live import workspace_tls as module

    path = MagicMock()
    path.parents = []
    path.is_symlink.return_value = path.is_junction.return_value = False
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix"))
    module.restrict_private(path, directory=directory)
    path.chmod.assert_called_once_with(expected)


def test_posix_world_readable_key_is_rejected_before_open(monkeypatch):
    from cloudsecops_live import workspace_tls as module

    path = MagicMock()
    path.parents = []
    path.is_symlink.return_value = path.is_junction.return_value = False
    path.stat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=1)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="unsafe_private_permissions"):
        module.private_file(path, max_bytes=10)
