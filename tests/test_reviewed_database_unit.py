"""Malformed verifier authority fails before any service operation is exposed."""

from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import MagicMock

import psycopg
import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import (
    disable_verifier,
    provision_verifier,
    validate_verifier_identity,
)
from tests.test_workspace_privilege_edges import Catalog


class VerifierCatalog(Catalog):
    def execute(self, statement, parameters=()):
        text = str(statement)
        if text == "SELECT csl.vf_identity() AS value":
            value = None if self.hazard == "unmapped_login" else {"verifier_id": "v"}
            return SimpleNamespace(fetchone=lambda: {"value": value})
        if text.startswith("SELECT r.rolname,m.admin_option"):
            rows = (
                []
                if self.hazard == "no_memberships"
                else [{"rolname": "csl_ws_verifier", "admin_option": self.hazard == "admin_option"}]
            )
            if self.hazard == "unexpected_membership":
                rows.append({"rolname": "csl_ws_reader", "admin_option": False})
            return SimpleNamespace(fetchall=lambda: rows)
        return super().execute(statement, parameters)


@pytest.mark.parametrize(
    "hazard",
    [
        "missing_owner",
        "login_owner",
        "owner_inherits",
        "missing_login",
        "rolsuper",
        "no_inherit",
        "no_memberships",
        "admin_option",
        "unexpected_membership",
        "database_or_schema_create",
        "direct_object_privilege",
        "object_owner",
    ],
)
def test_service_cannot_validate_with_catalog_privilege_drift(hazard):
    with pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"):
        validate_verifier_identity(VerifierCatalog(hazard).conn)


def test_service_must_have_an_enabled_case_mapping():
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        validate_verifier_identity(VerifierCatalog("unmapped_login").conn)
    validate_verifier_identity(VerifierCatalog(None).conn)


def test_provisioning_rejects_unbound_identifiers_before_connecting():
    for case_id, digest in (("bad", "a" * 64), ("a" * 64, "bad")):
        with pytest.raises(EvidenceError, match="WS_INVALID"):
            provision_verifier(None, case_id, digest)


def test_verifier_maintenance_errors_are_redacted():
    db = MagicMock()
    db.connect.side_effect = psycopg.OperationalError("private verifier connection")
    for operation, args in (
        (provision_verifier, ("a" * 64, "b" * 64)),
        (disable_verifier, ("a" * 32,)),
    ):
        with pytest.raises(EvidenceError, match="WS_DATABASE") as rejected:
            operation(db, *args)
        assert "private" not in str(rejected.value)


def test_disabled_existing_verifier_store_raises_a_bounded_denial(monkeypatch):
    import cloudsecops_live.workflow_store as module

    store = object.__new__(module.VerifierStore)
    store.db = MagicMock()
    monkeypatch.setattr(module, "_call", lambda *args: None)
    with pytest.raises(EvidenceError, match="WS_DENIED"):
        store.identity()


@pytest.mark.parametrize("prefix_length,stored_hash", [(2, "a" * 64), (3, "b" * 64)])
def test_verifier_constructor_rejects_stale_or_mismatched_schema_before_authority(
    monkeypatch, prefix_length, stored_hash
):
    import cloudsecops_live.database as database
    import cloudsecops_live.workflow_store as module

    # These are valid contiguous migration receipts, so a schema gate must reject
    # the stale length or live-catalog mismatch rather than a malformed checksum.
    receipt = [
        {
            "version": version,
            "checksum": sha256(source.read_bytes()).hexdigest(),
            "schema_hash": stored_hash,
        }
        for version, source in enumerate(database._MIGRATIONS[:prefix_length], 1)
    ]
    db, conn = MagicMock(), MagicMock()
    db.connect.return_value.__enter__.return_value = conn
    conn.execute.return_value.fetchone.return_value = {"value": receipt}
    monkeypatch.setattr(module, "_receipt_hash", lambda conn, version: "a" * 64)

    def authority_forbidden(_):
        raise AssertionError("An unvalidated schema must not reach verifier authority")

    monkeypatch.setattr(module, "validate_verifier_identity", authority_forbidden)
    with pytest.raises(EvidenceError) as rejected:
        module.VerifierStore(db)
    assert str(rejected.value) == "WS_SCHEMA"


def test_verifier_constructor_redacts_database_connection_errors(monkeypatch, capsys):
    import cloudsecops_live.workflow_store as module

    db = MagicMock()
    db.connect.side_effect = psycopg.OperationalError("private verifier connection marker")

    def authority_forbidden(_):
        raise AssertionError("A failed connection must not reach verifier authority")

    monkeypatch.setattr(module, "validate_verifier_identity", authority_forbidden)
    with pytest.raises(EvidenceError) as rejected:
        module.VerifierStore(db)
    assert str(rejected.value) == "WS_SCHEMA"
    assert "private verifier" not in str(rejected.value)
    assert capsys.readouterr().err == ""
