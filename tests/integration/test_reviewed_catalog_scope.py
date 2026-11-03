"""Restricted LOGIN validation rejects authority outside the fingerprinted schema."""

from __future__ import annotations

import pytest
from psycopg import sql

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import validate_identity, validate_verifier_identity
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def test_unrelated_schema_authority_cannot_hide_from_runtime_identity_checks(workflow):  # noqa: F811
    runtime = Database(workflow.workspace.accounts["reviewer"]["data_dsn"])
    role = sql.Identifier(runtime._values["user"])
    with workflow.db.connect() as control:
        control.autocommit = True
        control.execute("CREATE SCHEMA authority_probe")
        control.execute("CREATE TABLE authority_probe.private_rows(value text)")
        control.execute("CREATE SEQUENCE authority_probe.private_sequence")
        statements = (
            (
                sql.SQL("GRANT CREATE ON SCHEMA authority_probe TO {}").format(role),
                sql.SQL("REVOKE CREATE ON SCHEMA authority_probe FROM {}").format(role),
            ),
            (
                sql.SQL("ALTER SCHEMA authority_probe OWNER TO {}").format(role),
                sql.SQL("ALTER SCHEMA authority_probe OWNER TO {}").format(
                    sql.Identifier(workflow.db._values["user"])
                ),
            ),
            (
                sql.SQL("GRANT SELECT(value) ON authority_probe.private_rows TO {}").format(role),
                sql.SQL("REVOKE SELECT(value) ON authority_probe.private_rows FROM {}").format(
                    role
                ),
            ),
            (
                sql.SQL("GRANT SELECT ON authority_probe.private_rows TO {}").format(role),
                sql.SQL("REVOKE SELECT ON authority_probe.private_rows FROM {}").format(role),
            ),
            (
                sql.SQL("GRANT USAGE ON SEQUENCE authority_probe.private_sequence TO {}").format(
                    role
                ),
                sql.SQL("REVOKE USAGE ON SEQUENCE authority_probe.private_sequence FROM {}").format(
                    role
                ),
            ),
            (
                sql.SQL("ALTER TABLE authority_probe.private_rows OWNER TO {}").format(role),
                sql.SQL("ALTER TABLE authority_probe.private_rows OWNER TO {}").format(
                    sql.Identifier(workflow.db._values["user"])
                ),
            ),
        )
        for grant, repair in statements:
            control.execute(grant)
            try:
                with (
                    runtime.connect() as conn,
                    pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"),
                ):
                    validate_identity(conn, "data")
            finally:
                control.execute(repair)


def test_unrelated_public_security_definer_execution_is_unsafe_for_all_runtime_kinds(workflow):  # noqa: F811
    account = workflow.workspace.accounts["alice"]
    connections = (
        (Database(account["auth_dsn"]), "auth"),
        (Database(account["data_dsn"]), "data"),
        (workflow.workspace.config.gate_db, "gate"),
        (Database(workflow.verifier_account["dsn"]), "verifier"),
    )
    with workflow.db.connect() as control:
        control.autocommit = True
        control.execute(
            "CREATE FUNCTION public.invoker_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1'"
        )
        for runtime, kind in connections:
            with runtime.connect() as conn:
                if kind == "verifier":
                    validate_verifier_identity(conn)
                else:
                    validate_identity(conn, kind)
        control.execute("DROP FUNCTION public.invoker_probe()")
        control.execute(
            "CREATE FUNCTION public.authority_probe() RETURNS integer LANGUAGE sql "
            "SECURITY DEFINER AS 'SELECT 1'"
        )
        try:
            for runtime, kind in connections:
                with (
                    runtime.connect() as conn,
                    pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"),
                ):
                    if kind == "verifier":
                        validate_verifier_identity(conn)
                    else:
                        validate_identity(conn, kind)
        finally:
            control.execute("DROP FUNCTION public.authority_probe()")


def test_pg_named_user_schema_is_not_a_system_namespace(workflow):  # noqa: F811
    runtimes = (
        (Database(workflow.workspace.accounts["reviewer"]["data_dsn"]), "data"),
        (Database(workflow.verifier_account["dsn"]), "verifier"),
    )
    with workflow.db.connect() as control:
        control.autocommit = True
        control.execute("CREATE SCHEMA pgx_private")
        control.execute("CREATE TABLE pgx_private.private_rows(value text)")
        control.execute(
            "CREATE FUNCTION pgx_private.unsafe_probe() RETURNS integer "
            "LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
        )
        # Isolate CREATE and table grants first, without default function execution.
        control.execute("REVOKE EXECUTE ON FUNCTION pgx_private.unsafe_probe() FROM PUBLIC")
        for runtime, kind in runtimes:
            role = sql.Identifier(runtime._values["user"])
            for grant, repair in (
                (
                    sql.SQL("GRANT CREATE ON SCHEMA pgx_private TO {}").format(role),
                    sql.SQL("REVOKE CREATE ON SCHEMA pgx_private FROM {}").format(role),
                ),
                (
                    sql.SQL("GRANT SELECT ON pgx_private.private_rows TO {}").format(role),
                    sql.SQL("REVOKE SELECT ON pgx_private.private_rows FROM {}").format(role),
                ),
                (
                    sql.SQL("GRANT EXECUTE ON FUNCTION pgx_private.unsafe_probe() TO {}").format(
                        role
                    ),
                    sql.SQL("REVOKE EXECUTE ON FUNCTION pgx_private.unsafe_probe() FROM {}").format(
                        role
                    ),
                ),
            ):
                control.execute(grant)
                try:
                    with (
                        runtime.connect() as conn,
                        pytest.raises(EvidenceError, match="WS_ROLES_UNSAFE"),
                    ):
                        if kind == "verifier":
                            validate_verifier_identity(conn)
                        else:
                            validate_identity(conn, kind)
                finally:
                    control.execute(repair)
