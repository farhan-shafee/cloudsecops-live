"""Offline role provisioning and exact runtime privilege validation.

Generated PostgreSQL credentials are returned only to the private config writer.
Neither exception text nor logging contains passwords or role creation statements.
"""

from __future__ import annotations

import re
import secrets
from hashlib import sha256
from typing import Any
from uuid import uuid4

import psycopg
from psycopg import Connection, sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError

CAPABILITIES = ("csl_ws_auth", "csl_ws_reader", "csl_ws_notes", "csl_ws_gate", "csl_ws_reviews")
ROLES = (
    "csl_ws_owner",
    "csl_vf_owner",
    "csl_ws_verifier",
    *CAPABILITIES,
)
FUNCTIONS = {
    "csl_ws_auth": (
        "ws_identity",
        "ws_password_hash",
        "ws_create_session",
        "ws_issue_csrf",
        "ws_revoke",
        "ws_rotate",
        "ws_schema_receipt",
        "wf_issue_csrf",
    ),
    "csl_ws_reader": (
        "ws_identity",
        "ws_session",
        "ws_list_cases",
        "ws_case",
        "ws_evidence",
        "ws_schema_receipt",
        "wf_view",
        "wf_recommendation",
        "wf_queue",
    ),
    "csl_ws_notes": ("ws_add_note", "wf_recommend"),
    "csl_ws_gate": ("ws_challenge", "ws_consume", "ws_throttle", "ws_schema_receipt"),
    "csl_ws_reviews": ("wf_review", "wf_close", "wf_reopen"),
    "csl_ws_verifier": ("vf_identity", "vf_begin", "vf_original", "vf_finish", "ws_schema_receipt"),
}


def _safe_role(row: dict[str, Any], *, login: bool) -> bool:
    return row["rolcanlogin"] == login and not any(
        row[k]
        for k in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")
    )


def setup_roles(maintenance_db: Database) -> None:
    """Explicitly create stable NONLOGIN roles; never repair an unsafe existing role."""
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(7242601106)")
            for role in ROLES:
                row = conn.execute(
                    "SELECT * FROM pg_catalog.pg_roles WHERE rolname=%s", (role,)
                ).fetchone()
                if row is None:
                    conn.execute(
                        sql.SQL(
                            "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEROLE "
                            "NOCREATEDB NOREPLICATION NOBYPASSRLS"
                        ).format(sql.Identifier(role))
                    )
                elif not _safe_role(row, login=False):
                    raise EvidenceError("WS_ROLES_UNSAFE")
                if conn.execute(
                    "SELECT 1 FROM pg_catalog.pg_auth_members WHERE member="
                    "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s)",
                    (role,),
                ).fetchone():
                    raise EvidenceError("WS_ROLES_UNSAFE")
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def apply_security(conn: Connection[dict[str, Any]]) -> None:
    """Reconstruct only the fixed workspace ownership and allowlisted grants."""
    database = sql.Identifier(conn.info.dbname)
    conn.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(database))
    conn.execute(
        sql.SQL(
            "GRANT CONNECT ON DATABASE {} TO csl_ws_auth,csl_ws_reader,csl_ws_notes,csl_ws_gate"
        ).format(database)
    )
    conn.execute(
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC,csl_ws_auth,csl_ws_reader,"
        "csl_ws_notes,csl_ws_gate,csl_ws_verifier"
    )
    conn.execute(
        "GRANT USAGE ON SCHEMA csl TO csl_ws_owner,csl_ws_auth,csl_ws_reader,"
        "csl_ws_notes,csl_ws_gate"
    )
    conn.execute("REVOKE ALL ON SCHEMA csl FROM PUBLIC")
    conn.execute(
        "REVOKE ALL ON ALL TABLES IN SCHEMA csl FROM PUBLIC,"
        "csl_ws_auth,csl_ws_reader,csl_ws_notes,csl_ws_gate,csl_ws_verifier"
    )
    conn.execute(
        "REVOKE ALL ON ALL SEQUENCES IN SCHEMA csl FROM PUBLIC,"
        "csl_ws_auth,csl_ws_reader,csl_ws_notes,csl_ws_gate,csl_ws_verifier"
    )
    conn.execute(
        "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA csl FROM PUBLIC,"
        "csl_ws_auth,csl_ws_reader,csl_ws_notes,csl_ws_gate,csl_ws_verifier"
    )
    for row in conn.execute(
        "SELECT c.relname FROM pg_catalog.pg_class c JOIN "
        "pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='csl' AND c.relkind='r' AND c.relname LIKE 'ws_%'"
    ):
        conn.execute(
            sql.SQL("ALTER TABLE csl.{} OWNER TO csl_ws_owner").format(
                sql.Identifier(row["relname"])
            )
        )
    functions = conn.execute(
        "SELECT p.oid::regprocedure::text AS signature,p.proname FROM "
        "pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON "
        "n.oid=p.pronamespace WHERE n.nspname='csl' AND p.proname LIKE 'ws_%'"
    )
    for row in functions:
        signature = sql.SQL(row["signature"])
        conn.execute(sql.SQL("ALTER FUNCTION {} OWNER TO csl_ws_owner").format(signature))
        for role, names in FUNCTIONS.items():
            if row["proname"] in names:
                conn.execute(
                    sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                        signature, sql.Identifier(role)
                    )
                )
    conn.execute(
        "GRANT SELECT ON csl.schema_migrations,csl.cases,csl.case_revisions,"
        "csl.finding_evidence,csl.record_variants,csl.case_lineage,"
        "csl.source_references TO csl_ws_owner"
    )
    conn.execute(
        "GRANT SELECT(raw_id,archive_hash,content_hash) ON csl.raw_objects TO csl_ws_owner"
    )
    # FOR UPDATE needs UPDATE privilege even though workspace functions never change cases.
    conn.execute("GRANT UPDATE(current_revision) ON csl.cases TO csl_ws_owner")
    conn.execute("GRANT INSERT ON csl.audit TO csl_ws_owner")
    conn.execute("GRANT USAGE ON SEQUENCE csl.audit_audit_id_seq TO csl_ws_owner")
    conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE csl_ws_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE csl_ws_owner IN SCHEMA csl "
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    conn.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA csl REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    workflow = conn.execute("SELECT to_regclass('csl.ws_workflows') AS value").fetchone()
    if workflow and workflow["value"]:
        _apply_workflow_security(conn)
        from cloudsecops_live.pipeline_roles import apply_pipeline_security

        apply_pipeline_security(conn)


def _apply_workflow_security(conn: Connection[dict[str, Any]]) -> None:
    """Fixed v3 grants; no credential receives direct table or column authority."""
    conn.execute(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO csl_ws_reviews,csl_ws_verifier").format(
            sql.Identifier(conn.info.dbname)
        )
    )
    conn.execute("REVOKE CREATE ON SCHEMA public FROM csl_ws_reviews,csl_vf_owner")
    conn.execute("GRANT USAGE ON SCHEMA csl TO csl_ws_reviews,csl_ws_verifier,csl_vf_owner")
    conn.execute("REVOKE ALL ON ALL TABLES IN SCHEMA csl FROM csl_ws_reviews")
    conn.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA csl FROM csl_ws_reviews")
    conn.execute("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA csl FROM csl_ws_reviews")
    for name in (
        "ws_verifiers",
        "ws_verifier_grants",
        "ws_verification_requests",
        "ws_verifications",
    ):
        conn.execute(
            sql.SQL("ALTER TABLE csl.{} OWNER TO csl_vf_owner").format(sql.Identifier(name))
        )
    functions = conn.execute(
        "SELECT p.oid::regprocedure::text AS signature,p.proname FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='csl' "
        "AND (p.proname LIKE 'wf_%' OR p.proname LIKE 'vf_%')"
    ).fetchall()
    for row in functions:
        owner = (
            "csl_vf_owner"
            if row["proname"].startswith("vf_") or row["proname"] == "wf_manifest"
            else "csl_ws_owner"
        )
        signature = sql.SQL(row["signature"])
        conn.execute(
            sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(signature, sql.Identifier(owner))
        )
        conn.execute(
            sql.SQL(
                "REVOKE EXECUTE ON FUNCTION {} FROM PUBLIC,csl_ws_auth,csl_ws_reader,"
                "csl_ws_notes,csl_ws_gate,csl_ws_reviews,csl_ws_verifier"
            ).format(signature)
        )
        for role, names in FUNCTIONS.items():
            if row["proname"] in names:
                conn.execute(
                    sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                        signature, sql.Identifier(role)
                    )
                )
        conn.execute(
            sql.SQL("GRANT EXECUTE ON FUNCTION {} TO csl_ws_owner,csl_vf_owner").format(signature)
        )
    conn.execute("GRANT EXECUTE ON FUNCTION csl.ws_schema_receipt() TO csl_ws_verifier")
    conn.execute(
        "GRANT SELECT ON csl.pipeline,csl.findings,csl.conflicts,csl.ws_verifiers,"
        "csl.ws_verifier_grants,csl.ws_verification_requests,csl.ws_verifications TO csl_ws_owner"
    )
    # Row-lock clauses need UPDATE privilege; these functions never change service authority.
    conn.execute("GRANT UPDATE(enabled) ON csl.ws_verifiers TO csl_ws_owner")
    conn.execute("GRANT UPDATE(case_id) ON csl.ws_verifier_grants TO csl_ws_owner")
    conn.execute("GRANT UPDATE(generation) ON csl.pipeline TO csl_ws_owner,csl_vf_owner")
    conn.execute("GRANT SELECT(generation,status) ON csl.jobs TO csl_ws_owner")
    # SHARE-lock the current processing job without changing any job from workspace SQL.
    conn.execute("GRANT UPDATE(status) ON csl.jobs TO csl_ws_owner")
    conn.execute(
        "GRANT SELECT ON csl.schema_migrations,csl.pipeline,csl.cases,csl.case_revisions,"
        "csl.findings,csl.finding_evidence,csl.raw_objects,csl.record_variants,csl.events,"
        "csl.source_references,csl.raw_deliveries,csl.batches,csl.conflicts,"
        "csl.ws_workflows,csl.ws_recommendations,csl.ws_reviews TO csl_vf_owner"
    )
    conn.execute("GRANT UPDATE(current_revision) ON csl.cases TO csl_vf_owner")
    conn.execute("GRANT INSERT ON csl.audit TO csl_vf_owner")
    conn.execute("GRANT USAGE ON SEQUENCE csl.audit_audit_id_seq TO csl_vf_owner")
    conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE csl_vf_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    conn.execute(
        "ALTER DEFAULT PRIVILEGES FOR ROLE csl_vf_owner IN SCHEMA csl "
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    for row in conn.execute("SELECT data_role FROM csl.ws_users WHERE app_role='reviewer'"):
        conn.execute(
            sql.SQL("GRANT csl_ws_reviews TO {} WITH ADMIN FALSE").format(
                sql.Identifier(row["data_role"])
            )
        )


def _login(
    conn: Connection[dict[str, Any]], db: Database, role: str, capabilities: tuple[str, ...]
) -> str:
    # PostgreSQL can otherwise log the full failed password-bearing DDL.
    conn.execute("SET LOCAL log_statement='none'")
    conn.execute("SET LOCAL log_min_error_statement='panic'")
    password = secrets.token_urlsafe(48)
    conn.execute(
        sql.SQL(
            "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD {}"
        ).format(sql.Identifier(role), sql.Literal(password))
    )
    for capability in capabilities:
        conn.execute(
            sql.SQL("GRANT {} TO {} WITH ADMIN FALSE").format(
                sql.Identifier(capability), sql.Identifier(role)
            )
        )
    return make_conninfo(**{**db._values, "user": role, "password": password})


def _database_prefix(conn: Connection[dict[str, Any]]) -> str:
    row = conn.execute("SELECT database_id FROM csl.schema_migrations WHERE version=2").fetchone()
    if not row or row["database_id"] is None:
        raise EvidenceError("WS_SCHEMA")
    return sha256(str(row["database_id"]).encode()).hexdigest()[:12]


def setup_gate(maintenance_db: Database) -> str:
    """Create a database-scoped gate identity with only gate function execution."""
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            prefix = _database_prefix(conn)
            return _login(conn, maintenance_db, f"csl_g_{prefix}_{uuid4().hex}", ("csl_ws_gate",))
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def provision_user(
    maintenance_db: Database, username: str, role: str, password_hash: str
) -> dict[str, str]:
    """Provision two independent SQL identities bound to one enabled account."""
    if (
        not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", username)
        or role not in {"analyst", "reviewer", "auditor"}
        or not 32 <= len(password_hash) <= 512
    ):
        raise EvidenceError("WS_INVALID")
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            conn.execute("LOCK TABLE csl.ws_users IN EXCLUSIVE MODE")
            count = conn.execute("SELECT count(*) AS n FROM csl.ws_users").fetchone()
            assert count is not None
            if count["n"] >= 100:
                raise EvidenceError("WS_LIMIT")
            user_id = uuid4().hex
            prefix = _database_prefix(conn)
            auth_role, data_role = (f"csl_u_{prefix}_{user_id}_{suffix}" for suffix in ("a", "d"))
            auth_dsn = _login(conn, maintenance_db, auth_role, ("csl_ws_auth",))
            capabilities = (
                ("csl_ws_reader", "csl_ws_notes")
                if role == "analyst"
                else ("csl_ws_reader", "csl_ws_reviews")
                if role == "reviewer"
                else ("csl_ws_reader",)
            )
            data_dsn = _login(conn, maintenance_db, data_role, capabilities)
            conn.execute(
                "INSERT INTO csl.ws_users(user_id,username,app_role,password_hash,"
                "auth_role,data_role) VALUES (%s,%s,%s,%s,%s,%s)",
                (user_id, username, role, password_hash, auth_role, data_role),
            )
            return {
                "user_id": user_id,
                "username": username,
                "auth_dsn": auth_dsn,
                "data_dsn": data_dsn,
            }
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def grant_case(maintenance_db: Database, username: str, case_id: str) -> None:
    """Grant one existing case, without following case lineage or merges."""
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            row = conn.execute(
                "INSERT INTO csl.ws_case_grants SELECT user_id,%s FROM "
                "csl.ws_users WHERE username=%s ON CONFLICT DO NOTHING "
                "RETURNING user_id",
                (case_id, username),
            ).fetchone()
            if (
                row is None
                and not conn.execute(
                    "SELECT 1 FROM csl.ws_users WHERE username=%s", (username,)
                ).fetchone()
            ):
                raise EvidenceError("WS_INVALID")
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def disable_user(maintenance_db: Database, username: str) -> None:
    """Disable immediately; existing sessions cease to authorize any operation."""
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            if not conn.execute(
                "UPDATE csl.ws_users SET enabled=false WHERE username=%s RETURNING user_id",
                (username,),
            ).fetchone():
                raise EvidenceError("WS_INVALID")
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def validate_identity(conn: Connection[dict[str, Any]], expected: str) -> None:
    """Reject privileged roles, unexpected memberships and direct object privileges."""
    for role in ROLES:
        stable = conn.execute(
            "SELECT * FROM pg_catalog.pg_roles WHERE rolname=%s", (role,)
        ).fetchone()
        inherited = conn.execute(
            "SELECT 1 FROM pg_catalog.pg_auth_members WHERE member="
            "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s)",
            (role,),
        ).fetchone()
        if stable is None or not _safe_role(stable, login=False) or inherited:
            raise EvidenceError("WS_ROLES_UNSAFE")
    row = conn.execute("SELECT * FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER").fetchone()
    if row is None or not _safe_role(row, login=True) or not row["rolinherit"]:
        raise EvidenceError("WS_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_database d WHERE "
        "d.datname=pg_catalog.current_database() AND (d.datdba="
        "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER) OR "
        "pg_catalog.has_database_privilege(SESSION_USER,d.oid,'CREATE') OR "
        "pg_catalog.has_schema_privilege(SESSION_USER,'public','CREATE') OR "
        "pg_catalog.has_schema_privilege(SESSION_USER,'csl','CREATE') OR EXISTS("
        "SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (has_schema_privilege(SESSION_USER,n.oid,'CREATE') "
        "OR pg_has_role(SESSION_USER,n.nspowner,'USAGE'))))"
    ).fetchone():
        raise EvidenceError("WS_ROLES_UNSAFE")
    identity_row = (
        conn.execute("SELECT csl.ws_identity() AS value").fetchone()
        if expected != ("gate")
        else None
    )
    identity = identity_row["value"] if identity_row else None
    if expected != "gate" and not identity:
        raise EvidenceError("WS_DENIED")
    if identity and identity.get("identity_kind") != expected:
        raise EvidenceError("WS_DENIED")
    allowed = (
        {"csl_ws_gate"}
        if expected == "gate"
        else {"csl_ws_auth"}
        if expected == ("auth")
        else {"csl_ws_reader", "csl_ws_notes"}
        if identity and identity["app_role"] == "analyst"
        else {"csl_ws_reader", "csl_ws_reviews"}
        if identity and identity["app_role"] == "reviewer"
        else {"csl_ws_reader"}
    )
    memberships = conn.execute(
        "SELECT r.rolname,m.admin_option FROM pg_catalog.pg_auth_members m "
        "JOIN pg_catalog.pg_roles r ON r.oid=m.roleid "
        "WHERE m.member=(SELECT oid FROM pg_catalog.pg_roles "
        "WHERE rolname=SESSION_USER)"
    ).fetchall()
    if {r["rolname"] for r in memberships} != allowed or any(
        r["admin_option"] for r in memberships
    ):
        raise EvidenceError("WS_ROLES_UNSAFE")
    bad = conn.execute(
        "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
        "n.oid=c.relnamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (c.relowner="
        "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER) OR "
        "CASE WHEN c.relkind='S' THEN has_sequence_privilege(SESSION_USER,c.oid,"
        "'USAGE,SELECT,UPDATE') WHEN c.relkind IN ('r','v','m','p','f') THEN "
        "has_table_privilege(SESSION_USER,c.oid,'SELECT,INSERT,UPDATE,DELETE,"
        "TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege("
        "SESSION_USER,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') "
        "ELSE false END) LIMIT 1"
    ).fetchone()
    if bad:
        raise EvidenceError("WS_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
        "ON n.oid=p.pronamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (pg_has_role(SESSION_USER,p.proowner,'USAGE') "
        "OR (n.nspname<>'csl' AND p.prosecdef "
        "AND has_function_privilege(SESSION_USER,p.oid,'EXECUTE'))) "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_namespace n "
        "WHERE n.nspname<>'information_schema' AND left(n.nspname,3)<>'pg_' "
        "AND pg_has_role(SESSION_USER,n.nspowner,'USAGE')"
    ).fetchone():
        raise EvidenceError("WS_ROLES_UNSAFE")


def restore_security(maintenance_db: Database) -> None:
    """Trusted no-owner/no-ACL restore repair, preserving original catalog receipts."""
    from cloudsecops_live.database import (
        LATEST_SCHEMA_VERSION,
        _receipt_hash,
        _schema_hash,
        _validate_prefix,
    )

    try:
        with maintenance_db.connect() as conn, conn.transaction():
            rows = conn.execute("SELECT * FROM csl.schema_migrations ORDER BY version").fetchall()
            _validate_prefix(rows)
            if len(rows) != LATEST_SCHEMA_VERSION or rows[-1]["structural_hash"] != _schema_hash(
                conn
            ):
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
            apply_security(conn)
            if rows[-1]["schema_hash"] != _receipt_hash(conn, len(rows)):
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
    except psycopg.Error:
        raise EvidenceError("SCHEMA_INCOMPATIBLE") from None


def provision_verifier(
    maintenance_db: Database, case_id: str, checker_source_digest: str
) -> dict[str, str]:
    """Explicit offline provisioning, with the generated DSN returned only to private custody."""
    if not re.fullmatch(r"[0-9a-f]{64}", case_id) or not re.fullmatch(
        r"[0-9a-f]{64}", checker_source_digest
    ):
        raise EvidenceError("WS_INVALID")
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            conn.execute("LOCK TABLE csl.ws_verifiers IN EXCLUSIVE MODE")
            count = conn.execute("SELECT count(*) AS n FROM csl.ws_verifiers").fetchone()
            assert count is not None
            if count["n"] >= 100:
                raise EvidenceError("WS_LIMIT")
            verifier_id = uuid4().hex
            role = f"csl_v_{_database_prefix(conn)}_{verifier_id}"
            dsn = _login(conn, maintenance_db, role, ("csl_ws_verifier",))
            conn.execute(
                "INSERT INTO csl.ws_verifiers(verifier_id,login_role,case_id,"
                "checker_source_digest) "
                "VALUES (%s,%s,%s,%s)",
                (verifier_id, role, case_id, checker_source_digest),
            )
            conn.execute(
                "INSERT INTO csl.ws_verifier_grants(verifier_id,case_id) VALUES (%s,%s)",
                (verifier_id, case_id),
            )
            return {"verifier_id": verifier_id, "dsn": dsn, "case_id": case_id}
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def disable_verifier(maintenance_db: Database, verifier_id: str) -> None:
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            if not conn.execute(
                "UPDATE csl.ws_verifiers SET enabled=false WHERE verifier_id=%s "
                "RETURNING verifier_id",
                (verifier_id,),
            ).fetchone():
                raise EvidenceError("WS_INVALID")
    except psycopg.Error:
        raise EvidenceError("WS_DATABASE") from None


def validate_verifier_identity(conn: Connection[dict[str, Any]]) -> None:
    """Reject the same catalog hazards as human identities, with a separate exact capability."""
    for role in ROLES:
        row = conn.execute("SELECT * FROM pg_catalog.pg_roles WHERE rolname=%s", (role,)).fetchone()
        if (
            row is None
            or not _safe_role(row, login=False)
            or conn.execute(
                "SELECT 1 FROM pg_catalog.pg_auth_members WHERE member="
                "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s)",
                (role,),
            ).fetchone()
        ):
            raise EvidenceError("WS_ROLES_UNSAFE")
    row = conn.execute("SELECT * FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER").fetchone()
    if row is None or not _safe_role(row, login=True) or not row["rolinherit"]:
        raise EvidenceError("WS_ROLES_UNSAFE")
    memberships = conn.execute(
        "SELECT r.rolname,m.admin_option FROM pg_catalog.pg_auth_members m JOIN "
        "pg_catalog.pg_roles r ON r.oid=m.roleid WHERE m.member="
        "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER)"
    ).fetchall()
    if (
        len(memberships) != 1
        or memberships[0]["rolname"] != "csl_ws_verifier"
        or memberships[0]["admin_option"]
    ):
        raise EvidenceError("WS_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_database d WHERE d.datname=pg_catalog.current_database() "
        "AND (d.datdba=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER) "
        "OR has_database_privilege(SESSION_USER,d.oid,'CREATE') "
        "OR has_schema_privilege(SESSION_USER,'csl','CREATE') "
        "OR has_schema_privilege(SESSION_USER,'public','CREATE') OR EXISTS("
        "SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (has_schema_privilege(SESSION_USER,n.oid,'CREATE') "
        "OR pg_has_role(SESSION_USER,n.nspowner,'USAGE'))))"
    ).fetchone():
        raise EvidenceError("WS_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON "
        "n.oid=c.relnamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (c.relowner="
        "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER) OR CASE "
        "WHEN c.relkind='S' THEN has_sequence_privilege(SESSION_USER,c.oid,'USAGE,SELECT,UPDATE') "
        "WHEN c.relkind IN ('r','v','m','p','f') THEN has_table_privilege(SESSION_USER,c.oid,"
        "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR "
        "has_any_column_privilege(SESSION_USER,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') "
        "ELSE false END)"
    ).fetchone():
        raise EvidenceError("WS_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON "
        "n.oid=p.pronamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (pg_has_role(SESSION_USER,p.proowner,'USAGE') "
        "OR (n.nspname<>'csl' AND p.prosecdef "
        "AND has_function_privilege(SESSION_USER,p.oid,'EXECUTE'))) "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_namespace n "
        "WHERE n.nspname<>'information_schema' AND left(n.nspname,3)<>'pg_' "
        "AND pg_has_role(SESSION_USER,n.nspowner,'USAGE')"
    ).fetchone():
        raise EvidenceError("WS_ROLES_UNSAFE")
    identity = conn.execute("SELECT csl.vf_identity() AS value").fetchone()
    if not identity or not identity["value"]:
        raise EvidenceError("WS_DENIED")
