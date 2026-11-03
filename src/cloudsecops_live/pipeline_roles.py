"""Explicit collector/worker credentials and a fixed machine-only SQL privilege matrix."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from psycopg import Connection, sql

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_roles import ROLES, _database_prefix, _login, _safe_role
from cloudsecops_live.workspace_tls import private_file

KINDS = {"collector", "worker"}
SOURCE_READS = (
    "schema_migrations",
    "pipeline",
    "batches",
    "checkpoints",
    "raw_objects",
    "raw_deliveries",
    "events",
    "record_variants",
    "source_references",
    "conflicts",
)
COLLECTOR_INSERT = {
    "batches": (
        "batch_id",
        "checkpoint",
        "request_hash",
        "status",
        "generation",
        "accepted_count",
        "duplicate_count",
        "conflicting_count",
        "source_count",
    ),
    "checkpoints": ("checkpoint", "batch_id", "generation"),
    "raw_objects": (
        "raw_id",
        "source_ref",
        "archive_bytes",
        "archive_hash",
        "content_hash",
        "expanded_size",
        "record_count",
    ),
    "raw_deliveries": ("batch_id", "raw_id", "source_ref"),
    "events": ("event_key", "source_kind", "account", "region", "event_id"),
    "record_variants": ("event_key", "record_hash", "canonical_bytes", "normalized"),
    "source_references": (
        "batch_id",
        "raw_id",
        "source_ref",
        "record_index",
        "event_key",
        "record_hash",
    ),
    "conflicts": ("event_key", "detected_generation"),
    "ingestion_errors": ("checkpoint", "code"),
    "jobs": ("job_id", "generation"),
}
WORKER_INSERT = {
    "job_attempts": ("job_id", "attempt", "token"),
    "findings": ("finding_id", "payload", "generation", "status"),
    "finding_evidence": ("finding_id", "event_key", "record_hash"),
    "cases": ("case_id", "current_revision", "status"),
    "case_revisions": (
        "case_id",
        "revision",
        "payload",
        "fingerprint",
        "finding_id",
        "generation",
        "status",
    ),
    "case_timeline": ("case_id", "revision", "kind", "payload"),
    "case_lineage": ("parent_case_id", "child_case_id", "generation"),
    "outbox": ("outbox_id", "idempotency_key", "case_id", "revision", "payload"),
    "offline_sink": ("idempotency_key", "payload", "payload_hash"),
}
COLLECTOR_UPDATE = {"pipeline": ("generation",), "findings": ("status",), "cases": ("status",)}
WORKER_UPDATE = {
    "pipeline": ("published_generation",),
    "jobs": ("status", "claim_token", "lease_until", "attempts", "last_error", "completed_at"),
    "job_attempts": ("result", "finished_at"),
    "findings": ("status",),
    "cases": ("current_revision", "status"),
    "outbox": ("status", "attempts", "claim_token", "lease_until", "last_error", "acknowledged_at"),
}
WORKER_READS = (
    *SOURCE_READS,
    "jobs",
    "findings",
    "finding_evidence",
    "cases",
    "case_revisions",
    "case_timeline",
    "case_lineage",
    "outbox",
    "offline_sink",
)


def privilege_matrix(kind: str) -> set[tuple[str, str, str, str]]:
    """Exact catalog grants: schema, relation, column (empty for table/sequence), privilege."""
    if kind not in KINDS:
        raise EvidenceError("PIPE_INVALID")
    result = {
        ("csl", table, "", "SELECT")
        for table in (SOURCE_READS if kind == "collector" else WORKER_READS)
    }
    result.add(("csl", "ingestion_errors", "error_id", "SELECT"))
    selects = (
        {"findings": ("status",), "cases": ("status",)}
        if kind == "collector"
        else {"job_attempts": ("job_id", "attempt", "token")}
    )
    for privilege, tables in (
        ("SELECT", selects),
        ("INSERT", COLLECTOR_INSERT if kind == "collector" else WORKER_INSERT),
        ("UPDATE", COLLECTOR_UPDATE if kind == "collector" else WORKER_UPDATE),
    ):
        result.update(
            ("csl", table, column, privilege)
            for table, columns in tables.items()
            for column in columns
        )
    sequence = (
        "ingestion_errors_error_id_seq" if kind == "collector" else "case_timeline_timeline_id_seq"
    )
    result.add(("csl", sequence, "", "USAGE"))
    return result


def capability_names(conn: Connection[dict[str, Any]]) -> dict[str, str]:
    prefix = _database_prefix(conn)
    return {"collector": f"csl_pc_{prefix}", "worker": f"csl_pw_{prefix}"}


def apply_pipeline_security(conn: Connection[dict[str, Any]]) -> None:
    """Restore the one reviewed fixed grant matrix; dynamic LOGINs own nothing."""
    database = sql.Identifier(conn.info.dbname)
    names = capability_names(conn)
    capabilities = sql.SQL(",").join(sql.Identifier(name) for name in names.values())
    conn.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, capabilities))
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA csl TO {}").format(capabilities))
    conn.execute(sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(capabilities))
    conn.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA csl FROM {}").format(capabilities))
    conn.execute(sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA csl FROM {}").format(capabilities))
    conn.execute(
        sql.SQL("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA csl FROM {}").format(capabilities)
    )
    public_functions = ("csl.pi_identity()", "csl.pi_audit(text,jsonb)")
    for signature in (*public_functions, "csl.pi_actor()", "csl.pi_write_guard()"):
        conn.execute(sql.SQL("ALTER FUNCTION {} OWNER TO csl_ws_owner").format(sql.SQL(signature)))
        conn.execute(
            sql.SQL("REVOKE EXECUTE ON FUNCTION {} FROM PUBLIC").format(sql.SQL(signature))
        )
        if signature in public_functions:
            conn.execute(
                sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                    sql.SQL(signature), capabilities
                )
            )
    for kind, role in names.items():
        for _, table, column, privilege in sorted(privilege_matrix(kind)):
            object_name = sql.Identifier("csl", table)
            privilege_name: sql.Composable = sql.SQL(privilege)
            if column:
                privilege_name = sql.SQL("{}({})").format(privilege_name, sql.Identifier(column))
            object_type = sql.SQL("SEQUENCE ") if privilege == "USAGE" else sql.SQL("")
            conn.execute(
                sql.SQL("GRANT {} ON {}{} TO {}").format(
                    privilege_name, object_type, object_name, sql.Identifier(role)
                )
            )


def provision_pipeline(maintenance_db: Database, kind: str) -> dict[str, str]:
    if kind not in KINDS:
        raise EvidenceError("PIPE_INVALID")
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            conn.execute("LOCK TABLE csl.ws_pipeline_identities IN EXCLUSIVE MODE")
            row = conn.execute("SELECT count(*) AS n FROM csl.ws_pipeline_identities").fetchone()
            if row is None or row["n"] >= 100:
                raise EvidenceError("PIPE_LIMIT")
            pipeline_id = uuid4().hex
            role = f"csl_p_{_database_prefix(conn)}_{pipeline_id}_{kind[0]}"
            dsn = _login(conn, maintenance_db, role, (capability_names(conn)[kind],))
            conn.execute(
                "INSERT INTO csl.ws_pipeline_identities(pipeline_id,login_role,kind) "
                "VALUES (%s,%s,%s)",
                (pipeline_id, role, kind),
            )
            return {"pipeline_id": pipeline_id, "kind": kind, "dsn": dsn}
    except psycopg.Error:
        raise EvidenceError("PIPE_DATABASE") from None


def disable_pipeline(maintenance_db: Database, pipeline_id: str) -> None:
    if not isinstance(pipeline_id, str) or not re.fullmatch(r"[0-9a-f]{32}", pipeline_id):
        raise EvidenceError("PIPE_INVALID")
    try:
        with maintenance_db.connect() as conn, conn.transaction():
            Database.check_schema(conn)
            row = conn.execute(
                "UPDATE csl.ws_pipeline_identities SET enabled=false WHERE pipeline_id=%s "
                "RETURNING login_role,kind",
                (pipeline_id,),
            ).fetchone()
            if row is None:
                raise EvidenceError("PIPE_INVALID")
            conn.execute(sql.SQL("ALTER ROLE {} NOLOGIN").format(sql.Identifier(row["login_role"])))
            conn.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(capability_names(conn)[row["kind"]]),
                    sql.Identifier(row["login_role"]),
                )
            )
    except psycopg.Error:
        raise EvidenceError("PIPE_DATABASE") from None


def validate_pipeline_identity(
    conn: Connection[dict[str, Any]], kind: str, expected_id: str | None = None
) -> dict[str, Any]:
    if kind not in KINDS:
        raise EvidenceError("PIPE_INVALID")
    names = capability_names(conn)
    for role in (*ROLES, *names.values()):
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
            raise EvidenceError("PIPE_ROLES_UNSAFE")
    session_role = conn.execute(
        "SELECT * FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER"
    ).fetchone()
    if (
        session_role is None
        or not _safe_role(session_role, login=True)
        or not session_role["rolinherit"]
    ):
        raise EvidenceError("PIPE_ROLES_UNSAFE")
    memberships = conn.execute(
        "SELECT r.rolname,m.admin_option FROM pg_catalog.pg_auth_members m JOIN "
        "pg_catalog.pg_roles r ON r.oid=m.roleid WHERE m.member="
        "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER)"
    ).fetchall()
    if (
        len(memberships) != 1
        or memberships[0]["rolname"] != names[kind]
        or memberships[0]["admin_option"]
    ):
        raise EvidenceError("PIPE_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_database d WHERE d.datname=pg_catalog.current_database() "
        "AND (pg_has_role(SESSION_USER,d.datdba,'USAGE') "
        "OR has_database_privilege(SESSION_USER,d.oid,'CREATE')) UNION ALL "
        "SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (pg_has_role(SESSION_USER,n.nspowner,'USAGE') "
        "OR has_schema_privilege(SESSION_USER,n.oid,'CREATE'))"
    ).fetchone():
        raise EvidenceError("PIPE_ROLES_UNSAFE")
    if conn.execute(
        "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND pg_has_role(SESSION_USER,c.relowner,'USAGE') "
        "UNION ALL SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
        "ON n.oid=p.pronamespace WHERE n.nspname<>'information_schema' "
        "AND left(n.nspname,3)<>'pg_' AND (pg_has_role(SESSION_USER,p.proowner,'USAGE') OR "
        "(has_function_privilege(SESSION_USER,p.oid,'EXECUTE') AND "
        "((n.nspname='csl' AND p.oid::regprocedure::text NOT IN "
        "('csl.pi_identity()','csl.pi_audit(text,jsonb)')) OR "
        "(n.nspname<>'csl' AND p.prosecdef))))"
    ).fetchone():
        raise EvidenceError("PIPE_ROLES_UNSAFE")
    # Exact ACL origins matter: duplicate direct/PUBLIC grants are not silently accepted.
    rows = conn.execute(
        """WITH allowed AS (
      SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN (SESSION_USER,%s)
    ), relations AS (
      SELECT n.nspname,c.relname,c.oid,c.relowner,c.relacl,c.relkind
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname<>'information_schema' AND left(n.nspname,3)<>'pg_'
      AND c.relkind IN ('r','v','m','p','f','S')
    ) SELECT nspname,relname,'' AS col,a.privilege_type,a.grantee,a.is_grantable
      FROM relations c CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(c.relacl,
      pg_catalog.acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,
      c.relowner))) a WHERE a.grantee=0 OR a.grantee IN (SELECT oid FROM allowed)
    UNION ALL SELECT nspname,relname,att.attname,a.privilege_type,a.grantee,a.is_grantable
      FROM relations c JOIN pg_catalog.pg_attribute att ON att.attrelid=c.oid
      AND att.attnum>0 AND NOT att.attisdropped
      CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a
      WHERE a.grantee=0 OR a.grantee IN (SELECT oid FROM allowed)""",
        (names[kind],),
    ).fetchall()
    capability = conn.execute(
        "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s", (names[kind],)
    ).fetchone()
    assert capability is not None
    actual = {(r["nspname"], r["relname"], r["col"], r["privilege_type"]) for r in rows}
    if actual != privilege_matrix(kind) or any(
        r["grantee"] != capability["oid"] or r["is_grantable"] for r in rows
    ):
        raise EvidenceError("PIPE_ROLES_UNSAFE")
    identity_row = conn.execute("SELECT csl.pi_identity() AS value").fetchone()
    identity = identity_row["value"] if identity_row else None
    if (
        not identity
        or identity["kind"] != kind
        or (expected_id is not None and identity["pipeline_id"] != expected_id)
    ):
        raise EvidenceError("PIPE_DENIED")
    return dict(identity)


class PipelineDatabase(Database):
    """Validate one real machine identity before each independent transaction begins."""

    def __init__(self, dsn: str, pipeline_id: str, kind: str) -> None:
        super().__init__(dsn)
        self.pipeline_id, self.kind = pipeline_id, kind

    def connect(self) -> Connection[dict[str, Any]]:
        conn = super().connect()
        try:
            with conn.transaction():
                Database.check_schema(conn)
                validate_pipeline_identity(conn, self.kind, self.pipeline_id)
            return conn
        except Exception:
            conn.close()
            raise


def _unique_pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate_pipeline_config_key")
        result[key] = value
    return result


def load_pipeline_config(path: str | Path, expected_kind: str) -> PipelineDatabase:
    try:
        value = json.loads(
            private_file(Path(path), max_bytes=65536), object_pairs_hook=_unique_pairs
        )
        if (
            not isinstance(value, dict)
            or set(value) != {"pipeline_id", "kind", "dsn"}
            or expected_kind not in KINDS
            or value.get("kind") != expected_kind
            or not isinstance(value.get("pipeline_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["pipeline_id"])
            or not isinstance(value.get("dsn"), str)
        ):
            raise ValueError
        return PipelineDatabase(value["dsn"], value["pipeline_id"], expected_kind)
    except (OSError, ValueError, TypeError, EvidenceError):
        raise EvidenceError("PIPE_CONFIG") from None
