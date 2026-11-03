"""Project-local PostgreSQL connection and explicit checksum migrations.

The owner can bypass database triggers. They protect routine application writes;
this schema makes no tamper-proof or authenticated-source claim.
"""

from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from importlib.resources import files
from typing import Any
from uuid import uuid4

import psycopg
from psycopg import Connection
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

from cloudsecops_live.errors import EvidenceError

_MIGRATION = files("cloudsecops_live").joinpath("sql/001_initial.sql")
_MIGRATIONS = (_MIGRATION, files("cloudsecops_live").joinpath("sql/002_workspace.sql"))
LATEST_SCHEMA_VERSION = len(_MIGRATIONS)
_ALLOWED = {"host", "port", "dbname", "user", "password", "connect_timeout", "application_name"}


def _schema_hash(conn: Connection[dict[str, Any]]) -> str:
    """A restore-stable catalog fingerprint, including constraints and trigger bodies."""
    rows = conn.execute(
        """SELECT 'column' AS kind, c.relname AS name, a.attname AS item,
                  format_type(a.atttypid,a.atttypmod) || ':' || a.attnotnull::text || ':' ||
                  coalesce(pg_get_expr(d.adbin,d.adrelid),'') AS definition
           FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           JOIN pg_attribute a ON a.attrelid=c.oid
           LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
           WHERE n.nspname='csl' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
           UNION ALL
           SELECT 'relation',c.relname,'',c.relkind::text
           FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='csl'
           UNION ALL
           SELECT 'index',c.relname,'',pg_get_indexdef(c.oid)
           FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='csl' AND c.relkind='i'
           UNION ALL
           SELECT 'constraint',c.relname,k.conname,pg_get_constraintdef(k.oid)
           FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
           JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='csl'
           UNION ALL
           SELECT 'trigger',c.relname,t.tgname,pg_get_triggerdef(t.oid) || ':' || t.tgenabled::text
           FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
           JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='csl' AND NOT t.tgisinternal
           UNION ALL
           SELECT 'function',p.proname,'',pg_get_functiondef(p.oid)
           FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='csl'
           ORDER BY 1,2,3,4"""
    ).fetchall()
    return sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _security_hash(conn: Connection[dict[str, Any]]) -> str:
    """Bind the structural receipt to ownership, effective ACLs and default ACLs."""
    rows = conn.execute(
        """SELECT 'relation' AS kind,c.relname AS name,
        pg_catalog.pg_get_userbyid(c.relowner) AS owner,
        coalesce(c.relacl::text,'') AS acl FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='csl'
        UNION ALL SELECT 'column',c.relname||'.'||a.attname,
        pg_catalog.pg_get_userbyid(c.relowner),coalesce(a.attacl::text,'')
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='csl' AND a.attnum>0 AND NOT a.attisdropped
        UNION ALL SELECT 'function',p.oid::regprocedure::text,
        pg_catalog.pg_get_userbyid(p.proowner),coalesce(p.proacl::text,'')||':'||
        p.prosecdef::text||':'||coalesce(p.proconfig::text,'')
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='csl'
        UNION ALL SELECT 'schema',n.nspname,pg_catalog.pg_get_userbyid(n.nspowner),
        coalesce(n.nspacl::text,'') FROM pg_catalog.pg_namespace n
        WHERE n.nspname IN ('csl','public')
        UNION ALL SELECT 'database','current',pg_catalog.pg_get_userbyid(d.datdba),
        coalesce(d.datacl::text,'') FROM pg_catalog.pg_database d
        WHERE d.datname=pg_catalog.current_database()
        UNION ALL SELECT 'default',d.defaclobjtype::text,pg_catalog.pg_get_userbyid(d.defaclrole),
        d.defaclacl::text FROM pg_catalog.pg_default_acl d
        JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname='csl'
        UNION ALL SELECT 'default_global',d.defaclobjtype::text,
        pg_catalog.pg_get_userbyid(d.defaclrole),d.defaclacl::text
        FROM pg_catalog.pg_default_acl d
        WHERE d.defaclnamespace=0 AND d.defaclobjtype='f' AND d.defaclrole=
        (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='csl_ws_owner')
        ORDER BY 1,2,3,4"""
    ).fetchall()
    return sha256(
        (_schema_hash(conn) + json.dumps(rows, sort_keys=True, separators=(",", ":"))).encode()
    ).hexdigest()


def _validate_prefix(rows: list[dict[str, Any]]) -> None:
    if not rows or len(rows) > len(_MIGRATIONS):
        raise EvidenceError("SCHEMA_INCOMPATIBLE")
    for version, row in enumerate(rows, 1):
        source = _MIGRATION if version == 1 else _MIGRATIONS[version - 1]
        if row["version"] != version or row["checksum"] != sha256(source.read_bytes()).hexdigest():
            raise EvidenceError("SCHEMA_INCOMPATIBLE")


class Database:
    """An explicit lab/test DSN; never resolve hosts or follow libpq services."""

    def __init__(self, dsn: str) -> None:
        try:
            values = {k: str(v) for k, v in conninfo_to_dict(dsn).items()}
            if (
                set(values) - _ALLOWED
                or values.get("host") not in {"127.0.0.1", "::1"}
                or not re.fullmatch(
                    r"cloudsecops_lab|csl_test_[a-z0-9_]+", values.get("dbname", "")
                )
                or not 1 <= int(values.get("port", "5432")) <= 65535
                or not 1 <= int(values.get("connect_timeout", "5")) <= 10
                or len(values.get("application_name", "")) > 128
            ):
                raise ValueError
        except (psycopg.Error, ValueError, TypeError):
            raise EvidenceError("UNSAFE_DATABASE_DSN") from None
        self._values = values

    def connect(self) -> Connection[dict[str, Any]]:
        # PGSERVICE can supply arbitrary options/SSL paths even with explicit host.
        if any(os.environ.get(key) for key in ("PGSERVICE", "PGSERVICEFILE")):
            raise EvidenceError("UNSAFE_DATABASE_ENVIRONMENT")
        values = {
            **self._values,
            "hostaddr": self._values["host"],
            "password": self._values.get("password", ""),
            "connect_timeout": self._values.get("connect_timeout", "5"),
            "sslmode": "disable",
            "gssencmode": "disable",
            "passfile": os.devnull,
            "options": "-c search_path=pg_catalog -c statement_timeout=30000 -c lock_timeout=10000",
        }
        conn = psycopg.connect(make_conninfo(**values), row_factory=dict_row)
        if not 170011 <= conn.info.server_version < 180000:
            conn.close()
            raise EvidenceError("UNSUPPORTED_DATABASE_VERSION")
        return conn

    def migrate(self, *, target_version: int | None = None) -> None:
        """Apply a verified forward-only checksum prefix in one atomic transaction."""
        target = len(_MIGRATIONS) if target_version is None else target_version
        if type(target) is not int or not 1 <= target <= len(_MIGRATIONS):
            raise EvidenceError("SCHEMA_INCOMPATIBLE")
        with self.connect() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(7242601103)")
            exists = conn.execute("SELECT to_regnamespace('csl') IS NOT NULL AS present").fetchone()
            if exists and exists["present"]:
                try:
                    ledger = conn.execute(
                        "SELECT to_regclass('csl.schema_migrations') AS found"
                    ).fetchone()
                    if not ledger or not ledger["found"]:
                        raise EvidenceError("SCHEMA_MISSING")
                    rows = conn.execute(
                        "SELECT version,checksum,schema_hash FROM "
                        "csl.schema_migrations ORDER BY version"
                    ).fetchall()
                    _validate_prefix(rows)
                    actual = _schema_hash(conn) if len(rows) == 1 else _security_hash(conn)
                    if rows[-1]["schema_hash"] != actual or target < len(rows):
                        raise EvidenceError("SCHEMA_INCOMPATIBLE")
                except psycopg.Error:
                    raise EvidenceError("SCHEMA_INCOMPATIBLE") from None
            else:
                rows = []
            for version in range(len(rows) + 1, target + 1):
                source = _MIGRATION if version == 1 else _MIGRATIONS[version - 1]
                script = source.read_bytes().decode("utf-8")
                conn.execute(script)
                if version == 2:
                    from cloudsecops_live.workspace_roles import apply_security

                    apply_security(conn)
                    conn.execute(
                        "INSERT INTO csl.schema_migrations(version,checksum,schema_hash,"
                        "structural_hash,database_id) VALUES (%s,%s,%s,%s,%s)",
                        (
                            version,
                            sha256(script.encode()).hexdigest(),
                            _security_hash(conn),
                            _schema_hash(conn),
                            uuid4(),
                        ),
                    )
                else:
                    conn.execute(
                        "INSERT INTO csl.schema_migrations(version,checksum,schema_hash) "
                        "VALUES (1,%s,%s)",
                        (sha256(script.encode()).hexdigest(), _schema_hash(conn)),
                    )
            if target == len(_MIGRATIONS):
                self.check_schema(conn)

    @staticmethod
    def check_schema(conn: Connection[dict[str, Any]]) -> None:
        try:
            exists = conn.execute(
                "SELECT to_regclass('csl.schema_migrations') IS NOT NULL AS present"
            ).fetchone()
            if not exists or not exists["present"]:
                raise EvidenceError("SCHEMA_MISSING")
            rows = conn.execute(
                "SELECT version,checksum,schema_hash FROM csl.schema_migrations ORDER BY version"
            ).fetchall()
            _validate_prefix(rows)
            if len(rows) != len(_MIGRATIONS):
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
            if rows[-1]["schema_hash"] != _security_hash(conn):
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
            pipeline = conn.execute("SELECT count(*) AS n FROM csl.pipeline").fetchone()
            if not pipeline or pipeline["n"] != 1:
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
        except psycopg.Error:
            raise EvidenceError("SCHEMA_INCOMPATIBLE") from None
