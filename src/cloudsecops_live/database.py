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

import psycopg
from psycopg import Connection
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

from cloudsecops_live.errors import EvidenceError

_MIGRATION = files("cloudsecops_live").joinpath("sql/001_initial.sql")
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

    def migrate(self) -> None:
        """Initial migration is atomic and rejects unknown pre-existing state."""
        with self.connect() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(7242601103)")
            exists = conn.execute("SELECT to_regnamespace('csl') IS NOT NULL AS present").fetchone()
            if exists and exists["present"]:
                self.check_schema(conn)
                return
            script = _MIGRATION.read_bytes().decode("utf-8")
            conn.execute(script)
            conn.execute(
                "INSERT INTO csl.schema_migrations(version,checksum,schema_hash) VALUES (1,%s,%s)",
                (sha256(script.encode()).hexdigest(), _schema_hash(conn)),
            )
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
            checksum = sha256(_MIGRATION.read_bytes()).hexdigest()
            if len(rows) != 1 or rows[0]["version"] != 1 or rows[0]["checksum"] != checksum:
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
            if rows[0]["schema_hash"] != _schema_hash(conn):
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
            pipeline = conn.execute("SELECT count(*) AS n FROM csl.pipeline").fetchone()
            if not pipeline or pipeline["n"] != 1:
                raise EvidenceError("SCHEMA_INCOMPATIBLE")
        except psycopg.Error:
            raise EvidenceError("SCHEMA_INCOMPATIBLE") from None
