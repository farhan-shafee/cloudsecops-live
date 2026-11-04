"""Serialized, journaled creation for explicitly enrolled disposable tests only."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import uuid
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from types import TracebackType
from typing import Any

from psycopg import sql
from psycopg.conninfo import make_conninfo

from cloudsecops_live.database import Database
from scripts.test_capacity import (
    COUNT_KEYS,
    DEFAULT_LIMITS,
    RESOURCE_KEYS,
    CapacityError,
    Limits,
    evaluate_capacity,
)
from scripts.test_journal import Journal, JournalError
from scripts.test_service import (
    ServiceContract,
    admin_from_environment,
    catalog_counts,
    load,
    observe,
    require_hosted,
    sql_identity,
)

VERSION = "ops1/1"
LOCK_ID = 7242601201


def mask_identifier(name: str) -> None:
    """Register only a generated database name, before it can reach service logs.

    The supervising CLI passes its own Actions stdout pipe explicitly. Private
    pytest output is never interpreted or relayed as workflow commands.
    """
    require_hosted()
    descriptor = os.environ.get("CSL_TEST_MASK_FD", "")
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"csl_test_[a-f0-9]{32}", name)
        or not re.fullmatch(r"[0-9]{1,4}", descriptor)
        or not 3 <= int(descriptor) <= 1024
    ):
        raise CapacityError("PRIVATE_MASK_CHANNEL_UNAVAILABLE")
    try:
        fd = int(descriptor)
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise OSError
        command = ("::add-mask::" + name + "\n").encode("ascii")
        if os.write(fd, command) != len(command):
            raise OSError
    except OSError:
        raise CapacityError("PRIVATE_MASK_CHANNEL_UNAVAILABLE") from None


def source_metadata(root: Path, service: ServiceContract) -> dict[str, Any]:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    ).stdout.splitlines()
    paths = sorted(
        [
            *(root / "scripts").glob("test_*.py"),
            root / "scripts/run_integration.py",
            root / "tests/integration/conftest.py",
        ]
    )
    digest = sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return {
        "source_revision": result[0],
        "source_tree": result[1],
        "harness_version": VERSION,
        "harness_sha256": digest.hexdigest(),
        "cluster_id": service.cluster_id,
        "service_id": service.container_id,
        "volume_id": service.volume_id,
        "postmaster_started": service.postmaster_started,
    }


class Provisioner:
    """Own the fixed-admin-DB advisory lock across the whole test run.

    Test-only fault/observer/limits injection is deliberately Python-only. The
    operator runner exposes no override to bypass the canonical private ledger.
    Other cluster users must not provision concurrently; advisory locks bind only
    cooperating harnesses. Catalog observations are repeated, never inferred.
    """

    def __init__(
        self,
        admin: Database,
        service: ServiceContract,
        journal: Journal,
        observe: Callable[[], dict[str, int]],
        *,
        limits: Limits = DEFAULT_LIMITS,
        fault: Callable[[str], None] | None = None,
        mask: Callable[[str], None] | None = None,
    ) -> None:
        self.admin, self.service, self.journal = admin, service, journal
        self.observe, self.limits = observe, limits
        self.fault = fault or (lambda stage: None)
        self.mask = mask or mask_identifier
        self.conn: Any = None
        self.blocked = False
        self.created: list[str] = []
        self.samples: list[dict[str, int]] = []

    def __enter__(self) -> Provisioner:
        try:
            self.service.validate()
            # Journal safety/identity before even contacting the test service.
            self.journal.__enter__()
            self.conn = self.admin.connect()
            self.conn.autocommit = True
            self._identity()
            row = self.conn.execute(
                "SELECT pg_try_advisory_lock(%s) AS held", (LOCK_ID,)
            ).fetchone()
            if not row["held"]:
                raise CapacityError("HARNESS_BUSY")
            self.preflight()
            return self
        except BaseException:
            self.close()
            raise

    def _identity(self) -> None:
        identity = sql_identity(self.conn)
        if any(
            identity[key] != getattr(self.service, key)
            for key in ("cluster_id", "postmaster_started")
        ):
            raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")

    def preflight(self) -> dict[str, int]:
        if self.blocked:
            raise CapacityError("CREATION_OPERATOR_REVIEW_REQUIRED")
        self._identity()
        counts = catalog_counts(self.conn)
        # Reject a known exhausted cluster without resource-heavy follow-up.
        if counts["database_count"] >= self.limits.max_databases:
            raise CapacityError("CAPACITY_DATABASE_LIMIT")
        if counts["role_count"] + self.limits.role_reserve > self.limits.max_roles:
            raise CapacityError("CAPACITY_ROLE_LIMIT")
        resources = self.observe()
        evaluate_capacity(counts, resources, self.limits)
        if len(self.created) >= self.limits.max_per_run:
            raise CapacityError("CAPACITY_RUN_LIMIT")
        self.samples.append(
            {
                **{key: counts[key] for key in COUNT_KEYS},
                **{key: resources[key] for key in RESOURCE_KEYS},
            }
        )
        return counts

    def create(
        self,
        *,
        migrate: bool = True,
        test: str = "unspecified",
        purpose: str = "migration",
    ) -> Database:
        if purpose not in {"migration", "restore_upgrade", "capacity_probe"}:
            raise CapacityError("INVALID_CREATION_PURPOSE")
        counts = self.preflight()
        name, creation_id = "csl_test_" + uuid.uuid4().hex, uuid.uuid4().hex
        base = {
            "creation_id": creation_id,
            "database_name": name,
            "retention": "retain_operator_review",
        }
        intent = {
            **base,
            "event": "intent",
            "test": test[:256],
            "purpose": purpose,
            "retention": "retain_operator_review",
            **counts,
        }
        attempted = False
        try:
            self.journal.append(intent)  # Must succeed durably before any CREATE.
            self.mask(name)  # Must register before PostgreSQL can log this name.
            self.fault("intent")
            attempted = True
            self.conn.execute(
                sql.SQL("CREATE DATABASE {} TEMPLATE template0 ALLOW_CONNECTIONS false").format(
                    sql.Identifier(name)
                )
            )
            row = self.conn.execute(
                "SELECT oid::bigint AS oid, pg_get_userbyid(datdba) AS owner, datallowconn "
                "FROM pg_catalog.pg_database WHERE datname=%s",
                (name,),
            ).fetchone()
            if not row or row["owner"] != self.admin._values["user"] or row["datallowconn"]:
                raise CapacityError("CREATED_DATABASE_IDENTITY_MISMATCH")
            base.update({"oid": row["oid"], "owner": row["owner"]})
            self.created.append(name)
            self.journal.append({**base, "event": "created", "outcome": "connections_disabled"})
            self.fault("created")
            self.conn.execute(
                sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
            )
            self.fault("acl")
            row = self.conn.execute(
                "SELECT datallowconn, EXISTS(SELECT FROM aclexplode("
                "coalesce(datacl,acldefault('d',datdba))) WHERE grantee=0 "
                "AND privilege_type='CONNECT') AS public_access "
                "FROM pg_catalog.pg_database WHERE datname=%s AND oid=%s "
                "AND pg_get_userbyid(datdba)=%s",
                (name, base["oid"], base["owner"]),
            ).fetchone()
            if not row or row["datallowconn"] or row["public_access"]:
                raise CapacityError("CREATION_QUARANTINE_FAILED")
            self.journal.append({**base, "event": "quarantined", "outcome": "owner_only_connect"})
            self.fault("quarantined")
            self.conn.execute(
                sql.SQL("ALTER DATABASE {} ALLOW_CONNECTIONS true").format(sql.Identifier(name))
            )
            self.fault("enabled")
            self.journal.append({**base, "event": "ready", "outcome": "owner_connection_enabled"})
            self.fault("ready")
            db = Database(make_conninfo(**{**self.admin._values, "dbname": name}))
            if migrate:
                from cloudsecops_live.workspace_roles import setup_roles

                setup_roles(db)
                db.migrate()
            self.journal.append(
                {
                    **base,
                    "event": "provisioned",
                    "outcome": "migration_complete" if migrate else "unmigrated_target_ready",
                }
            )
            self.fault("provisioned")
            return db
        except BaseException as exc:
            self.blocked = True
            # Never reconnect to infer an interrupted CREATE outcome or adopt it.
            # A failed append may leave a durable intent/torn tail, also blocking.
            try:
                if any(r.get("creation_id") == creation_id for r in self.journal.records):
                    self.journal.append(
                        {
                            **base,
                            "event": "uncertain" if attempted else "failed",
                            "outcome": "operator_review_required",
                        }
                    )
            except JournalError:
                pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise CapacityError("CREATION_OPERATOR_REVIEW_REQUIRED") from None

    def public_summary(self) -> dict[str, Any]:
        keys = self.samples[0].keys() if self.samples else ()
        return {
            "harness_version": VERSION,
            "retained_databases_created": len(self.created),
            "samples": len(self.samples),
            "operator_review_required": self.blocked,
            "observed_min": {key: min(row[key] for row in self.samples) for key in keys},
            "observed_max": {key: max(row[key] for row in self.samples) for key in keys},
            "cleanup": "none",
        }

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()  # Session lock automatically released, including crashes.
            self.conn = None
        self.journal.close()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.journal.__exit__(exc_type, exc, traceback)
        finally:
            if self.conn is not None:
                self.conn.close()
                self.conn = None


def build_provisioner(
    root: Path,
    *,
    journal_directory: Path | None = None,
    fault: Callable[[str], None] | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> Provisioner:
    admin, service = admin_from_environment(), load(root)
    directory = journal_directory or root / ".tools/private/test-harness/creation-ledger"
    journal = Journal(directory, uuid.uuid4().hex, source_metadata(root, service))
    return Provisioner(
        admin, service, journal, lambda: observe(root, service), limits=limits, fault=fault
    )
