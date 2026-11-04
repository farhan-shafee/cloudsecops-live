"""Explicit hosted disposable-service enrollment and read-only observations.

Local services are deliberately unsupported in this milestone. Environment labels
are an operator boundary, not an authentication mechanism against the host owner.
Never read Docker Config.Env or fall back to retained project configurations.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path
from typing import Any

import psycopg

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from scripts.local_postgres import (
    IMAGE,
    Docker,
    LocalPostgresError,
    _restrict_directory,
    _safe_path,
    _write_private,
)
from scripts.test_capacity import CapacityError, evaluate_capacity

# Fixed read-only commands, no caller paths/commands interpolated into a shell.
PROBE = r"""set -eu
printf 'CSL_DATA_DISK\n'
df -Pk /var/lib/postgresql/data
printf 'CSL_SHM_DISK\n'
df -Pk /dev/shm
printf 'CSL_CGROUP\n'
cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current
cat /sys/fs/cgroup/memory.stat /sys/fs/cgroup/memory.events
cat /sys/fs/cgroup/pids.current /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max
"""


def _disk_row(lines: list[str]) -> int:
    # The validated operand and frame bind the measurement. df's display mount
    # label may name a different bind on the same filesystem; it is not identity.
    if len(lines) != 2 or not lines[0].startswith("Filesystem "):
        raise ValueError
    fields = lines[1].split()
    if len(fields) != 6 or not fields[-1].startswith("/"):
        raise ValueError
    if any(not re.fullmatch(r"[0-9]{1,20}", part) for part in fields[1:4]):
        raise ValueError
    total, used, free = map(int, fields[1:4])
    if total <= 0 or used > total or free > total or used + free > total:
        raise ValueError
    if not re.fullmatch(r"(?:100|[0-9]{1,2})%", fields[4]):
        raise ValueError
    return free * 1024


def sanitized[**P, T](function: Callable[P, T]) -> Callable[P, T]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return function(*args, **kwargs)
        except CapacityError:
            raise
        except (
            OSError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            AttributeError,
            LocalPostgresError,
            psycopg.Error,
            EvidenceError,
            subprocess.SubprocessError,
        ):
            raise CapacityError("TEST_SERVICE_OBSERVATION_FAILED") from None

    return call


def require_hosted() -> None:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Linux"
    ):
        raise CapacityError("DISPOSABLE_HOSTED_SERVICE_REQUIRED")


def admin_from_environment() -> Database:
    require_hosted()  # Before reading a DSN or making any connection.
    value = os.environ.get("CSL_TEST_DSN", "")
    db = Database(value)
    if (
        db._values.get("host") != "127.0.0.1"
        or db._values.get("port", "5432") != "5432"
        or db._values.get("dbname") != "cloudsecops_lab"
        or db._values.get("user") != "cloudsecops_ci"
        or any(os.environ.get(k) for k in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"))
    ):
        raise CapacityError("TEST_SERVICE_DSN_MISMATCH")
    return db


@dataclass(frozen=True)
class ServiceContract:
    container_id: str
    image_id: str
    volume_id: str
    cluster_id: str
    postmaster_started: str
    run_scope: str

    def validate(self) -> None:
        if (
            not re.fullmatch(r"[a-f0-9]{64}", self.container_id)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id)
            or not re.fullmatch(r"[a-f0-9]{64}", self.volume_id)
            or not re.fullmatch(r"[0-9]{1,20}", self.cluster_id)
            or not self.postmaster_started
            or len(self.postmaster_started) > 64
            or self.run_scope != run_scope()
        ):
            raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")


def run_scope() -> str:
    values = [os.environ.get(k, "") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")]
    if not all(re.fullmatch(r"[A-Za-z0-9_-]{1,100}", value) for value in values):
        raise CapacityError("TEST_SERVICE_SCOPE_MISSING")
    return ":".join(values)


@sanitized
def _run(root: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        [*Docker(root).prefix, *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode or len(result.stdout) > 65536:
        raise CapacityError("TEST_SERVICE_OBSERVATION_FAILED")
    return result.stdout


@sanitized
def inspect_service(root: Path, container_id: str) -> dict[str, Any]:
    require_hosted()
    if not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise CapacityError("TEST_SERVICE_IDENTITY_MISSING")
    # Selected fields only; no credentials, environment or logging configuration.
    template = (
        '{"Id":{{json .Id}},"Image":{{json .Image}},'
        '"ConfiguredImage":{{json .Config.Image}},'
        '"State":{"Running":{{.State.Running}},"OOMKilled":{{.State.OOMKilled}},'
        '"Health":{"Status":{{json .State.Health.Status}}}},'
        '"Mounts":{{json .Mounts}},"Memory":{{.HostConfig.Memory}},'
        '"NanoCpus":{{.HostConfig.NanoCpus}},"PidsLimit":{{.HostConfig.PidsLimit}},'
        '"ShmSize":{{.HostConfig.ShmSize}},"Ports":{{json .NetworkSettings.Ports}}}'
    )
    result: dict[str, Any] = json.loads(_run(root, ["inspect", "--format", template, container_id]))
    if (
        result["Id"] != container_id
        or result["ConfiguredImage"] != IMAGE
        or not result["State"]["Running"]
        or result["State"]["OOMKilled"]
        or result["State"].get("Health", {}).get("Status") != "healthy"
        or result["Memory"] != 512 * 1024**2
        or result["NanoCpus"] != 1_000_000_000
        or result["PidsLimit"] != 128
        or result["ShmSize"] != 64 * 1024**2
        or result["Ports"].get("5432/tcp") != [{"HostIp": "127.0.0.1", "HostPort": "5432"}]
    ):
        raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")
    from hashlib import sha256

    mounts = [m for m in result["Mounts"] if m["Destination"] == "/var/lib/postgresql/data"]
    if (
        len(mounts) != 1
        or mounts[0]["Type"] != "volume"
        or not re.fullmatch(r"[a-f0-9]{64}", mounts[0]["Name"])
        or mounts[0]["Source"] != "/var/lib/docker/volumes/" + mounts[0]["Name"] + "/_data"
    ):
        raise CapacityError("TEST_SERVICE_VOLUME_MISMATCH")
    result["volume_id"] = sha256(json.dumps(mounts[0], sort_keys=True).encode()).hexdigest()
    return result


def sql_identity(conn: Any) -> dict[str, str]:
    row: dict[str, str] = conn.execute(
        "SELECT system_identifier::text AS cluster_id, "
        "pg_postmaster_start_time()::text AS postmaster_started, "
        "current_user AS owner, current_database() AS database, "
        "current_setting('log_parameter_max_length_on_error') AS error_parameters "
        "FROM pg_catalog.pg_control_system()"
    ).fetchone()
    if not row or row["owner"] != "cloudsecops_ci" or row["database"] != "cloudsecops_lab":
        raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")
    if row.get("error_parameters") != "0":
        raise CapacityError("TEST_SERVICE_LOGGING_UNSAFE")
    return row


def catalog_counts(conn: Any) -> dict[str, int]:
    row: dict[str, int] = conn.execute(
        "SELECT (SELECT count(*) FROM pg_catalog.pg_database)::int AS database_count, "
        "(SELECT count(*) FROM pg_catalog.pg_roles)::int AS role_count"
    ).fetchone()
    return row


@sanitized
def observe(root: Path, service: ServiceContract) -> dict[str, int]:
    service.validate()
    actual = inspect_service(root, service.container_id)
    if actual["Image"] != service.image_id or actual["volume_id"] != service.volume_id:
        raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")
    text = _run(root, ["exec", service.container_id, "sh", "-c", PROBE])
    lines = text.splitlines()
    stage = "DATA_FILESYSTEM"
    try:
        if lines.count("CSL_DATA_DISK") != 1 or lines[0] != "CSL_DATA_DISK":
            raise ValueError
        shm_start = lines.index("CSL_SHM_DISK")
        data_free = _disk_row(lines[1:shm_start])
        stage = "SHARED_FILESYSTEM"
        cgroup_start = lines.index("CSL_CGROUP")
        if lines.count("CSL_SHM_DISK") != 1 or lines.count("CSL_CGROUP") != 1:
            raise ValueError
        shm_free = _disk_row(lines[shm_start + 1 : cgroup_start])
        tail = lines[cgroup_start + 1 :]
        stage = "MEMORY_COUNTERS"
        memory_limit, memory_current = int(tail[0]), int(tail[1])
        stage = "MEMORY_EVENTS"
        pairs = {parts[0]: int(parts[1]) for line in tail[2:-3] if len(parts := line.split()) == 2}
        stage = "PID_CPU"
        pids_current, pids_limit = int(tail[-3]), int(tail[-2])
        quota, period = (int(part) for part in tail[-1].split())
        stage = "BACKING_DISK"
        backing = shutil.disk_usage("/var/lib/docker").free
        stage = "RESULT_FIELDS"
        result = {
            "data_free_bytes": data_free,
            "shm_free_bytes": shm_free,
            "backing_free_bytes": backing,
            "memory_limit_bytes": memory_limit,
            "memory_current_bytes": memory_current,
            "inactive_file_bytes": pairs["inactive_file"],
            "oom_kill": pairs["oom_kill"],
            "pids_current": pids_current,
            "pids_limit": pids_limit,
            "cpu_quota": quota,
            "cpu_period": period,
        }
    except (ValueError, KeyError, IndexError, StopIteration, OSError):
        raise CapacityError("INVALID_CAPACITY_OBSERVATION_" + stage) from None
    return result


def contract_path(root: Path) -> Path:
    return _safe_path(root, ".tools/private/test-harness/service.json")


@sanitized
def enroll(root: Path) -> ServiceContract:
    """Called once on a fresh hosted service; never auto-enroll an existing cluster."""
    admin = admin_from_environment()
    container_id = os.environ.get("CSL_POSTGRES_CONTAINER", "")
    actual = inspect_service(root, container_id)
    with admin.connect() as conn:
        identity, counts = sql_identity(conn), catalog_counts(conn)
        if counts["database_count"] != 4 or counts["role_count"] > 20:
            raise CapacityError("FRESH_TEST_SERVICE_REQUIRED")
    service = ServiceContract(
        container_id,
        actual["Image"],
        actual["volume_id"],
        identity["cluster_id"],
        identity["postmaster_started"],
        run_scope(),
    )
    evaluate_capacity(counts, observe(root, service))
    directory = _safe_path(root, ".tools/private/test-harness")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    _restrict_directory(directory)
    _write_private(contract_path(root), json.dumps(asdict(service), sort_keys=True) + "\n")
    return service


@sanitized
def load(root: Path) -> ServiceContract:
    require_hosted()
    path = contract_path(root)
    if not path.is_file() or path.stat().st_size > 4096:
        raise CapacityError("TEST_SERVICE_CONTRACT_MISSING")
    try:
        service = ServiceContract(**json.loads(path.read_text(encoding="utf-8")))
        service.validate()
        if os.environ.get("CSL_POSTGRES_CONTAINER") != service.container_id:
            raise CapacityError("TEST_SERVICE_IDENTITY_MISMATCH")
        return service
    except (ValueError, TypeError):
        raise CapacityError("TEST_SERVICE_CONTRACT_INVALID") from None
