"""Fail-closed admission policy for explicitly disposable PostgreSQL tests.

This is an operational growth bound, not an attribution or repair of the retained
cluster's shared-memory failure. No automatic reclamation is implemented.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

GIB = 1024**3
MIB = 1024**2
COUNT_KEYS = ("database_count", "role_count")
RESOURCE_KEYS = (
    "data_free_bytes",
    "backing_free_bytes",
    "shm_free_bytes",
    "memory_limit_bytes",
    "memory_current_bytes",
    "inactive_file_bytes",
    "oom_kill",
    "pids_current",
    "pids_limit",
    "cpu_quota",
    "cpu_period",
)


class CapacityError(Exception):
    """Only fixed non-sensitive codes may reach public receipts."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Limits:
    max_databases: int = 200
    max_roles: int = 1536
    role_reserve: int = 32
    max_per_run: int = 192


DEFAULT_LIMITS = Limits()


def evaluate_capacity(
    counts: Mapping[str, int], resources: Mapping[str, int], limits: Limits = DEFAULT_LIMITS
) -> None:
    values = {
        **{key: counts.get(key) for key in COUNT_KEYS},
        **{key: resources.get(key) for key in RESOURCE_KEYS},
    }
    if any(type(value) is not int or value < 0 for value in values.values()):
        raise CapacityError("INVALID_CAPACITY_OBSERVATION")
    if any(type(value) is not int or value <= 0 for value in vars(limits).values()):
        raise CapacityError("INVALID_CAPACITY_OBSERVATION")
    if counts["database_count"] >= limits.max_databases:
        raise CapacityError("CAPACITY_DATABASE_LIMIT")
    if counts["role_count"] + limits.role_reserve > limits.max_roles:
        raise CapacityError("CAPACITY_ROLE_LIMIT")
    tests = (
        (resources["data_free_bytes"] >= 2 * GIB, "DATA_DISK"),
        (resources["backing_free_bytes"] >= 5 * GIB, "BACKING_DISK"),
        (resources["shm_free_bytes"] >= 36 * MIB, "SHARED_MEMORY"),
        (
            resources["memory_limit_bytes"] >= 512 * MIB
            and resources["inactive_file_bytes"] <= resources["memory_current_bytes"]
            and resources["memory_current_bytes"] <= resources["memory_limit_bytes"]
            and resources["memory_limit_bytes"]
            - (resources["memory_current_bytes"] - resources["inactive_file_bytes"])
            >= 32 * MIB,
            "MEMORY",
        ),
        (resources["oom_kill"] == 0, "OOM"),
        (resources["pids_limit"] - resources["pids_current"] >= 16, "PIDS"),
        (resources["cpu_period"] > 0 and resources["cpu_quota"] >= resources["cpu_period"], "CPU"),
    )
    for passed, code in tests:
        if not passed:
            raise CapacityError("CAPACITY_" + code)
