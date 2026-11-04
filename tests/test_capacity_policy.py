"""Independent numeric expectations for the fail-closed cluster capacity gate.

These tests never connect to PostgreSQL or inspect Docker. The values below are
reviewed thresholds, rather than values imported from the implementation.
"""

from __future__ import annotations

import math

import pytest

from scripts.test_capacity import CapacityError, Limits, evaluate_capacity

GIB = 1_073_741_824
MIB = 1_048_576


def counts() -> dict[str, int]:
    return {"database_count": 4, "role_count": 32}


def resources() -> dict[str, int]:
    return {
        "data_free_bytes": 10 * GIB,
        "backing_free_bytes": 20 * GIB,
        "shm_free_bytes": 48 * MIB,
        "memory_limit_bytes": 512 * MIB,
        "memory_current_bytes": 360 * MIB,
        "inactive_file_bytes": 64 * MIB,
        "oom_kill": 0,
        "pids_current": 16,
        "pids_limit": 128,
        "cpu_quota": 100_000,
        "cpu_period": 100_000,
    }


def test_reviewed_limits_are_not_raised_to_accept_the_retained_cluster() -> None:
    reviewed = Limits()
    assert reviewed.max_databases == 200
    assert reviewed.max_roles == 1536
    assert reviewed.role_reserve == 32
    assert reviewed.max_per_run == 192


def test_fresh_bounded_cluster_is_accepted() -> None:
    assert evaluate_capacity(counts(), resources()) is None


@pytest.mark.parametrize("database_count", [200, 201, 2442])
def test_cluster_wide_database_cap_rejects_before_next_creation(database_count: int) -> None:
    with pytest.raises(CapacityError):
        evaluate_capacity({"database_count": database_count, "role_count": 32}, resources())


def test_last_database_slot_is_accepted() -> None:
    evaluate_capacity({"database_count": 199, "role_count": 32}, resources())


@pytest.mark.parametrize("role_count", [1505, 1536, 9444])
def test_roles_require_space_for_the_reviewed_provisioning_reserve(role_count: int) -> None:
    with pytest.raises(CapacityError):
        evaluate_capacity({"database_count": 4, "role_count": role_count}, resources())


def test_role_reservation_exact_boundary_is_accepted() -> None:
    evaluate_capacity({"database_count": 4, "role_count": 1504}, resources())


@pytest.mark.parametrize("field", ["database_count", "role_count"])
def test_missing_cluster_count_fails_closed(field: str) -> None:
    observed = counts()
    del observed[field]
    with pytest.raises(CapacityError):
        evaluate_capacity(observed, resources())


@pytest.mark.parametrize("field", ["database_count", "role_count"])
@pytest.mark.parametrize("value", [None, True, False, -1, 1.0, "4", math.inf, math.nan])
def test_malformed_cluster_count_is_not_coerced(field: str, value: object) -> None:
    observed: dict[str, object] = counts()
    observed[field] = value
    with pytest.raises(CapacityError):
        evaluate_capacity(observed, resources())


@pytest.mark.parametrize("field", list(resources()))
def test_each_required_resource_observation_must_be_present(field: str) -> None:
    observed = resources()
    del observed[field]
    with pytest.raises(CapacityError):
        evaluate_capacity(counts(), observed)


@pytest.mark.parametrize("field", list(resources()))
@pytest.mark.parametrize("value", [None, True, False, -1, 1.5, "100", math.inf, math.nan])
def test_resource_observations_are_exact_nonnegative_integers(field: str, value: object) -> None:
    observed: dict[str, object] = resources()
    observed[field] = value
    with pytest.raises(CapacityError):
        evaluate_capacity(counts(), observed)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("data_free_bytes", 2 * GIB - 1),
        ("backing_free_bytes", 5 * GIB - 1),
        ("shm_free_bytes", 36 * MIB - 1),
        ("memory_limit_bytes", 512 * MIB - 1),
        ("pids_current", 113),
        ("pids_limit", 31),
        ("cpu_quota", 99_999),
        ("cpu_period", 100_001),
        ("oom_kill", 1),
    ],
)
def test_one_beyond_a_capacity_boundary_rejects(field: str, value: int) -> None:
    observed = resources()
    observed[field] = value
    with pytest.raises(CapacityError):
        evaluate_capacity(counts(), observed)


def test_all_minimum_headroom_boundaries_are_inclusive() -> None:
    observed = {
        **resources(),
        "data_free_bytes": 2 * GIB,
        "backing_free_bytes": 5 * GIB,
        "shm_free_bytes": 36 * MIB,
        "memory_current_bytes": 480 * MIB,
        "inactive_file_bytes": 0,
        "pids_current": 112,
    }
    evaluate_capacity(counts(), observed)


def test_one_byte_below_working_memory_headroom_rejects() -> None:
    observed = {
        **resources(),
        "memory_current_bytes": 480 * MIB + 1,
        "inactive_file_bytes": 0,
    }
    with pytest.raises(CapacityError):
        evaluate_capacity(counts(), observed)


def test_inactive_file_cache_is_not_double_counted_as_another_allocation() -> None:
    observed = {
        **resources(),
        "memory_current_bytes": 512 * MIB,
        "inactive_file_bytes": 32 * MIB,
    }
    evaluate_capacity(counts(), observed)


@pytest.mark.parametrize(
    "overrides",
    [
        {"inactive_file_bytes": 361 * MIB},
        {"pids_current": 129},
        {"cpu_period": 0},
        {"cpu_quota": 0},
        {"pids_limit": 0},
        {"memory_limit_bytes": 0},
    ],
)
def test_contradictory_or_unbounded_measurements_do_not_pass(overrides: dict[str, int]) -> None:
    with pytest.raises(CapacityError):
        evaluate_capacity(counts(), {**resources(), **overrides})


def test_errors_expose_only_stable_non_sensitive_codes() -> None:
    observed: dict[str, object] = resources()
    observed["data_free_bytes"] = (
        "postgresql://fake:fake@127.0.0.1/fake"  # pragma: allowlist secret - fake DSN
    )
    with pytest.raises(CapacityError) as caught:
        evaluate_capacity(counts(), observed)
    assert caught.value.code
    assert str(caught.value) == caught.value.code
    assert caught.value.code.replace("_", "").isalnum()
    assert "private" not in str(caught.value).lower()


@pytest.mark.parametrize("maximum", [0, -1, True])
def test_invalid_limit_configuration_fails_closed(maximum):
    with pytest.raises(CapacityError, match="INVALID_CAPACITY_OBSERVATION"):
        evaluate_capacity(counts(), resources(), Limits(max_databases=maximum))
