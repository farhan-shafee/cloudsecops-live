"""One-CPU connections avoid parallel-query dynamic shared memory without serializing clients."""

import pytest


@pytest.mark.parametrize("environment_override", [False, True])
def test_connection_uses_serial_query_plan_with_independent_transactions(
    admin_db, monkeypatch, environment_override
):
    if environment_override:
        monkeypatch.setenv(
            "PGOPTIONS",
            "-c max_parallel_workers_per_gather=2 -c max_parallel_maintenance_workers=2",
        )
    with admin_db.connect() as first, admin_db.connect() as second:
        first_value = first.execute("SHOW max_parallel_workers_per_gather").fetchone()
        second_value = second.execute("SHOW max_parallel_workers_per_gather").fetchone()
        assert first_value["max_parallel_workers_per_gather"] == "0"
        assert second_value["max_parallel_workers_per_gather"] == "0"
        for connection in (first, second):
            maintenance = connection.execute("SHOW max_parallel_maintenance_workers").fetchone()
            assert maintenance["max_parallel_maintenance_workers"] == "0"
        assert first.info.backend_pid != second.info.backend_pid
