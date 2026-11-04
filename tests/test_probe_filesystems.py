"""Fixed probe operands identify filesystems; df display aliases do not.

Every observation is independently authored text and every external operation is
replaced. These tests never run Docker, PostgreSQL, or a resource probe.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts import test_service as service
from scripts.test_capacity import CapacityError, evaluate_capacity
from tests.test_test_service import contract

HEADER = "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
DATA_ROW = "disk 10485760 1048576 9437184 10% /var/lib/postgresql/data\n"
SHM_ROW = "shm 65536 8192 57344 13% /dev/shm\n"
CGROUP = (
    "536870912\n"
    "125829120\n"
    "anon 104857600\n"
    "inactive_file 20971520\n"
    "oom 0\n"
    "oom_kill 0\n"
    "32\n"
    "128\n"
    "100000 100000\n"
)


def framed_probe(data: str = DATA_ROW, shm: str = SHM_ROW) -> str:
    return (
        "CSL_DATA_DISK\n"
        + HEADER
        + data
        + "CSL_SHM_DISK\n"
        + HEADER
        + shm
        + "CSL_CGROUP\n"
        + CGROUP
    )


def test_probe_binds_each_measurement_to_one_fixed_operand():
    commands = [line.split() for line in service.PROBE.splitlines() if line.startswith("df ")]
    assert commands == [
        ["df", "-Pk", "/var/lib/postgresql/data"],
        ["df", "-Pk", "/dev/shm"],
    ]


@pytest.fixture
def isolated_probe(monkeypatch, tmp_path):
    selected = contract(monkeypatch)
    calls = []

    def inspect(_root, container_id):
        assert container_id == selected.container_id
        calls.append("inspect")
        # The service boundary has already validated the exact Docker mount.
        return {"Image": selected.image_id, "volume_id": selected.volume_id}

    monkeypatch.setattr(service, "inspect_service", inspect)
    monkeypatch.setattr(
        service.shutil, "disk_usage", lambda _path: SimpleNamespace(free=9 * 1024**3)
    )

    def observe(raw: str):
        def run(_root, arguments):
            assert calls == ["inspect"]
            assert arguments[:4] == ["exec", selected.container_id, "sh", "-c"]
            calls.append("probe")
            return raw

        monkeypatch.setattr(service, "_run", run)
        return service.observe(tmp_path, selected)

    return observe


@pytest.mark.parametrize("display_mount", ["/var/lib/postgresql/data", "/etc/hosts", "/"])
def test_fixed_data_operand_accepts_display_alias_without_changing_mount_identity(
    isolated_probe, display_mount
):
    row = DATA_ROW.replace("/var/lib/postgresql/data", display_mount)
    observed = isolated_probe(framed_probe(data=row))
    assert observed == {
        "data_free_bytes": 9437184 * 1024,
        "shm_free_bytes": 57344 * 1024,
        "backing_free_bytes": 9 * 1024**3,
        "memory_limit_bytes": 536870912,
        "memory_current_bytes": 125829120,
        "inactive_file_bytes": 20971520,
        "oom_kill": 0,
        "pids_current": 32,
        "pids_limit": 128,
        "cpu_quota": 100000,
        "cpu_period": 100000,
    }
    evaluate_capacity({"database_count": 4, "role_count": 14}, observed)


def test_display_alias_never_allows_a_replaced_volume(monkeypatch, tmp_path):
    selected = contract(monkeypatch)
    monkeypatch.setattr(
        service,
        "inspect_service",
        lambda *_args: {"Image": selected.image_id, "volume_id": "f" * 64},
    )
    monkeypatch.setattr(
        service, "_run", lambda *_args: pytest.fail("Replaced volume reached resource probe")
    )
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
        service.observe(tmp_path, selected)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("", id="empty"),
        pytest.param(framed_probe().replace("CSL_DATA_DISK\n", ""), id="missing-data-marker"),
        pytest.param(framed_probe().replace("CSL_SHM_DISK\n", ""), id="missing-shm-marker"),
        pytest.param(framed_probe().replace("CSL_CGROUP\n", ""), id="missing-cgroup-marker"),
        pytest.param("CSL_DATA_DISK\n" + framed_probe(), id="duplicate-marker"),
        pytest.param(
            framed_probe().replace("CSL_DATA_DISK", "CSL_SHM_DISK", 1),
            id="out-of-order-markers",
        ),
        pytest.param(framed_probe(data=""), id="missing-data-row"),
        pytest.param(framed_probe(shm=""), id="missing-shm-row"),
        pytest.param(framed_probe(data=DATA_ROW + DATA_ROW), id="multiple-data-rows"),
        pytest.param(framed_probe(shm=SHM_ROW + SHM_ROW), id="multiple-shm-rows"),
        pytest.param(
            framed_probe(data=DATA_ROW.replace("9437184", "unknown")), id="nonnumeric-data"
        ),
        pytest.param(framed_probe(shm=SHM_ROW.replace("57344", "unknown")), id="nonnumeric-shm"),
        pytest.param(
            framed_probe(data="disk 10485760 9437184 9437184 90% /etc/hosts\n"),
            id="inconsistent-data-block-counts",
        ),
        pytest.param(
            framed_probe(shm="shm 65536 57344 57344 88% /dev/shm\n"),
            id="inconsistent-shm-block-counts",
        ),
        pytest.param(framed_probe(data="unsupported disk format\n"), id="unsupported-data-row"),
        pytest.param(framed_probe(shm="unsupported disk format\n"), id="unsupported-shm-row"),
        pytest.param(
            framed_probe().replace(HEADER, "unsupported df header\n", 1),
            id="unsupported-data-header",
        ),
        pytest.param(HEADER + DATA_ROW + SHM_ROW + CGROUP, id="unframed-combined-output"),
    ],
)
def test_ambiguous_or_unsupported_probe_output_fails_closed(isolated_probe, raw):
    with pytest.raises(CapacityError, match="INVALID_CAPACITY_OBSERVATION"):
        isolated_probe(raw)
