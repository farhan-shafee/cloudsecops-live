"""Disposable-service boundaries using independently authored fake observations.

No test in this module accesses Docker, PostgreSQL, credentials, or the network.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from types import SimpleNamespace

import psycopg
import pytest

from scripts import test_service as service
from scripts.test_capacity import CapacityError

CONTAINER = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
VOLUME = "c" * 64
DSN = "host=127.0.0.1 port=5432 dbname=cloudsecops_lab user=cloudsecops_ci"
PROBE = """CSL_DATA_DISK
Filesystem 1024-blocks Used Available Capacity Mounted on
disk 10485760 1048576 9437184 10% /var/lib/postgresql/data
CSL_SHM_DISK
Filesystem 1024-blocks Used Available Capacity Mounted on
shm 65536 8192 57344 13% /dev/shm
CSL_CGROUP
536870912
125829120
anon 104857600
inactive_file 20971520
oom 0
oom_kill 0
32
128
100000 100000
"""


@pytest.fixture(autouse=True)
def no_real_external_connections(monkeypatch):
    def deny(*_args, **_kwargs):
        pytest.fail("unit service boundary reached a real database connection")

    monkeypatch.setattr(psycopg, "connect", deny)
    for key in (
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "RUNNER_OS",
        "CSL_TEST_DSN",
        "CSL_POSTGRES_CONTAINER",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGHOSTADDR",
    ):
        monkeypatch.delenv(key, raising=False)


def hosted(monkeypatch):
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "GITHUB_RUN_ID": "1234",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "postgres-integration",
        "CSL_TEST_DSN": DSN,
        "CSL_POSTGRES_CONTAINER": CONTAINER,
    }.items():
        monkeypatch.setenv(key, value)


def contract(monkeypatch):
    hosted(monkeypatch)
    return service.ServiceContract(
        CONTAINER,
        IMAGE_ID,
        "d" * 64,
        "1234567890123456789",
        "2026-11-04 12:00:00+00",
        "1234:1:postgres-integration",
    )


def inspection():
    return {
        "Id": CONTAINER,
        "Image": IMAGE_ID,
        "ConfiguredImage": service.IMAGE,
        "State": {"Running": True, "OOMKilled": False, "Health": {"Status": "healthy"}},
        "Mounts": [
            {
                "Destination": "/var/lib/postgresql/data",
                "Type": "volume",
                "Name": VOLUME,
                "Source": f"/var/lib/docker/volumes/{VOLUME}/_data",
                "RW": True,
            }
        ],
        "Memory": 512 * 1024**2,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": 128,
        "ShmSize": 64 * 1024**2,
        "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
    }


def test_local_runner_refuses_before_reading_connection_configuration(monkeypatch, tmp_path):
    def unexpected(*_args, **_kwargs):
        pytest.fail("local runner must refuse before parsing private configuration")

    monkeypatch.setattr(service, "Database", unexpected)
    monkeypatch.setattr(service, "_run", unexpected)
    for operation in (
        service.admin_from_environment,
        lambda: service.enroll(tmp_path),
        lambda: service.load(tmp_path),
        lambda: service.inspect_service(tmp_path, CONTAINER),
    ):
        with pytest.raises(CapacityError, match="DISPOSABLE_HOSTED_SERVICE_REQUIRED"):
            operation()


@pytest.mark.parametrize(
    "key,value",
    [("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_OS", "Windows")],
)
def test_partial_hosted_labels_never_authorize_a_retained_service(monkeypatch, key, value):
    hosted(monkeypatch)
    monkeypatch.setenv(key, value)
    with pytest.raises(CapacityError, match="DISPOSABLE_HOSTED_SERVICE_REQUIRED"):
        service.admin_from_environment()


def test_only_explicit_expected_admin_dsn_is_parsed_without_connecting(monkeypatch):
    hosted(monkeypatch)
    assert service.admin_from_environment()._values == {
        "host": "127.0.0.1",
        "port": "5432",
        "dbname": "cloudsecops_lab",
        "user": "cloudsecops_ci",
    }


@pytest.mark.parametrize(
    "override", ["port=55432", "user=cloudsecops_local", "dbname=csl_test_existing"]
)
def test_wrong_admin_service_parameters_are_rejected_before_connection(monkeypatch, override):
    hosted(monkeypatch)
    monkeypatch.setenv("CSL_TEST_DSN", DSN + " " + override)
    with pytest.raises(CapacityError, match="TEST_SERVICE_DSN_MISMATCH"):
        service.admin_from_environment()


@pytest.mark.parametrize("key", ["PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR"])
def test_ambient_connection_routes_are_not_adopted(monkeypatch, key):
    hosted(monkeypatch)
    monkeypatch.setenv(key, "untrusted")
    with pytest.raises(CapacityError, match="TEST_SERVICE_DSN_MISMATCH"):
        service.admin_from_environment()


def test_inspection_requests_only_allowlisted_nonsensitive_fields(monkeypatch, tmp_path):
    hosted(monkeypatch)
    commands = []

    def run(_root, arguments):
        commands.append(arguments)
        return json.dumps(inspection())

    monkeypatch.setattr(service, "_run", run)
    found = service.inspect_service(tmp_path, CONTAINER)
    assert found["Id"] == CONTAINER
    assert len(found["volume_id"]) == 64
    assert commands[0][0:2] == ["inspect", "--format"]
    assert ".Config.Env" not in commands[0][2]
    assert ".Config.Image" in commands[0][2]
    assert "{{json .State}}" not in commands[0][2], "whole State includes arbitrary health/log text"


@pytest.mark.parametrize(
    "patch",
    [
        {"Id": "f" * 64},
        {"ConfiguredImage": "postgres:latest"},
        {"Memory": 0},
        {"NanoCpus": 0},
        {"PidsLimit": 0},
        {"ShmSize": 128 * 1024**2},
        {"State": {"Running": False, "OOMKilled": False, "Health": {"Status": "healthy"}}},
        {"State": {"Running": True, "OOMKilled": True, "Health": {"Status": "healthy"}}},
        {"State": {"Running": True, "OOMKilled": False, "Health": {"Status": "unhealthy"}}},
        {"Ports": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}},
    ],
)
def test_wrong_service_identity_or_resource_envelope_is_rejected(monkeypatch, tmp_path, patch):
    hosted(monkeypatch)
    monkeypatch.setattr(service, "_run", lambda *_args: json.dumps({**inspection(), **patch}))
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
        service.inspect_service(tmp_path, CONTAINER)


@pytest.mark.parametrize(
    "mount",
    [
        [],
        [
            {
                "Destination": "/var/lib/postgresql/data",
                "Type": "bind",
                "Name": VOLUME,
                "Source": "/private",
            }
        ],
        [
            {
                "Destination": "/var/lib/postgresql/data",
                "Type": "volume",
                "Name": "cloudsecops-live-phase1a2-evidence",
                "Source": "/private",
            }
        ],
    ],
)
def test_named_retained_or_bind_mount_is_never_enrolled(monkeypatch, tmp_path, mount):
    hosted(monkeypatch)
    data = inspection()
    data["Mounts"] = mount
    monkeypatch.setattr(service, "_run", lambda *_args: json.dumps(data))
    with pytest.raises(CapacityError, match="TEST_SERVICE_VOLUME_MISMATCH"):
        service.inspect_service(tmp_path, CONTAINER)


@pytest.mark.parametrize("raw", ["not JSON private text", "[]", "{}", '{"Id": null}', "null"])
def test_malformed_docker_responses_fail_with_fixed_reason(monkeypatch, tmp_path, raw):
    hosted(monkeypatch)
    monkeypatch.setattr(service, "_run", lambda *_args: raw)
    with pytest.raises(CapacityError) as error:
        service.inspect_service(tmp_path, CONTAINER)
    assert "private text" not in str(error.value)


def test_missing_or_wrong_container_id_prevents_docker_probe(monkeypatch, tmp_path):
    hosted(monkeypatch)
    monkeypatch.setattr(service, "_run", lambda *_args: pytest.fail("invalid id reached Docker"))
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISSING"):
        service.inspect_service(tmp_path, "cloudsecops-live-phase1a2-postgres-1")


def test_resource_probe_counts_distinct_memory_domains_without_double_counting(
    monkeypatch, tmp_path
):
    selected = contract(monkeypatch)
    monkeypatch.setattr(
        service,
        "inspect_service",
        lambda *_args: {"Image": IMAGE_ID, "volume_id": selected.volume_id},
    )
    monkeypatch.setattr(service, "_run", lambda *_args: PROBE)
    monkeypatch.setattr(
        service.shutil, "disk_usage", lambda _path: SimpleNamespace(free=9 * 1024**3)
    )
    assert service.observe(tmp_path, selected) == {
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


@pytest.mark.parametrize(
    "raw",
    [
        "",
        PROBE.replace("inactive_file 20971520\n", ""),
        PROBE.replace("100000 100000", "max 100000"),
        PROBE.replace("536870912", "max"),
        PROBE.replace("CSL_SHM_DISK", "CSL_OTHER_DISK"),
        PROBE + "unexpected trailing line\n",
    ],
)
def test_incomplete_resource_measurements_fail_closed(monkeypatch, tmp_path, raw):
    selected = contract(monkeypatch)
    monkeypatch.setattr(
        service,
        "inspect_service",
        lambda *_args: {"Image": IMAGE_ID, "volume_id": selected.volume_id},
    )
    monkeypatch.setattr(service, "_run", lambda *_args: raw)
    monkeypatch.setattr(
        service.shutil, "disk_usage", lambda _path: SimpleNamespace(free=9 * 1024**3)
    )
    with pytest.raises(CapacityError, match="INVALID_CAPACITY_OBSERVATION"):
        service.observe(tmp_path, selected)


def test_replaced_service_is_rejected_before_resource_exec(monkeypatch, tmp_path):
    selected = contract(monkeypatch)
    monkeypatch.setattr(
        service,
        "inspect_service",
        lambda *_args: {"Image": "sha256:" + "f" * 64, "volume_id": selected.volume_id},
    )
    monkeypatch.setattr(
        service, "_run", lambda *_args: pytest.fail("replaced service reached exec")
    )
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
        service.observe(tmp_path, selected)


def test_contract_missing_or_oversized_never_connects(monkeypatch, tmp_path):
    contract(monkeypatch)
    with pytest.raises(CapacityError, match="TEST_SERVICE_CONTRACT_MISSING"):
        service.load(tmp_path)
    target = service.contract_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text("x" * 4097)
    with pytest.raises(CapacityError, match="TEST_SERVICE_CONTRACT_MISSING"):
        service.load(tmp_path)


@pytest.mark.parametrize(
    "patch",
    [
        {"cluster_id": ""},
        {"image_id": "latest"},
        {"volume_id": "retained"},
        {"postmaster_started": ""},
        {"run_scope": "other:run:job"},
        {"container_id": "f" * 64},
    ],
)
def test_tampered_private_contract_is_rejected(monkeypatch, tmp_path, patch):
    selected = contract(monkeypatch)
    target = service.contract_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({**asdict(selected), **patch}))
    with pytest.raises(CapacityError):
        service.load(tmp_path)


def test_valid_contract_replays_only_in_exact_hosted_run_scope(monkeypatch, tmp_path):
    selected = contract(monkeypatch)
    target = service.contract_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(asdict(selected)))
    assert service.load(tmp_path) == selected
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
        service.load(tmp_path)


@pytest.mark.parametrize(
    "raw",
    ["[]", "not JSON", '{"password":"fake"}'],  # pragma: allowlist secret - fixture
)
def test_malformed_contract_has_generic_error(monkeypatch, tmp_path, raw):
    contract(monkeypatch)
    target = service.contract_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text(raw)
    with pytest.raises(CapacityError, match="TEST_SERVICE_CONTRACT_INVALID"):
        service.load(tmp_path)


def test_sql_identity_observes_only_fixed_catalog_identity():
    expected = {
        "cluster_id": "123456789",
        "postmaster_started": "2026-11-04 12:00:00+00",
        "owner": "cloudsecops_ci",
        "database": "cloudsecops_lab",
    }
    calls = []

    class FakeConnection:
        def execute(self, statement):
            calls.append(statement)
            return SimpleNamespace(fetchone=lambda: expected)

    assert service.sql_identity(FakeConnection()) == expected
    assert "pg_control_system()" in calls[0]
    assert "pg_authid" not in calls[0]


@pytest.mark.parametrize(
    "row",
    [
        None,
        {"owner": "cloudsecops_local", "database": "cloudsecops_lab"},
        {"owner": "cloudsecops_ci", "database": "csl_test_retained"},
    ],
)
def test_wrong_sql_identity_is_rejected(row):
    connection = SimpleNamespace(execute=lambda *_args: SimpleNamespace(fetchone=lambda: row))
    with pytest.raises(CapacityError, match="TEST_SERVICE_IDENTITY_MISMATCH"):
        service.sql_identity(connection)


@pytest.mark.parametrize("key", ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"])
def test_missing_run_identity_prevents_scope_binding(monkeypatch, key):
    hosted(monkeypatch)
    monkeypatch.delenv(key)
    with pytest.raises(CapacityError, match="TEST_SERVICE_SCOPE_MISSING"):
        service.run_scope()


def fake_enrollment(monkeypatch, *, database_count=4, role_count=17):
    selected = contract(monkeypatch)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    monkeypatch.setattr(
        service, "admin_from_environment", lambda: SimpleNamespace(connect=Connection)
    )
    monkeypatch.setattr(
        service,
        "inspect_service",
        lambda *_args: {"Image": IMAGE_ID, "volume_id": selected.volume_id},
    )
    monkeypatch.setattr(
        service,
        "sql_identity",
        lambda _conn: {
            "cluster_id": selected.cluster_id,
            "postmaster_started": selected.postmaster_started,
            "owner": "cloudsecops_ci",
            "database": "cloudsecops_lab",
        },
    )
    monkeypatch.setattr(
        service,
        "catalog_counts",
        lambda _conn: {"database_count": database_count, "role_count": role_count},
    )
    monkeypatch.setattr(
        service,
        "observe",
        lambda *_args: {
            "data_free_bytes": 9 * 1024**3,
            "shm_free_bytes": 56 * 1024**2,
            "backing_free_bytes": 9 * 1024**3,
            "memory_limit_bytes": 512 * 1024**2,
            "memory_current_bytes": 120 * 1024**2,
            "inactive_file_bytes": 20 * 1024**2,
            "oom_kill": 0,
            "pids_current": 32,
            "pids_limit": 128,
            "cpu_quota": 100000,
            "cpu_period": 100000,
        },
    )
    return selected


def test_successful_fresh_enrollment_writes_only_private_bound_identity(monkeypatch, tmp_path):
    selected = fake_enrollment(monkeypatch)
    assert service.enroll(tmp_path) == selected
    raw = service.contract_path(tmp_path).read_text()
    assert json.loads(raw) == asdict(selected)
    assert "dsn" not in raw and "password" not in raw
    assert service.load(tmp_path) == selected


@pytest.mark.parametrize("counts", [{"database_count": 5}, {"role_count": 21}])
def test_enrollment_rejects_existing_catalog_before_resources_or_writes(
    monkeypatch, tmp_path, counts
):
    fake_enrollment(monkeypatch, **counts)
    monkeypatch.setattr(
        service, "observe", lambda *_args: pytest.fail("existing cluster reached resource probe")
    )
    with pytest.raises(CapacityError, match="FRESH_TEST_SERVICE_REQUIRED"):
        service.enroll(tmp_path)
    assert not (tmp_path / ".tools").exists()


def test_insufficient_capacity_cannot_produce_an_enrollment_contract(monkeypatch, tmp_path):
    fake_enrollment(monkeypatch)
    observe = service.observe
    monkeypatch.setattr(
        service, "observe", lambda *args: {**observe(*args), "shm_free_bytes": 3 * 1024**2}
    )
    with pytest.raises(CapacityError, match="CAPACITY_SHARED_MEMORY"):
        service.enroll(tmp_path)
    assert not (tmp_path / ".tools").exists()


def test_existing_enrollment_contract_is_never_overwritten(monkeypatch, tmp_path):
    fake_enrollment(monkeypatch)
    service.enroll(tmp_path)
    original = service.contract_path(tmp_path).read_bytes()
    with pytest.raises(CapacityError, match="TEST_SERVICE_OBSERVATION_FAILED"):
        service.enroll(tmp_path)
    assert service.contract_path(tmp_path).read_bytes() == original
