"""Safety contracts for the project-only local database launcher."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compose_is_pinned_private_and_resource_bounded() -> None:
    document = yaml.safe_load((ROOT / "compose.phase1a2.yml").read_text(encoding="utf-8"))
    assert document["name"] == "cloudsecops-live-phase1a2"
    pg = document["services"]["postgres"]
    assert (
        pg["image"]
        == (
            "postgres:17.11-alpine3.24@sha256:"
            "266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b"  # pragma: allowlist secret  # noqa: E501 - public official image digest
        )
    )
    assert pg["ports"] == ["127.0.0.1:55432:5432"]
    assert pg["mem_limit"] == "512m" and pg["cpus"] == 1.0 and pg["pids_limit"] == 128
    # Docker29 suppresses published ports on an internal network. The dedicated
    # bridge is private by project ownership; host access is explicitly loopback.
    assert document["networks"]["private"]["name"] == "cloudsecops-live-phase1a2-loopback"
    assert document["networks"]["private"].get("internal", False) is False
    assert "POSTGRES_PASSWORD" not in pg["environment"]
    assert pg["environment"]["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres_password"
    assert document["secrets"]["postgres_password"]["file"] == ".tools/private/postgres-password"


def test_generated_local_credentials_are_private_stable_and_unique(tmp_path: Path) -> None:
    from scripts.local_postgres import prepare_secrets

    config_path = prepare_secrets(tmp_path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    password_path = tmp_path / ".tools/private/postgres-password"
    password = password_path.read_text(encoding="utf-8").strip()
    assert len(password) >= 40
    assert config["dsn"] == (
        f"postgresql://cloudsecops_local:{password}@127.0.0.1:55432/cloudsecops_lab"
        "?connect_timeout=5&application_name=cloudsecops-live-phase1a2"
    )
    assert prepare_secrets(tmp_path) == config_path
    assert password_path.read_text(encoding="utf-8").strip() == password
    other = tmp_path / "second"
    other.mkdir()
    other_config = prepare_secrets(other)
    assert json.loads(other_config.read_text(encoding="utf-8"))["dsn"] != config["dsn"]
    if os.name != "nt":
        assert password_path.stat().st_mode & 0o777 == 0o600
        assert password_path.parent.stat().st_mode & 0o777 == 0o700


def test_incomplete_or_tampered_secret_pair_is_rejected_without_rotation(tmp_path: Path) -> None:
    from scripts.local_postgres import LocalPostgresError, prepare_secrets

    config_path = prepare_secrets(tmp_path)
    password_path = tmp_path / ".tools/private/postgres-password"
    original = password_path.read_bytes()
    config_path.write_text('{"dsn":"postgresql://remote.invalid/production"}', encoding="utf-8")
    with pytest.raises(LocalPostgresError, match="secret_state_invalid"):
        prepare_secrets(tmp_path)
    assert password_path.read_bytes() == original
    config_path.unlink()
    with pytest.raises(LocalPostgresError, match="secret_state_incomplete"):
        prepare_secrets(tmp_path)
    assert password_path.read_bytes() == original


def test_non_directory_private_path_is_rejected(tmp_path: Path) -> None:
    from scripts.local_postgres import LocalPostgresError, prepare_secrets

    (tmp_path / ".tools").write_text("unrelated data", encoding="utf-8")
    with pytest.raises(LocalPostgresError, match="unsafe_private_path"):
        prepare_secrets(tmp_path)
    assert (tmp_path / ".tools").read_text(encoding="utf-8") == "unrelated data"


@pytest.mark.parametrize("labels", [{}, {"com.docker.compose.project": "another-project"}])
def test_resources_owned_by_another_project_are_rejected(labels: dict[str, str]) -> None:
    from scripts.local_postgres import LocalPostgresError, require_project_labels

    with pytest.raises(LocalPostgresError, match="resource_name_collision"):
        require_project_labels(labels)


def test_project_resource_labels_are_accepted() -> None:
    from scripts.local_postgres import require_project_labels

    require_project_labels({"com.docker.compose.project": "cloudsecops-live-phase1a2"})


def test_launcher_refuses_preexisting_docker_credentials(tmp_path: Path) -> None:
    from scripts.local_postgres import Docker, LocalPostgresError

    config = tmp_path / ".tools/docker-client"
    config.mkdir(parents=True)
    (config / "config.json").write_text("{}", encoding="utf-8")
    with pytest.raises(LocalPostgresError, match="docker_config_not_empty"):
        Docker(tmp_path)


@pytest.mark.parametrize("message", ["No such container", "no such volume", "network not found"])
def test_missing_resources_are_safe_but_daemon_failures_are_not(
    tmp_path: Path, message: str
) -> None:
    from scripts.local_postgres import Docker, LocalPostgresError

    docker = Docker(tmp_path)
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", message)):
        assert docker.run(["container", "inspect", "lab"], missing_ok=True) is None
    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess([], 1, "", "permission denied"),
    ):
        with pytest.raises(LocalPostgresError, match="docker_operation_failed"):
            docker.run(["container", "inspect", "lab"], missing_ok=True)


def test_launcher_has_no_destructive_cleanup_command() -> None:
    from scripts.local_postgres import parser

    assert parser().parse_args(["stop"]).action == "stop"
    with pytest.raises(SystemExit):
        parser().parse_args(["destroy"])


def test_storage_preflight_rejects_one_byte_below_minimum(tmp_path: Path) -> None:
    from scripts.local_postgres import LocalPostgresError, require_free_space

    require_free_space(tmp_path, free_bytes=2 * 1024**3)
    with pytest.raises(LocalPostgresError, match="insufficient_free_space"):
        require_free_space(tmp_path, free_bytes=2 * 1024**3 - 1)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("DOCKER_HOST", "tcp://remote.invalid:2375"),
        ("DOCKER_HOST", "ssh://remote.invalid"),
        ("DOCKER_HOST", "unix:///tmp/other-project.sock"),
        ("DOCKER_CONTEXT", "remote-production"),
        ("DOCKER_TLS_VERIFY", "1"),
        ("DOCKER_CERT_PATH", "/private/certificates"),
        ("DOCKER_AUTH_CONFIG", "{}"),
    ],
)
def test_unsafe_docker_environment_fails_before_any_process_or_secret_creation(
    tmp_path: Path, key: str, value: str
) -> None:
    from scripts.local_postgres import main

    with (
        patch.dict(os.environ, {key: value}, clear=True),
        patch("scripts.local_postgres.ROOT", tmp_path),
        patch("subprocess.run") as child,
    ):
        assert main(["start"]) == 2
        child.assert_not_called()
    assert not (tmp_path / ".tools").exists()


@pytest.mark.parametrize(
    "host",
    ["", "unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"],
)
def test_only_standard_local_docker_endpoints_are_accepted(host: str) -> None:
    from scripts.local_postgres import require_local_docker

    require_local_docker({"DOCKER_HOST": host})


def test_docker_guard_rechecks_environment_immediately_before_subprocess(tmp_path: Path) -> None:
    from scripts.local_postgres import Docker, LocalPostgresError

    with patch.dict(os.environ, {}, clear=True):
        docker = Docker(tmp_path)
    with (
        patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote.invalid:2375"}, clear=True),
        patch("subprocess.run") as child,
    ):
        with pytest.raises(LocalPostgresError, match="unsafe_docker_environment"):
            docker.run(["info"])
        child.assert_not_called()


@pytest.mark.parametrize("use_ci_container", [False, True])
def test_backup_docker_paths_reject_remote_environment_before_process(
    use_ci_container: bool,
) -> None:
    from scripts.local_postgres import LocalPostgresError
    from tests.integration.test_backup import pg_command

    values = {"host": "127.0.0.1", "user": "lab", "dbname": "csl_test_negative"}
    environment = {"DOCKER_HOST": "tcp://remote.invalid:2375"}
    if use_ci_container:
        environment["CSL_POSTGRES_CONTAINER"] = "a" * 12
    with (
        patch.dict(os.environ, environment, clear=True),
        patch("shutil.which", side_effect=[None, "docker"]),
        patch("subprocess.run") as child,
    ):
        with pytest.raises(LocalPostgresError, match="unsafe_docker_environment"):
            pg_command(SimpleNamespace(_values=values), "pg_dump", [])
        child.assert_not_called()
