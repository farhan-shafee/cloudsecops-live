"""Fail-closed local HTTPS configuration and owner command contracts."""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def test_tls_is_unique_private_and_cannot_overwrite(tmp_path: Path) -> None:
    from cloudsecops_live.workspace_tls import create_tls, validate_tls

    certificate, key = create_tls(tmp_path / "tls")
    validate_tls(certificate, key)
    first = certificate.read_bytes()
    with pytest.raises(ValueError):
        create_tls(tmp_path / "tls")
    assert certificate.read_bytes() == first
    other, _ = create_tls(tmp_path / "other")
    assert other.read_bytes() != first
    if os.name != "nt":
        assert key.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:8443",
        "https://localhost:8443",
        "https://0.0.0.0:8443",
        "https://127.0.0.1:8443/",
        "https://127.0.0.1:8443?x=y",
        "https://a@127.0.0.1:8443",
        "https://127.0.0.1",
        "https://127.0.0.1:0",
    ],
)
def test_origin_rejects_ambiguous_or_non_loopback_values(origin: str) -> None:
    from cloudsecops_live.workspace_config import origin_port

    with pytest.raises(ValueError):
        origin_port(origin)


def test_runtime_config_contains_only_restricted_credentials(tmp_path: Path) -> None:
    from cloudsecops_live.workspace_config import load_config, write_private_json
    from cloudsecops_live.workspace_tls import create_tls

    certificate, key = create_tls(tmp_path / "tls")
    path = tmp_path / "runtime.json"
    payload = {
        "origin": "https://127.0.0.1:8443",
        "gate_dsn": "postgresql://gate@127.0.0.1:55432/cloudsecops_lab",
        "certificate": str(certificate),
        "key": str(key),
        "accounts": [],
    }
    write_private_json(path, payload)
    config = load_config(path)
    assert config.origin == payload["origin"]
    assert config.by_username("absent") is None
    with pytest.raises(ValueError):
        config.validate()
    payload["dsn"] = "maintenance"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        load_config(path)


def test_tls_rejects_mismatched_and_missing_files(tmp_path: Path) -> None:
    from cloudsecops_live.workspace_tls import create_tls, validate_tls

    certificate, _ = create_tls(tmp_path / "a")
    _, other_key = create_tls(tmp_path / "b")
    with pytest.raises(ValueError):
        validate_tls(certificate, other_key)
    with pytest.raises(ValueError):
        validate_tls(certificate, tmp_path / "missing")


def test_cli_has_no_password_or_network_binding_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cloudsecops_live.workspace_cli import main

    assert main(["serve", "--config", "missing", "--host", "0.0.0.0"]) == 2
    assert main(["user-add", "--password", "value"]) == 2
    assert "value" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "document",
    [
        [],
        {},
        {"dsn": "owner"},
        {
            "origin": "https://127.0.0.1:8443",
            "gate_dsn": "safe",
            "certificate": "a",
            "key": "b",
            "accounts": "wrong",
        },
        {"origin": 3, "gate_dsn": "safe", "certificate": "a", "key": "b", "accounts": []},
        {
            "origin": "https://127.0.0.1:8443",
            "gate_dsn": "safe",
            "certificate": "a",
            "key": "b",
            "accounts": [None],
        },
        {
            "origin": "https://127.0.0.1:8443",
            "gate_dsn": "safe",
            "certificate": "a",
            "key": "b",
            "accounts": [{}],
        },
        {
            "origin": "https://127.0.0.1:8443",
            "gate_dsn": "safe",
            "certificate": "a",
            "key": "b",
            "accounts": [0] * 101,
        },
    ],
)
def test_config_rejects_untrusted_shapes(document: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from cloudsecops_live import workspace_config as module

    monkeypatch.setattr(
        module, "private_file", lambda *args, **kwargs: json.dumps(document).encode()
    )
    with pytest.raises(ValueError):
        module.load_config(Path("unused"))


def test_config_loads_unique_account_and_rejects_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cloudsecops_live import workspace_config as module

    dsn = "postgresql://fixture@127.0.0.1:55432/cloudsecops_lab"
    account = {
        "user_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "username": "analyst",
        "auth_dsn": dsn,
        "data_dsn": dsn,
    }
    document = {
        "origin": "https://127.0.0.1:8443",
        "gate_dsn": dsn,
        "certificate": str(Path("cert.pem").absolute()),
        "key": str(Path("key.pem").absolute()),
        "accounts": [account],
    }
    monkeypatch.setattr(
        module, "private_file", lambda *args, **kwargs: json.dumps(document).encode()
    )
    monkeypatch.setattr(module, "validate_tls", lambda *args: None)
    config = module.load_config(Path("unused"))
    assert config.by_username("analyst").user_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    document["accounts"].append(account)
    with pytest.raises(ValueError):
        module.load_config(Path("unused"))
    document["accounts"] = [{**account, "user_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, account]
    with pytest.raises(ValueError):
        module.load_config(Path("unused"))
    document["accounts"] = [{**account, "username": "bad name"}]
    with pytest.raises(ValueError):
        module.load_config(Path("unused"))
    document["accounts"] = []
    document["certificate"] = "relative.pem"
    with pytest.raises(ValueError):
        module.load_config(Path("unused"))
    with pytest.raises(ValueError):
        module.origin_port("https://127.0.0.1:65536")


def test_config_validates_live_identity_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    from cloudsecops_live import workspace_config as module
    from cloudsecops_live import workspace_store
    from cloudsecops_live.database import Database

    db = Database("postgresql://fixture@127.0.0.1:55432/cloudsecops_lab")
    account = module.AccountConfig("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "analyst", db, db)
    config = module.WorkspaceConfig(
        "https://127.0.0.1:8443",
        db,
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": account},
        Path("cert"),
        Path("key"),
    )
    monkeypatch.setattr(module, "validate_tls", lambda *args: None)
    gate = Mock()
    store = Mock()
    store.identity.return_value = {
        "user_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "username": "analyst",
    }
    monkeypatch.setattr(workspace_store, "GateStore", lambda *args: gate)
    monkeypatch.setattr(workspace_store, "WorkspaceStore", lambda *args: store)
    config.validate()
    gate.validate.assert_called_once()
    store.validate.assert_called_once()
    store.identity.return_value = {
        "user_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "username": "analyst",
    }
    with pytest.raises(ValueError):
        config.validate()


def test_private_file_rejects_directories_empty_large_and_links(tmp_path: Path) -> None:
    from cloudsecops_live.workspace_tls import private_file, safe_path

    with pytest.raises(ValueError):
        private_file(tmp_path, max_bytes=8)
    file = tmp_path / "empty"
    file.write_bytes(b"")
    with pytest.raises(ValueError):
        private_file(file, max_bytes=8)
    file.write_bytes(b"x" * 9)
    with pytest.raises(ValueError):
        private_file(file, max_bytes=8)
    if os.name != "nt":
        file.chmod(0o644)
        with pytest.raises(ValueError):
            private_file(file, max_bytes=10)
        link = tmp_path / "link"
        link.symlink_to(file)
        with pytest.raises(ValueError):
            safe_path(link)


def test_owner_commands_dispatch_without_printing_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from cloudsecops_live import workspace_cli as module
    from cloudsecops_live import workspace_roles as roles

    db = Mock()
    monkeypatch.setattr(module, "_maintenance", lambda path: db)
    monkeypatch.setattr(
        module, "load_config", lambda path: SimpleNamespace(by_username=lambda username: object())
    )
    monkeypatch.setattr(
        module,
        "read_runtime_json",
        lambda path: {"accounts": [{"username": "analyst"}, {"username": "other"}]},
    )
    writer = Mock()
    monkeypatch.setattr(module, "write_private_json", writer)
    for command, function in (
        ("roles-setup", "setup_roles"),
        ("restore-security", "restore_security"),
        ("grant-case", "grant_case"),
        ("disable-user", "disable_user"),
    ):
        helper = Mock()
        monkeypatch.setattr(roles, function, helper)
        args = [command, "--maintenance-config", "private"]
        if command in {"grant-case", "disable-user"}:
            args += ["--username", "analyst"]
        if command == "grant-case":
            args += ["--case-id", "case1"]
        if command == "disable-user":
            args += ["--config", "runtime"]
        assert module.main(args) == 0
        helper.assert_called_once()
    assert writer.call_args.args[1] == {"accounts": [{"username": "other"}]}
    assert "dsn" not in capsys.readouterr().out


def test_init_excludes_maintenance_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from cloudsecops_live import workspace_cli as module
    from cloudsecops_live import workspace_roles as roles

    db = Mock()
    monkeypatch.setattr(module, "_maintenance", lambda path: db)
    monkeypatch.setattr(roles, "setup_gate", lambda db: "restricted_gate")
    monkeypatch.setattr(module, "create_tls", lambda path: (path / "cert", path / "key"))
    writer = Mock()
    monkeypatch.setattr(module, "write_private_json", writer)
    assert (
        module.main(
            [
                "init",
                "--maintenance-config",
                "private",
                "--config",
                str(tmp_path / "runtime"),
                "--tls-dir",
                str(tmp_path / "tls"),
            ]
        )
        == 0
    )
    document = writer.call_args.args[1]
    assert document["gate_dsn"] == "restricted_gate"
    assert "dsn" not in document and document["accounts"] == []
    db.migrate.assert_called_once()


def test_interactive_user_add_rejects_mismatch_then_writes_only_restricted_dsns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cloudsecops_live import workspace_cli as module
    from cloudsecops_live import workspace_roles as roles

    account = {
        "user_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "username": "analyst",
        "auth_dsn": "auth",
        "data_dsn": "data",
    }
    monkeypatch.setattr(module, "_maintenance", lambda path: Mock())
    monkeypatch.setattr(
        module,
        "load_config",
        lambda path: SimpleNamespace(accounts={}, by_username=lambda username: None),
    )
    monkeypatch.setattr(module, "read_runtime_json", lambda path: {"accounts": []})
    helper = Mock(return_value=account)
    monkeypatch.setattr(roles, "provision_user", helper)
    monkeypatch.setitem(
        sys.modules,
        "cloudsecops_live.workspace_auth",
        SimpleNamespace(hash_password=lambda _: "stub"),  # pragma: allowlist secret - mock hash
    )
    args = [
        "user-add",
        "--maintenance-config",
        "private",
        "--config",
        "runtime",
        "--username",
        "analyst",
        "--role",
        "analyst",
    ]
    passwords = iter(["first", "second"])
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: next(passwords))
    assert module.main(args) == 2
    helper.assert_not_called()
    monkeypatch.setattr(module.getpass, "getpass", lambda prompt: "correct secret")
    writer = Mock()
    monkeypatch.setattr(module, "write_private_json", writer)
    assert module.main(args) == 0
    assert writer.call_args.args[1] == {"accounts": [account]}
    assert writer.call_args.kwargs == {"replace": True}


def test_serve_passes_only_fixed_loopback_tls_options(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    from cloudsecops_live import workspace_cli as module

    config = SimpleNamespace(
        origin="https://127.0.0.1:8443", certificate=Path("cert"), key=Path("key"), validate=Mock()
    )
    monkeypatch.setattr(module, "load_config", lambda path: config)
    monkeypatch.setitem(
        sys.modules,
        "cloudsecops_live.workspace_web",
        SimpleNamespace(create_app=lambda config: "app"),
    )
    runner = Mock()
    monkeypatch.setattr(uvicorn, "run", runner)
    assert module.main(["serve", "--config", "runtime"]) == 0
    config.validate.assert_called_once()
    assert runner.call_args.kwargs == {
        "host": "127.0.0.1",
        "port": 8443,
        "ssl_certfile": "cert",
        "ssl_keyfile": "key",
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "access_log": False,
        "log_level": "critical",
        "server_header": False,
        "limit_concurrency": 8,
        "timeout_keep_alive": 5,
        "h11_max_incomplete_event_size": 16384,
    }


def test_private_writer_is_exclusive_and_replacement_stays_private(tmp_path: Path) -> None:
    from cloudsecops_live.workspace_config import write_private_json
    from cloudsecops_live.workspace_tls import private_file

    path = tmp_path / "config"
    write_private_json(path, {"fixture": 1})
    with pytest.raises(ValueError):
        write_private_json(path, {"fixture": 2})
    assert json.loads(private_file(path, max_bytes=100)) == {"fixture": 1}
    write_private_json(path, {"fixture": 3}, replace=True)
    assert json.loads(private_file(path, max_bytes=100)) == {"fixture": 3}
    assert not list(tmp_path.glob("*.tmp"))


def test_publicly_readable_private_file_is_rejected(tmp_path: Path) -> None:
    import subprocess

    from cloudsecops_live.workspace_tls import private_file, restrict_private

    path = tmp_path / "private"
    path.write_bytes(b"fixture")
    restrict_private(path)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:R"], check=True, capture_output=True
        )
    else:
        path.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe_private_permissions"):
        private_file(path, max_bytes=100)


@pytest.mark.parametrize("case", ["expired", "future", "missing_san", "wrong_ip", "corrupt"])
def test_tls_rejects_expired_future_and_wrong_san(
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ipaddress
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from cloudsecops_live import workspace_tls as module

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])
    now = datetime.now(UTC)
    start, end = now - timedelta(days=1), now + timedelta(days=1)
    if case == "expired":
        start, end = now - timedelta(days=2), now - timedelta(days=1)
    elif case == "future":
        start, end = now + timedelta(days=1), now + timedelta(days=2)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
    )
    if case != "missing_san":
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(
                        ipaddress.ip_address("127.0.0.2" if case == "wrong_ip" else "127.0.0.1")
                    )
                ]
            ),
            critical=False,
        )
    cert_bytes = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    if case == "corrupt":
        cert_bytes = b"invalid certificate"
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    monkeypatch.setattr(
        module,
        "private_file",
        lambda path, **kwargs: cert_bytes if path.name == "certificate" else key_bytes,
    )
    with pytest.raises(ValueError):
        module.validate_tls(Path("certificate"), Path("key"))


def test_maintenance_reader_requires_explicit_safe_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    from cloudsecops_live import workspace_cli as module

    value: dict[str, object] = {"dsn": "postgresql://fixture@127.0.0.1:55432/cloudsecops_lab"}
    monkeypatch.setattr(module, "private_file", lambda *args, **kwargs: json.dumps(value).encode())
    assert module._maintenance(Path("unused"))._values["host"] == "127.0.0.1"
    value["dsn"] = 123
    with pytest.raises(ValueError):
        module._maintenance(Path("unused"))


@pytest.mark.parametrize(
    "covered,missing,expected", [(84, False, 1), (85, False, 0), (85, True, 2)]
)
def test_security_branch_gate_is_separate_and_requires_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    covered: int,
    missing: bool,
    expected: int,
) -> None:
    from scripts import check_coverage as module

    report = {"meta": {"branch_coverage": True}, "files": {}}
    for name in (*module.FOUNDATION, *module.SECURITY):
        report["files"][f"src/cloudsecops_live/{name}.py"] = {
            "summary": {
                "num_statements": 100,
                "covered_lines": 95,
                "num_branches": 100,
                "covered_branches": covered if name in module.SECURITY else 95,
            }
        }
    if missing:
        report["files"].pop("src/cloudsecops_live/workspace_auth.py")
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(report))
    monkeypatch.setattr(sys, "argv", ["check_coverage.py", str(path), "--require-security"])
    assert module.main() == expected
