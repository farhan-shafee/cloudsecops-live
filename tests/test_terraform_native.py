"""Independent hostile-input tests for credential-free native Terraform checks.

These tests use hand-written protocol fixtures. They never run Terraform, GPG,
provider binaries, downloads, PostgreSQL, or cloud clients.
"""

import copy
import importlib
import json
import os
import stat
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def native():
    return importlib.import_module("scripts.terraform_native")


def valid_result() -> dict:
    return {
        "format_version": "1.0",
        "valid": True,
        "error_count": 0,
        "warning_count": 0,
        "diagnostics": [],
    }


def test_native_validation_accepts_complete_success(native) -> None:
    assert isinstance(native.parse_validate_output(json.dumps(valid_result()), 0), dict)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "Terraform failed before starting validation",
        "[]",
        "null",
        "{}",
        '{"format_version":"1.0","valid":true,"valid":false}',
        '{"format_version":"1.0","valid":true,"error_count":NaN}',
        json.dumps(valid_result()) + " unexpected trailing output",
    ],
)
def test_nonjson_duplicate_nonfinite_or_incomplete_validation_fails(native, payload: str) -> None:
    with pytest.raises(native.NativeError):
        native.parse_validate_output(payload, 0)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("format_version", "2.0"),
        ("format_version", 1.0),
        ("valid", 1),
        ("valid", "true"),
        ("valid", False),
        ("error_count", True),
        ("error_count", -1),
        ("error_count", 0.5),
        ("error_count", "0"),
        ("error_count", 1),
        ("warning_count", False),
        ("warning_count", -1),
        ("warning_count", 1),
        ("diagnostics", {}),
        ("diagnostics", [None]),
        ("diagnostics", [{"severity": "error", "summary": "failure"}]),
        ("diagnostics", [{"severity": "warning", "summary": "advice"}]),
    ],
)
def test_wrong_types_unsupported_versions_and_contradictory_counts_fail(
    native, key: str, value: object
) -> None:
    result = valid_result()
    result[key] = value
    with pytest.raises(native.NativeError):
        native.parse_validate_output(json.dumps(result), 0)


@pytest.mark.parametrize(
    "key", ["format_version", "valid", "error_count", "warning_count", "diagnostics"]
)
def test_each_required_validation_field_is_mandatory(native, key: str) -> None:
    result = valid_result()
    del result[key]
    with pytest.raises(native.NativeError):
        native.parse_validate_output(json.dumps(result), 0)


@pytest.mark.parametrize("returncode", [1, 2, -9])
def test_success_shaped_output_never_overrides_failed_process(native, returncode: int) -> None:
    with pytest.raises(native.NativeError):
        native.parse_validate_output(json.dumps(valid_result()), returncode)


def test_validation_error_does_not_echo_untrusted_diagnostics(native) -> None:
    marker = "SYNTHETIC-PRIVATE-DIAGNOSTIC-MARKER"
    result = valid_result()
    result.update(
        valid=False,
        error_count=1,
        diagnostics=[{"severity": "error", "summary": marker, "detail": marker}],
    )
    with pytest.raises(native.NativeError) as failure:
        native.parse_validate_output(json.dumps(result), 1)
    assert marker not in str(failure.value)


@pytest.fixture
def configuration() -> dict:
    return {
        "terraform": {
            "required_providers": {"aws": {"source": "hashicorp/aws", "version": "= 6.71.0"}}
        },
        "provider": {
            "aws": {
                "region": "us-east-1",
                "assume_role": [{"role_arn": "${var.provisioner_role_arn}"}],
            }
        },
        "resource": {
            "aws_s3_bucket": {
                "archive": {
                    "bucket": "${var.archive_bucket_name}",
                    "force_destroy": False,
                    "lifecycle": {"prevent_destroy": True},
                }
            },
            "aws_cloudtrail": {
                "management": {
                    "name": "cloudsecops-sandbox-management",
                    "event_selector": [
                        {"include_management_events": True, "read_write_type": "All"}
                    ],
                    "depends_on": ["aws_s3_bucket.archive"],
                    "lifecycle": {"prevent_destroy": True},
                }
            },
        },
    }


@pytest.fixture
def schema() -> dict:
    return {
        "format_version": "1.0",
        "provider_schemas": {
            "registry.terraform.io/hashicorp/aws": {
                "provider": {
                    "version": 0,
                    "block": {
                        "attributes": {"region": {"type": "string", "optional": True}},
                        "block_types": {
                            "assume_role": {
                                "nesting_mode": "list",
                                "max_items": 1,
                                "block": {
                                    "attributes": {"role_arn": {"type": "string", "required": True}}
                                },
                            }
                        },
                    },
                },
                "resource_schemas": {
                    "aws_s3_bucket": {
                        "version": 0,
                        "block": {
                            "attributes": {
                                "bucket": {"type": "string", "optional": True},
                                "force_destroy": {"type": "bool", "optional": True},
                            }
                        },
                    },
                    "aws_cloudtrail": {
                        "version": 0,
                        "block": {
                            "attributes": {"name": {"type": "string", "required": True}},
                            "block_types": {
                                "event_selector": {
                                    "nesting_mode": "set",
                                    "block": {
                                        "attributes": {
                                            "include_management_events": {
                                                "type": "bool",
                                                "optional": True,
                                            },
                                            "read_write_type": {
                                                "type": "string",
                                                "optional": True,
                                            },
                                        }
                                    },
                                }
                            },
                        },
                    },
                },
                "data_source_schemas": {},
            }
        },
    }


def test_schema_checks_used_provider_and_resource_blocks_without_provider_metaarguments(
    native, schema: dict, configuration: dict
) -> None:
    assert isinstance(native.check_provider_schema(schema, configuration), dict)


@pytest.mark.parametrize(
    "path",
    [
        ("format_version",),
        ("provider_schemas",),
        ("provider_schemas", "registry.terraform.io/hashicorp/aws"),
        ("provider_schemas", "registry.terraform.io/hashicorp/aws", "provider"),
        ("provider_schemas", "registry.terraform.io/hashicorp/aws", "provider", "block"),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "provider",
            "block",
            "attributes",
            "region",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "provider",
            "block",
            "block_types",
            "assume_role",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "provider",
            "block",
            "block_types",
            "assume_role",
            "block",
            "attributes",
            "role_arn",
        ),
        ("provider_schemas", "registry.terraform.io/hashicorp/aws", "resource_schemas"),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "resource_schemas",
            "aws_s3_bucket",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "resource_schemas",
            "aws_s3_bucket",
            "block",
            "attributes",
            "bucket",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "resource_schemas",
            "aws_s3_bucket",
            "block",
            "attributes",
            "force_destroy",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "resource_schemas",
            "aws_cloudtrail",
            "block",
            "block_types",
            "event_selector",
        ),
        (
            "provider_schemas",
            "registry.terraform.io/hashicorp/aws",
            "resource_schemas",
            "aws_cloudtrail",
            "block",
            "block_types",
            "event_selector",
            "block",
            "attributes",
            "read_write_type",
        ),
    ],
)
def test_missing_used_provider_resource_attribute_or_nested_block_fails(
    native, schema: dict, configuration: dict, path: tuple[str, ...]
) -> None:
    node = schema
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


@pytest.mark.parametrize("version", [None, 1, "2.0", "unexpected"])
def test_unsupported_schema_format_fails(
    native, schema: dict, configuration: dict, version
) -> None:
    schema["format_version"] = version
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


def test_unexpected_provider_schema_fails(native, schema: dict, configuration: dict) -> None:
    schema["provider_schemas"]["registry.terraform.io/hashicorp/null"] = {
        "provider": {"version": 0, "block": {}},
        "resource_schemas": {},
    }
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


@pytest.mark.parametrize("mode", [None, "unknown", 1])
def test_unsupported_used_nested_block_mode_fails(
    native, schema: dict, configuration: dict, mode
) -> None:
    provider = schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"]
    provider["provider"]["block"]["block_types"]["assume_role"]["nesting_mode"] = mode
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


def test_unknown_used_resource_argument_fails(native, schema: dict, configuration: dict) -> None:
    configuration["resource"]["aws_s3_bucket"]["archive"]["unreviewed_option"] = True
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


@pytest.mark.parametrize("attribute_type", [None, 1, "not-a-terraform-type", ["list"]])
def test_malformed_used_attribute_schema_fails(
    native, schema: dict, configuration: dict, attribute_type
) -> None:
    provider = schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"]
    provider["resource_schemas"]["aws_s3_bucket"]["block"]["attributes"]["bucket"]["type"] = (
        attribute_type
    )
    with pytest.raises(native.NativeError):
        native.check_provider_schema(schema, configuration)


@pytest.fixture
def official_manifest() -> str:
    return (
        "cb57bbcaf0fa3a70ea29b60d183d3a0dd020f041b18da5d1725d2acd17fa7d59  "
        "terraform-provider-aws_6.71.0_linux_amd64.zip\n"
        "55616730a485c9c7283546a84f1ac5f8341152c5572338a54fc7af5f69ebfb92  "
        "terraform-provider-aws_6.71.0_windows_amd64.zip\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  "
        "terraform-provider-aws_6.71.0_darwin_arm64.zip\n"
    )


@pytest.fixture
def lock_text() -> str:
    return """# Synthetic signed-manifest fixture; never install these packages.
provider "registry.terraform.io/hashicorp/aws" {
  version = "6.71.0"
  constraints = "6.71.0"
  hashes = [
    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
    "zh:cb57bbcaf0fa3a70ea29b60d183d3a0dd020f041b18da5d1725d2acd17fa7d59",
    "zh:55616730a485c9c7283546a84f1ac5f8341152c5572338a54fc7af5f69ebfb92",
    "zh:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  ]
}
"""


def test_lock_accepts_exact_aws_release_and_signed_platform_checksums(
    native, lock_text: str, official_manifest: str
) -> None:
    assert isinstance(native.check_lock(lock_text, official_manifest), dict)


@pytest.mark.parametrize(
    "digest",
    [
        "cb57bbcaf0fa3a70ea29b60d183d3a0dd"  # pragma: allowlist secret - public SHA256
        "020f041b18da5d1725d2acd17fa7d59",  # pragma: allowlist secret - public SHA256
        "55616730a485c9c7283546a84f1ac5f83"  # pragma: allowlist secret - public SHA256
        "41152c5572338a54fc7af5f69ebfb92",  # pragma: allowlist secret - public SHA256
        "c" * 64,
    ],
)
def test_removing_each_signed_archive_hash_is_incomplete(
    native, lock_text: str, official_manifest: str, digest: str
) -> None:
    damaged = lock_text.replace(f'    "zh:{digest}",\n', "")
    with pytest.raises(native.NativeError):
        native.check_lock(damaged, official_manifest)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('version = "6.71.0"', 'version = "6.70.0"'),
        ('constraints = "6.71.0"', 'constraints = ">= 6.0.0"'),
        ("registry.terraform.io/hashicorp/aws", "registry.terraform.io/attacker/aws"),
        (
            '"zh:cb57bbcaf0fa3a70ea29b60d183d3a0dd020f041b18da5d1725d2acd17fa7d59"',
            '"zh:' + "d" * 64 + '"',
        ),
        ('"h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="', '"h1:invalid"'),
        ("  hashes = [", "  unreviewed = true\n  hashes = ["),
    ],
)
def test_changed_release_origin_constraint_hash_or_lock_field_fails(
    native, lock_text: str, official_manifest: str, old: str, new: str
) -> None:
    with pytest.raises(native.NativeError):
        native.check_lock(lock_text.replace(old, new), official_manifest)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "{}",
        'provider "registry.terraform.io/hashicorp/aws" {}',
        'terraform { backend "s3" { bucket = "unexpected" } }',
        'resource "null_resource" "unexpected" {}',
    ],
)
def test_missing_or_unrelated_lock_payload_fails(
    native, official_manifest: str, payload: str
) -> None:
    with pytest.raises(native.NativeError):
        native.check_lock(payload, official_manifest)


def test_second_provider_cannot_hide_after_valid_lock(
    native, lock_text: str, official_manifest: str
) -> None:
    extra = '\nprovider "registry.terraform.io/hashicorp/null" { version = "3.2.4" }\n'
    with pytest.raises(native.NativeError):
        native.check_lock(lock_text + extra, official_manifest)


def test_duplicate_provider_block_fails(native, lock_text: str, official_manifest: str) -> None:
    with pytest.raises(native.NativeError):
        native.check_lock(lock_text + lock_text, official_manifest)


def test_manifest_missing_either_required_platform_fails(
    native, lock_text: str, official_manifest: str
) -> None:
    for platform in ("linux_amd64", "windows_amd64"):
        incomplete = "\n".join(
            line for line in official_manifest.splitlines() if platform not in line
        )
        with pytest.raises(native.NativeError):
            native.check_lock(lock_text, incomplete)


class SyntheticEnvironment(dict):
    """Permit explicit OS-key lookup, but catch ambient key/value discovery."""

    def __iter__(self):
        raise AssertionError("ambient environment must not be enumerated")

    def keys(self):
        raise AssertionError("ambient environment keys must not be enumerated")

    def items(self):
        raise AssertionError("ambient environment entries must not be enumerated")

    def copy(self):
        raise AssertionError("ambient environment must not be copied")


def test_isolated_environment_ignores_synthetic_secrets_hooks_and_proxies(
    native, monkeypatch, tmp_path: Path
) -> None:
    marker = "SYNTHETIC-ENVIRONMENT-SECRET-MARKER"
    fake = SyntheticEnvironment(
        {
            "SystemRoot": "C:/Windows",
            "WINDIR": "C:/Windows",
            "PATH": "C:/Synthetic/System32",
            "AWS_ACCESS_KEY_ID": marker,
            "AWS_SECRET_ACCESS_KEY": marker,
            "AWS_SESSION_TOKEN": marker,
            "AWS_PROFILE": marker,
            "AWS_WEB_IDENTITY_TOKEN_FILE": marker,
            "AWS_CONTAINER_CREDENTIALS_FULL_URI": marker,
            "GITHUB_TOKEN": marker,
            "TF_TOKEN_app_terraform_io": marker,
            "TF_VAR_account_id": marker,
            "TF_CLI_ARGS": "-var-file=" + marker,
            "TF_CLI_ARGS_init": "-backend-config=" + marker,
            "TF_CLI_ARGS_validate": "-var-file=" + marker,
            "TF_LOG": "TRACE",
            "TF_LOG_PATH": marker,
            "TF_REATTACH_PROVIDERS": marker,
            "TF_PLUGIN_CACHE_DIR": marker,
            "TF_CLI_CONFIG_FILE": marker,
            "TERRAFORM_CONFIG": marker,
            "HOME": marker,
            "USERPROFILE": marker,
            "APPDATA": marker,
            "HTTP_PROXY": marker,
            "HTTPS_PROXY": marker,
            "ALL_PROXY": marker,
            "http_proxy": marker,
            "https_proxy": marker,
        }
    )
    monkeypatch.setattr(os, "environ", fake)
    environment = native.isolated_environment(tmp_path)
    assert isinstance(environment, dict)
    assert marker not in json.dumps(environment)
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "GITHUB_TOKEN",
        "TF_TOKEN_app_terraform_io",
        "TF_VAR_account_id",
        "TF_CLI_ARGS",
        "TF_CLI_ARGS_init",
        "TF_CLI_ARGS_validate",
        "TF_LOG",
        "TF_LOG_PATH",
        "TF_REATTACH_PROVIDERS",
        "TF_PLUGIN_CACHE_DIR",
        "TERRAFORM_CONFIG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
    }
    assert not forbidden.intersection(environment)
    assert environment["AWS_EC2_METADATA_DISABLED"] == "true"
    assert environment["TF_INPUT"] in {"0", "false"}
    for name in ("HOME", "TMP", "TEMP", "TMPDIR", "TF_CLI_CONFIG_FILE"):
        location = Path(environment[name]).resolve()
        assert location.is_relative_to(tmp_path.resolve())
    for name in ("USERPROFILE", "APPDATA", "TF_DATA_DIR"):
        if name in environment:
            assert Path(environment[name]).resolve().is_relative_to(tmp_path.resolve())
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        location = Path(environment[name]).resolve()
        assert location.is_relative_to(tmp_path.resolve())
        assert location.read_bytes() == b""
    cli_config = Path(environment["TF_CLI_CONFIG_FILE"]).read_text(encoding="utf-8")
    assert "registry.terraform.io/hashicorp/aws" in cli_config
    assert "disable_checkpoint" in cli_config
    assert "dev_overrides" not in cli_config
    assert "credentials" not in cli_config
    assert "plugin_cache_dir" not in cli_config


def test_source_configuration_fixture_does_not_share_mutable_provider_schema(
    native, schema: dict, configuration: dict
) -> None:
    original = copy.deepcopy(configuration)
    native.check_provider_schema(schema, configuration)
    assert configuration == original


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("version", ["version", "-json"]),
        ("fmt", ["fmt", "-check", "-recursive", "-no-color"]),
        (
            "lock",
            [
                "providers",
                "lock",
                "-platform=linux_amd64",
                "-platform=windows_amd64",
                "registry.terraform.io/hashicorp/aws",
            ],
        ),
        (
            "init",
            ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"],
        ),
        ("validate", ["validate", "-json"]),
        ("schema", ["providers", "schema", "-json"]),
    ],
)
def test_native_commands_have_fixed_arguments_and_cannot_inherit_shell_or_stdin(
    native, monkeypatch, tmp_path: Path, name: str, arguments: list[str]
) -> None:
    binary = tmp_path / "terraform"
    binary.write_bytes(b"SYNTHETIC-NONEXECUTABLE")
    environment = {"HOME": str(tmp_path / "private-home"), "TF_INPUT": "0"}
    observed = []

    def fake_process(command, **kwargs):
        observed.append((command, kwargs))
        kwargs["stdout"].write(b"{}")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(native.subprocess, "run", fake_process)
    output, returncode = native._terraform(binary, name, tmp_path, environment, tmp_path)
    assert (output, returncode) == ("{}", 0)
    assert len(observed) == 1
    command, options = observed[0]
    assert command == [str(binary), *arguments]
    assert options["shell"] is False
    assert options["stdin"] == native.subprocess.DEVNULL
    assert options["env"] == environment
    assert options["cwd"] == tmp_path
    assert options["check"] is False
    assert 0 < options["timeout"] <= 300


@pytest.mark.parametrize(
    "command",
    [
        "plan",
        "apply",
        "destroy",
        "import",
        "refresh",
        "state",
        "workspace",
        "output",
        "console",
        "test",
        "get",
        "login",
        "providers mirror",
        "init -backend=true",
    ],
)
def test_forbidden_or_injected_command_never_reaches_process_boundary(
    native, monkeypatch, tmp_path: Path, command: str
) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("unapproved Terraform command reached process creation")

    monkeypatch.setattr(native.subprocess, "run", forbidden)
    with pytest.raises(native.NativeError):
        native._terraform(tmp_path / "verified-terraform", command, tmp_path, {}, tmp_path)


def test_relative_terraform_binary_never_uses_ambient_path(
    native, monkeypatch, tmp_path: Path
) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("relative executable reached process creation")

    monkeypatch.setattr(native.subprocess, "run", forbidden)
    with pytest.raises(native.NativeError):
        native._terraform(Path("terraform"), "version", tmp_path, {}, tmp_path)


def test_process_timeout_is_a_fixed_sanitized_failure(native, monkeypatch, tmp_path: Path) -> None:
    marker = "SYNTHETIC-TIMEOUT-PRIVATE-MARKER"

    def timed_out(*args, **kwargs):
        raise native.subprocess.TimeoutExpired(marker, 1, output=marker, stderr=marker)

    monkeypatch.setattr(native.subprocess, "run", timed_out)
    with pytest.raises(native.NativeError) as failure:
        native._terraform(tmp_path / "terraform", "validate", tmp_path, {}, tmp_path)
    assert str(failure.value) == "command_timeout"
    assert marker not in str(failure.value)


def test_verified_archive_extracts_only_expected_binary_and_reports_its_hash(
    native, tmp_path: Path
) -> None:
    archive = tmp_path / "fixture.zip"
    destination = tmp_path / "binary"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("terraform", b"hello")
        package.writestr("LICENSE.txt", b"public fixture")
    assert native._archive_binary(archive, "terraform", 32, destination) == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1"  # pragma: allowlist secret - public SHA256
        "b161e5c1fa7425e73043362938b9824"  # pragma: allowlist secret - public SHA256
    )
    assert destination.read_bytes() == b"hello"
    assert not (tmp_path / "LICENSE.txt").exists()


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "sub/../../escape", "C:drive", "sub\\escape"]
)
def test_unsafe_archive_member_rejects_entire_package_before_extraction(
    native, tmp_path: Path, name: str
) -> None:
    archive = tmp_path / "unsafe.zip"
    destination = tmp_path / "binary"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("terraform", b"hello")
        member = zipfile.ZipInfo("placeholder")
        member.filename = name
        package.writestr(member, b"untrusted")
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 32, destination)
    assert not destination.exists()


def test_archive_symlink_member_cannot_replace_binary(native, tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("terraform")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(link, b"/private/target")
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 32, tmp_path / "binary")


def test_duplicate_archive_binary_is_ambiguous_and_rejected(native, tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("terraform", b"first")
            package.writestr("terraform", b"second")
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 32, tmp_path / "binary")


@pytest.mark.parametrize("payload", [b"", b"not-a-zip"])
def test_corrupt_archive_never_creates_executable(native, tmp_path: Path, payload: bytes) -> None:
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(payload)
    destination = tmp_path / "binary"
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 32, destination)
    assert not destination.exists()


def test_archive_missing_binary_is_not_success(native, tmp_path: Path) -> None:
    archive = tmp_path / "missing.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("LICENSE.txt", b"public fixture")
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 32, tmp_path / "binary")


def test_archive_binary_size_limit_is_enforced_before_write(native, tmp_path: Path) -> None:
    archive = tmp_path / "large.zip"
    destination = tmp_path / "binary"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("terraform", b"123456789")
    with pytest.raises(native.NativeError):
        native._archive_binary(archive, "terraform", 8, destination)
    assert not destination.exists()


@pytest.mark.parametrize(
    "signature_status",
    [
        "",
        "[GNUPG:] GOODSIG 34365D9472D7468F HashiCorp\n",
        "[GNUPG:] BADSIG 34365D9472D7468F HashiCorp\n",
        "[GNUPG:] VALIDSIG DEADBEEF 2026-01-01 1 0 4 0 1 8 00 " + "F" * 40 + "\n",
        (
            "[GNUPG:] BADSIG 34365D9472D7468F HashiCorp\n"
            "[GNUPG:] VALIDSIG C874011F0AB405110D02105534365D9472D7468F "
            "2026-01-01 1 0 4 0 1 8 00 C874011F0AB405110D02105534365D9472D7468F\n"
        ),
    ],
)
def test_signature_success_requires_exact_pinned_primary_fingerprint(
    native, monkeypatch, tmp_path: Path, signature_status: str
) -> None:
    def fake_process(command, cwd, environment, logs, label, timeout):
        if "--show-keys" in command:
            return (
                "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264:::::scSC:\n"
                "fpr:::::::::C874011F0AB405110D02105534365D9472D7468F:\n",
                0,
            )
        if "--verify" in command:
            return signature_status, 0
        return "", 0

    monkeypatch.setattr(native, "_process", fake_process)
    with pytest.raises(native.NativeError) as failure:
        native._verify_signatures(tmp_path, {}, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert str(failure.value) == "signature_failed"


def test_signature_verifier_uses_private_keyring_and_disables_ambient_options_and_keyservers(
    native, monkeypatch, tmp_path: Path
) -> None:
    commands = []
    environment = {"HOME": str(tmp_path / "home")}

    def fake_process(command, cwd, env, logs, label, timeout):
        commands.append((command, env))
        if "--show-keys" in command:
            return (
                "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264:::::scSC:\n"
                "fpr:::::::::C874011F0AB405110D02105534365D9472D7468F:\n",
                0,
            )
        if "--verify" in command:
            return (
                "[GNUPG:] VALIDSIG C874011F0AB405110D02105534365D9472D7468F "
                "2026-01-01 1 0 4 0 1 8 00 C874011F0AB405110D02105534365D9472D7468F\n",
                0,
            )
        return "", 0

    monkeypatch.setattr(native, "_process", fake_process)
    native._verify_signatures(tmp_path, environment, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert len(commands) == 3
    for command, env in commands:
        assert command[0] == "/usr/bin/gpg"
        assert "--no-options" in command
        assert "--batch" in command
        assert "--no-auto-key-retrieve" in command
        assert "--no-auto-key-import" in command
        keyring = Path(command[command.index("--homedir") + 1])
        assert keyring.resolve().is_relative_to(tmp_path.resolve())
        assert env == environment


def test_wrong_signing_key_is_rejected_before_import_or_verification(
    native, monkeypatch, tmp_path: Path
) -> None:
    observed = []

    def fake_process(command, cwd, env, logs, label, timeout):
        observed.append(command)
        return "pub:-:4096:1:DEADBEEF:1::::::scSC:\nfpr:::::::::" + "F" * 40 + ":\n", 0

    monkeypatch.setattr(native, "_process", fake_process)
    with pytest.raises(native.NativeError):
        native._verify_signatures(tmp_path, {}, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert len(observed) == 1
    assert "--show-keys" in observed[0]


@pytest.fixture
def vendor_key_listing() -> str:
    """Public vendor keyring: expired retired subkey plus valid selected subkey."""
    return (
        "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264:::::scSC:\n"
        "fpr:::::::::C874011F0AB405110D02105534365D9472D7468F:\n"
        "sub:e:4096:1:B0B441097685B676:1587338112:1650413312:::::s:\n"
        "fpr:::::::::B36CBA91A2C0730C435FC280B0B441097685B676:\n"
        "sub:-:4096:1:C820C6D5CD27AB87:1740870922:1898637322:::::s:\n"
        "fpr:::::::::374EC75B485913604A831CC7C820C6D5CD27AB87:\n"
    )


@pytest.fixture
def vendor_signature_status() -> str:
    """GPG reports old-key expiry even when a current subkey signed correctly."""
    return (
        "[GNUPG:] NEWSIG\n"
        "[GNUPG:] KEY_CONSIDERED C874011F0AB405110D02105534365D9472D7468F 0\n"
        "[GNUPG:] KEYEXPIRED 1650413312\n"
        "[GNUPG:] GOODSIG C820C6D5CD27AB87 HashiCorp Security\n"
        "[GNUPG:] VALIDSIG 374EC75B485913604A831CC7C820C6D5CD27AB87 "
        "2026-10-15 1792022400 0 4 0 1 10 00 C874011F0AB405110D02105534365D9472D7468F\n"
        "[GNUPG:] TRUST_UNDEFINED 0 pgp\n"
    )


def signature_protocol_double(native, monkeypatch, key_listing: str, signature_status: str) -> None:
    """Replace GPG execution only; run the real key/status binding checks."""

    def fake_process(command, cwd, env, logs, label, timeout):
        if "--show-keys" in command:
            return key_listing, 0
        if "--verify" in command:
            return signature_status, 0
        if "--import" in command:
            return "", 0
        pytest.fail("unexpected GPG operation")

    monkeypatch.setattr(native, "_process", fake_process)
    monkeypatch.setattr(native.time, "time", lambda: 1793664000)


def test_retired_unselected_key_expiry_does_not_reject_current_vendor_signature(
    native, monkeypatch, tmp_path: Path, vendor_key_listing: str, vendor_signature_status: str
) -> None:
    signature_protocol_double(native, monkeypatch, vendor_key_listing, vendor_signature_status)
    result = native._verify_signatures(tmp_path, {}, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert result["signing_fingerprint"] == (
        "C874011F0AB405110D02105534365D9472D7468F"  # pragma: allowlist secret - public PGP
    )
    assert result["selected_signer_fingerprints"] == [
        "374EC75B485913604A831CC7C820C6D5CD27AB87"  # pragma: allowlist secret - public PGP
    ]
    assert result["ignored_retired_expiry_count"] == 1


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "sub:-:4096:1:C820C6D5CD27AB87:1740870922:1898637322",
            "sub:e:4096:1:C820C6D5CD27AB87:1740870922:1650413312",
        ),
        (
            "sub:-:4096:1:C820C6D5CD27AB87:1740870922:1898637322",
            "sub:-:4096:1:C820C6D5CD27AB87:1587338112:1650413312",
        ),
        (
            "sub:-:4096:1:C820C6D5CD27AB87:1740870922:1898637322",
            "sub:r:4096:1:C820C6D5CD27AB87:1740870922:1898637322",
        ),
        (
            "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264",
            "pub:e:4096:1:34365D9472D7468F:1617049246:1650413312",
        ),
        (
            "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264",
            "pub:-:4096:1:34365D9472D7468F:1617049246:1650413312",
        ),
        (
            "pub:-:4096:1:34365D9472D7468F:1617049246:1898637264",
            "pub:r:4096:1:34365D9472D7468F:1617049246:1898637264",
        ),
        (
            "sub:-:4096:1:C820C6D5CD27AB87:1740870922:1898637322:::::s:\n"
            "fpr:::::::::374EC75B485913604A831CC7C820C6D5CD27AB87:\n",
            "",
        ),
    ],
)
def test_expired_revoked_or_missing_selected_key_or_primary_never_uses_retired_key_exception(
    native,
    monkeypatch,
    tmp_path: Path,
    vendor_key_listing: str,
    vendor_signature_status: str,
    old: str,
    new: str,
) -> None:
    signature_protocol_double(
        native, monkeypatch, vendor_key_listing.replace(old, new), vendor_signature_status
    )
    with pytest.raises(native.NativeError) as failure:
        native._verify_signatures(tmp_path, {}, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert str(failure.value) == "signature_failed"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("KEYEXPIRED 1650413312", "KEYEXPIRED 1710000000"),
        ("KEYEXPIRED 1650413312", "KEYEXPIRED 1898637322"),
        ("KEYEXPIRED 1650413312", "KEYEXPIRED unparseable"),
        ("KEYEXPIRED 1650413312", "KEYREVOKED"),
        ("KEYEXPIRED 1650413312", "EXPKEYSIG C820C6D5CD27AB87 HashiCorp Security"),
        ("KEYEXPIRED 1650413312", "REVKEYSIG C820C6D5CD27AB87 HashiCorp Security"),
        (
            "VALIDSIG 374EC75B485913604A831CC7C820C6D5CD27AB87",
            "VALIDSIG EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        ),
    ],
)
def test_unknown_expiry_or_selected_signer_failures_remain_fatal(
    native,
    monkeypatch,
    tmp_path: Path,
    vendor_key_listing: str,
    vendor_signature_status: str,
    old: str,
    new: str,
) -> None:
    signature_protocol_double(
        native, monkeypatch, vendor_key_listing, vendor_signature_status.replace(old, new)
    )
    with pytest.raises(native.NativeError) as failure:
        native._verify_signatures(tmp_path, {}, [(tmp_path / "SUMS", tmp_path / "SUMS.sig")])
    assert str(failure.value) == "signature_failed"


@pytest.mark.parametrize(
    "url",
    [
        "http://releases.hashicorp.com/terraform/1.17.1/terraform_1.17.1_linux_amd64.zip",
        "https://attacker.invalid/terraform_1.17.1_linux_amd64.zip",
        "https://releases.hashicorp.com/terraform/1.17.1/../../unexpected",
        "https://releases.hashicorp.com/terraform/1.17.1/terraform_1.17.1_linux_amd64.zip?token=x",
    ],
)
def test_unapproved_download_endpoint_fails_before_opening_network(
    native, monkeypatch, tmp_path: Path, url: str
) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("unapproved download URL reached network setup")

    monkeypatch.setattr(native.urllib.request, "build_opener", forbidden)
    with pytest.raises(native.NativeError):
        native._download(url, tmp_path / "download", 1024)


def emulate_download_transport(
    native,
    monkeypatch,
    frames: list[tuple[bytes, float]],
    *,
    status: int = 200,
    final_url: str | None = None,
    failure: Exception | None = None,
) -> dict:
    """Use no sockets or CA files while exercising the real download loop."""
    url = "https://www.hashicorp.com/.well-known/pgp-key.txt"
    observed = {"clock": 0.0, "trust_files": [], "reads": []}
    remaining = iter(frames)

    class Response:
        def __init__(self):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return final_url or url

        def read1(self, size):
            observed["reads"].append(size)
            if failure is not None:
                raise failure
            payload, elapsed = next(remaining, (b"", 0.0))
            observed["clock"] += elapsed
            return payload

        def read(self, size):
            pytest.fail("download uses buffered reads that can hide slow trickle past its deadline")

    def make_context(protocol):
        observed["protocol"] = protocol
        context = SimpleNamespace(load_verify_locations=observed["trust_files"].append)

        def trust_file(*, cafile):
            observed["trust_files"].append(cafile)

        context.load_verify_locations = trust_file
        observed["context"] = context
        return context

    def build_opener(*handlers):
        observed["handlers"] = handlers

        def open_response(requested_url, timeout):
            observed["url"] = requested_url
            observed["timeout"] = timeout
            return Response()

        return SimpleNamespace(open=open_response)

    monkeypatch.setattr(native.ssl, "SSLContext", make_context)
    monkeypatch.setattr(native.urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(native.time, "monotonic", lambda: observed["clock"])
    return observed


def test_download_pins_tls_trust_disables_proxies_and_writes_bounded_complete_response(
    native, monkeypatch, tmp_path: Path
) -> None:
    observed = emulate_download_transport(native, monkeypatch, [(b"pub", 1.0), (b"lic", 1.0)])
    destination = tmp_path / "vendor-key"
    native._download("https://www.hashicorp.com/.well-known/pgp-key.txt", destination, 6)
    assert destination.read_bytes() == b"public"
    assert observed["protocol"] == native.ssl.PROTOCOL_TLS_CLIENT
    assert observed["context"].minimum_version == native.ssl.TLSVersion.TLSv1_2
    assert observed["trust_files"] == ["/etc/ssl/certs/ca-certificates.crt"]
    assert observed["timeout"] == 45
    proxies = [
        handler
        for handler in observed["handlers"]
        if isinstance(handler, native.urllib.request.ProxyHandler)
    ]
    assert len(proxies) == 1 and proxies[0].proxies == {}
    assert any(isinstance(handler, native._NoRedirect) for handler in observed["handlers"])


@pytest.mark.parametrize(
    ("frames", "status", "final_url", "limit", "code"),
    [
        ([], 200, None, 4, "download_failed"),
        ([(b"body", 0.0)], 302, None, 4, "download_failed"),
        ([(b"body", 0.0)], 404, None, 4, "download_failed"),
        ([(b"body", 0.0)], 200, "https://attacker.invalid/redirect", 4, "download_failed"),
        ([(b"abcde", 0.0)], 200, None, 4, "download_too_large"),
        ([(b"body", 301.0)], 200, None, 4, "download_failed"),
    ],
)
def test_download_status_redirect_empty_oversize_and_elapsed_failures_are_closed(
    native, monkeypatch, tmp_path: Path, frames, status, final_url, limit, code
) -> None:
    emulate_download_transport(native, monkeypatch, frames, status=status, final_url=final_url)
    with pytest.raises(native.NativeError) as failure:
        native._download(
            "https://www.hashicorp.com/.well-known/pgp-key.txt", tmp_path / "key", limit
        )
    assert str(failure.value) == code


def test_download_completion_after_overall_deadline_cannot_be_accepted(
    native, monkeypatch, tmp_path: Path
) -> None:
    emulate_download_transport(native, monkeypatch, [(b"body", 299.0), (b"", 2.0)])
    with pytest.raises(native.NativeError) as failure:
        native._download("https://www.hashicorp.com/.well-known/pgp-key.txt", tmp_path / "key", 4)
    assert str(failure.value) == "download_failed"


def test_download_transport_error_is_sanitized_and_cannot_leave_success(
    native, monkeypatch, tmp_path: Path
) -> None:
    marker = "SYNTHETIC-TRANSPORT-PRIVATE-MARKER"
    emulate_download_transport(native, monkeypatch, [], failure=OSError(marker))
    with pytest.raises(native.NativeError) as failure:
        native._download("https://www.hashicorp.com/.well-known/pgp-key.txt", tmp_path / "key", 4)
    assert str(failure.value) == "download_failed"
    assert marker not in str(failure.value)


def test_redirect_handler_rejects_redirect_instead_of_following(native) -> None:
    with pytest.raises(native.NativeError):
        native._NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "https://attacker.invalid/redirect"
        )


def test_failed_receipt_contains_fixed_codes_without_raw_argument_or_absolute_paths(
    native, tmp_path: Path, capsys
) -> None:
    marker = "SYNTHETIC-INVALID-REVISION-MARKER"
    receipt = tmp_path / "receipt.json"
    assert (
        native.main(
            [
                "--source-revision",
                marker,
                "--work-parent",
                str(tmp_path / "private"),
                "--receipt",
                str(receipt),
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    artifact = receipt.read_text(encoding="utf-8")
    document = json.loads(artifact)
    assert document["status"] == "failed"
    assert document["error_code"] == "invalid_source_revision"
    for content in (artifact, output.out, output.err):
        assert marker not in content
        assert str(tmp_path) not in content


@pytest.mark.parametrize("failure_point", ["signature", "archive"])
def test_toolchain_provenance_failure_never_extracts_or_executes_downloaded_binary(
    native, monkeypatch, tmp_path: Path, official_manifest: str, failure_point: str
) -> None:
    downloads = []

    def download(url, destination, limit):
        downloads.append(url)
        if destination.name == "terraform_1.17.1_SHA256SUMS":
            destination.write_text(
                "4638628058e71a55212b1c563712eac03b902128f40740f3dc8174df12135061  "
                "terraform_1.17.1_linux_amd64.zip\n"
                "a3b71365cff94c0f978cf75d86addb075ea1bb6409055ea0ab359bf057d7898a  "
                "terraform_1.17.1_windows_amd64.zip\n",
                encoding="ascii",
            )
        elif destination.name == "terraform-provider-aws_6.71.0_SHA256SUMS":
            destination.write_text(official_manifest, encoding="ascii")
        else:
            destination.write_bytes(b"SYNTHETIC-INVALID-DOWNLOAD")

    def signatures(*args):
        if failure_point == "signature":
            raise native.NativeError("signature_failed")

    def forbidden(*args, **kwargs):
        pytest.fail("unverified downloaded executable reached extraction or execution")

    monkeypatch.setattr(native, "_download", download)
    monkeypatch.setattr(native, "_verify_signatures", signatures)
    monkeypatch.setattr(native, "_archive_binary", forbidden)
    monkeypatch.setattr(native, "_terraform", forbidden)
    with pytest.raises(native.NativeError) as failure:
        native._toolchain(tmp_path, {})
    assert str(failure.value) == (
        "signature_failed" if failure_point == "signature" else "archive_hash_mismatch"
    )
    if failure_point == "signature":
        assert not any(url.endswith(".zip") for url in downloads)


def test_late_provider_archive_hash_failure_prevents_verified_cli_extraction_and_execution(
    native, monkeypatch, tmp_path: Path
) -> None:
    # All three earlier archives match this independently known SHA256("hello").
    digest = (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1"  # pragma: allowlist secret - public SHA256
        "b161e5c1fa7425e73043362938b9824"  # pragma: allowlist secret - public SHA256
    )
    archives = [
        "terraform_1.17.1_linux_amd64.zip",
        "terraform_1.17.1_windows_amd64.zip",
        "terraform-provider-aws_6.71.0_linux_amd64.zip",
        "terraform-provider-aws_6.71.0_windows_amd64.zip",
    ]
    monkeypatch.setattr(native, "ARCHIVE_HASHES", dict.fromkeys(archives, digest))
    observed = []

    def download(url, destination, limit):
        if destination.name.endswith("_SHA256SUMS"):
            prefix = destination.name.removesuffix("_SHA256SUMS") + "_"
            destination.write_text(
                "".join(f"{digest}  {name}\n" for name in archives if name.startswith(prefix)),
                encoding="ascii",
            )
        elif destination.name.endswith(".zip"):
            observed.append(destination.name)
            destination.write_bytes(b"tampered" if destination.name == archives[-1] else b"hello")
        else:
            destination.write_bytes(b"SYNTHETIC-PUBLIC-KEY-OR-SIGNATURE")

    def forbidden(*args, **kwargs):
        pytest.fail("verified CLI was extracted or executed before all provider ZIP hashes passed")

    monkeypatch.setattr(native, "_download", download)
    monkeypatch.setattr(native, "_verify_signatures", lambda *args: {})
    monkeypatch.setattr(native, "_archive_binary", forbidden)
    monkeypatch.setattr(native, "_terraform", forbidden)
    with pytest.raises(native.NativeError) as failure:
        native._toolchain(tmp_path, {})
    assert str(failure.value) == "archive_hash_mismatch"
    assert observed == archives


def emulate_native_dependency(
    native,
    monkeypatch,
    work: Path,
    lock_text: str,
    manifest: str,
    schema: dict,
    failure_stage: str | None = None,
) -> list[str]:
    """Replace external programs while retaining real orchestration/file checks."""
    events = []
    binary = work / "terraform"
    binary.write_bytes(b"SYNTHETIC-NONEXECUTABLE")
    expected_provider_hash = (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1"  # pragma: allowlist secret - public SHA256
        "b161e5c1fa7425e73043362938b9824"  # pragma: allowlist secret - public SHA256
    )

    def toolchain(directory, environment):
        events.append("verified_toolchain")
        return (
            binary,
            expected_provider_hash,
            manifest,
            {
                "signatures_verified": True,
                "signing_fingerprint": (
                    "C874011F0AB405110D02105534365D9472D7468F"  # pragma: allowlist secret - PGP
                ),
                "verified_platforms": ["linux_amd64", "windows_amd64"],
            },
        )

    def terraform(executable, name, cwd, environment, logs, label=None):
        stage = label or name
        events.append(stage)
        assert executable == binary
        if stage == failure_stage:
            return "", 1
        if name == "version":
            return '{"terraform_version":"1.17.1","platform":"linux_amd64"}', 0
        if name == "lock":
            assert {path.name for path in cwd.iterdir()} == {"main.tf.json"}
            (cwd / ".terraform.lock.hcl").write_text(lock_text, encoding="utf-8")
            return "signed by HashiCorp\nsigned by HashiCorp\n", 0
        if name == "fmt":
            assert {path.name for path in cwd.iterdir()} == {"main.tf.json", ".terraform.lock.hcl"}
            return "", 0
        if name == "init":
            installed = (
                cwd
                / ".terraform/providers/registry.terraform.io/hashicorp/aws/6.71.0/linux_amd64"
                / "terraform-provider-aws_v6.71.0_x5"
            )
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(b"hello" if failure_stage != "provider_hash" else b"tampered")
            if stage == "reinit" and failure_stage == "lock_drift":
                (cwd / ".terraform.lock.hcl").write_text("", encoding="utf-8")
            return "", 0
        if name == "validate":
            return json.dumps(valid_result()), 0
        if name == "schema":
            return json.dumps(schema), 0
        pytest.fail("unexpected native command")

    monkeypatch.setattr(native, "_toolchain", toolchain)
    monkeypatch.setattr(native, "_terraform", terraform)
    return events


def test_native_orchestration_requires_schema_and_second_initialization_validation(
    native,
    monkeypatch,
    tmp_path: Path,
    lock_text: str,
    official_manifest: str,
    schema: dict,
    configuration: dict,
) -> None:
    events = emulate_native_dependency(
        native, monkeypatch, tmp_path, lock_text, official_manifest, schema
    )
    result = native._run(tmp_path, json.dumps(configuration), lock_text, False)
    assert events == [
        "verified_toolchain",
        "version",
        "lock",
        "fmt",
        "init",
        "validate",
        "schema",
        "reinit",
        "revalidate",
    ]
    assert result["validation"]["valid"] is True
    assert result["revalidation"]["valid"] is True
    assert result["lock_reproduced"] is True
    assert result["provider_binary_verified"] is True
    assert result["provider_schema"]["resource_type_count"] == 2
    assert result["provider_schema"]["resource_count"] == 2


def test_lock_bootstrap_never_claims_native_validation_or_initializes_provider(
    native,
    monkeypatch,
    tmp_path: Path,
    lock_text: str,
    official_manifest: str,
    schema: dict,
    configuration: dict,
) -> None:
    events = emulate_native_dependency(
        native, monkeypatch, tmp_path, lock_text, official_manifest, schema
    )
    result = native._run(tmp_path, json.dumps(configuration), None, True)
    assert events == ["verified_toolchain", "version", "lock"]
    assert result["native_validation"] == "not_run_bootstrap"
    assert result["generated_lock"] == lock_text
    assert "validation" not in result
    assert "revalidation" not in result
    assert "provider_schema" not in result


@pytest.mark.parametrize(
    "stage", ["version", "lock", "fmt", "init", "validate", "schema", "reinit", "revalidate"]
)
def test_any_native_stage_failure_cannot_be_reported_as_complete(
    native,
    monkeypatch,
    tmp_path: Path,
    lock_text: str,
    official_manifest: str,
    schema: dict,
    configuration: dict,
    stage: str,
) -> None:
    events = emulate_native_dependency(
        native, monkeypatch, tmp_path, lock_text, official_manifest, schema, failure_stage=stage
    )
    with pytest.raises(native.NativeError):
        native._run(tmp_path, json.dumps(configuration), lock_text, False)
    assert events[-1] == stage


@pytest.mark.parametrize("failure", ["provider_hash", "lock_drift"])
def test_provider_replacement_or_readonly_reinit_lock_drift_is_rejected(
    native,
    monkeypatch,
    tmp_path: Path,
    lock_text: str,
    official_manifest: str,
    schema: dict,
    configuration: dict,
    failure: str,
) -> None:
    events = emulate_native_dependency(
        native, monkeypatch, tmp_path, lock_text, official_manifest, schema, failure_stage=failure
    )
    with pytest.raises(native.NativeError):
        native._run(tmp_path, json.dumps(configuration), lock_text, False)
    if failure == "provider_hash":
        assert events[-1] == "init"
    else:
        assert events[-1] == "reinit"
