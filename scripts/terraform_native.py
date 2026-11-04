"""Credential-free, pinned native Terraform validation on Ubuntu AMD64.

Only the command tuples below may execute. No plan, provider configuration,
state, cloud credentials, user CLI configuration, or ambient proxy is used.
Raw tool output stays in a private temporary directory; receipts contain only
public tool identities, hashes, counts, and fixed status codes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import platform
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

TERRAFORM_VERSION = "1.17.1"
PROVIDER_VERSION = "6.71.0"
PROVIDER_ADDRESS = "registry.terraform.io/hashicorp/aws"
SIGNING_FINGERPRINT = (
    "C874011F0AB405110D02105534365D9472D7468F"  # pragma: allowlist secret - public PGP
)
# Independently anchored outside registry metadata by HashiCorp's trust page
# and HCSEC-2026-03; the refreshed key expires on 2030-03-01.
# https://www.hashicorp.com/en/trust/security
# https://discuss.hashicorp.com/t/77237
KEY_URL = "https://www.hashicorp.com/.well-known/pgp-key.txt"
ARCHIVE_HASHES = {
    "terraform_1.17.1_linux_amd64.zip": (
        "4638628058e71a55212b1c563712eac03"  # pragma: allowlist secret - public SHA256
        "b902128f40740f3dc8174df12135061"  # pragma: allowlist secret - public SHA256
    ),
    "terraform_1.17.1_windows_amd64.zip": (
        "a3b71365cff94c0f978cf75d86addb075"  # pragma: allowlist secret - public SHA256
        "ea1bb6409055ea0ab359bf057d7898a"  # pragma: allowlist secret - public SHA256
    ),
    "terraform-provider-aws_6.71.0_linux_amd64.zip": (
        "cb57bbcaf0fa3a70ea29b60d183d3a0dd"  # pragma: allowlist secret - public SHA256
        "020f041b18da5d1725d2acd17fa7d59"  # pragma: allowlist secret - public SHA256
    ),
    "terraform-provider-aws_6.71.0_windows_amd64.zip": (
        "55616730a485c9c7283546a84f1ac5f83"  # pragma: allowlist secret - public SHA256
        "41152c5572338a54fc7af5f69ebfb92"  # pragma: allowlist secret - public SHA256
    ),
}
DOWNLOAD_URLS = frozenset(
    {
        KEY_URL,
        *(
            f"https://releases.hashicorp.com/{product}/{version}/{product}_{version}_{suffix}"
            for product, version in (
                ("terraform", TERRAFORM_VERSION),
                ("terraform-provider-aws", PROVIDER_VERSION),
            )
            for suffix in (
                "SHA256SUMS",
                "SHA256SUMS.72D7468F.sig",
                "linux_amd64.zip",
                "windows_amd64.zip",
            )
        ),
    }
)
TERRAFORM_COMMANDS = {
    "version": ("version", "-json"),
    "fmt": ("fmt", "-check", "-recursive", "-no-color"),
    "lock": (
        "providers",
        "lock",
        "-platform=linux_amd64",
        "-platform=windows_amd64",
        PROVIDER_ADDRESS,
    ),
    "init": ("init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"),
    "validate": ("validate", "-json"),
    "schema": ("providers", "schema", "-json"),
}
GPG_COMMANDS = {
    "inspect": ("--with-colons", "--show-keys"),
    "import": ("--import",),
    "verify": ("--status-fd=1", "--verify"),
}
ERROR_CODES = frozenset(
    {
        "invalid_json",
        "invalid_validate_output",
        "invalid_provider_schema",
        "schema_argument_mismatch",
        "invalid_lock",
        "invalid_manifest",
        "invalid_environment",
        "download_failed",
        "download_too_large",
        "signature_failed",
        "archive_hash_mismatch",
        "unsafe_archive",
        "command_failed",
        "command_timeout",
        "output_too_large",
        "unsupported_host",
        "version_mismatch",
        "provider_binary_mismatch",
        "lock_mismatch",
        "validation_failed",
        "missing_committed_lock",
        "bootstrap_not_needed",
        "invalid_source_revision",
        "filesystem_error",
        "unexpected_error",
        "unreviewed_source",
    }
)
STAGES = frozenset(
    {
        "arguments",
        "source_policy",
        "source_lock",
        "signature",
        "version",
        "fmt",
        "lock",
        "init",
        "validate",
        "schema",
        "reinit",
        "revalidate",
    }
)
MIB = 1024 * 1024
PROVIDER_BINARY = "terraform-provider-aws_v6.71.0_x5"


class NativeError(Exception):
    """An error with a fixed public code, never a tool-provided message."""

    def __init__(self, code: str, stage: str | None = None) -> None:
        self.code = code if code in ERROR_CODES else "unexpected_error"
        self.stage = stage if stage in STAGES else None
        super().__init__(self.code)


def _require(condition: bool, code: str, stage: str | None = None) -> None:
    if not condition:
        raise NativeError(code, stage)


def _json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _require(key not in result, "invalid_json")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=lambda _: _bad_json())
    except (ValueError, RecursionError, TypeError) as exc:
        raise NativeError("invalid_json") from exc


def _bad_json() -> Any:
    raise NativeError("invalid_json")


def _read(path: Path, limit: int = 2 * MIB) -> str:
    _require(path.is_file() and not path.is_symlink(), "filesystem_error")
    _require(path.stat().st_size <= limit, "output_too_large")
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except UnicodeError as exc:
        raise NativeError("invalid_json") from exc


def isolated_environment(work: Path) -> dict[str, str]:
    """Construct an allowlist from scratch; never inspect the process environment."""
    work = work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    home, temporary = work / "home", work / "tmp"
    home.mkdir(mode=0o700, exist_ok=True)
    temporary.mkdir(mode=0o700, exist_ok=True)
    credentials, config = work / "empty-aws-credentials", work / "empty-aws-config"
    credentials.write_text("", encoding="ascii")
    config.write_text("", encoding="ascii")
    cli = work / "terraform.rc"
    cli.write_text(
        "disable_checkpoint = true\nprovider_installation {\n"
        '  direct {\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n',
        encoding="ascii",
    )
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CHECKPOINT_DISABLE": "1",
        "TF_INPUT": "0",
        "TF_IN_AUTOMATION": "1",
        "TF_CLI_CONFIG_FILE": str(cli),
        "AWS_CONFIG_FILE": str(config),
        "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_SDK_LOAD_CONFIG": "0",
    }


def parse_validate_output(stdout: str, returncode: int) -> dict[str, Any]:
    _require(len(stdout) <= 32 * MIB, "invalid_validate_output")
    document = _json(stdout)
    _require(isinstance(document, dict), "invalid_validate_output")
    _require(document.get("format_version") == "1.0", "invalid_validate_output")
    valid = document.get("valid")
    errors, warnings = document.get("error_count"), document.get("warning_count")
    diagnostics = document.get("diagnostics")
    _require(type(valid) is bool, "invalid_validate_output")
    _require(type(errors) is int and 0 <= errors <= 10000, "invalid_validate_output")
    _require(type(warnings) is int and 0 <= warnings <= 10000, "invalid_validate_output")
    _require(isinstance(diagnostics, list) and len(diagnostics) <= 20000, "invalid_validate_output")
    counts = {"error": 0, "warning": 0}
    for diagnostic in diagnostics:
        _require(isinstance(diagnostic, dict), "invalid_validate_output")
        severity = diagnostic.get("severity")
        _require(isinstance(severity, str) and severity in counts, "invalid_validate_output")
        _require(
            all(isinstance(diagnostic.get(k, ""), str) for k in ("summary", "detail")),
            "invalid_validate_output",
        )
        counts[severity] += 1
    _require(counts == {"error": errors, "warning": warnings}, "invalid_validate_output")
    _require(type(returncode) is int and 0 <= returncode <= 255, "invalid_validate_output")
    _require(valid == (errors == 0) == (returncode == 0), "invalid_validate_output")
    _require(valid, "validation_failed")
    return {
        "format_version": "1.0",
        "valid": valid,
        "error_count": errors,
        "warning_count": warnings,
    }


def check_provider_schema(
    document: dict[str, Any], configuration: dict[str, Any]
) -> dict[str, Any]:
    _require(
        isinstance(document, dict) and isinstance(configuration, dict), "invalid_provider_schema"
    )
    _require(document.get("format_version") == "1.0", "invalid_provider_schema")
    providers = document.get("provider_schemas")
    _require(
        isinstance(providers, dict) and set(providers) == {PROVIDER_ADDRESS},
        "invalid_provider_schema",
    )
    schema = providers[PROVIDER_ADDRESS]
    _require(isinstance(schema, dict), "invalid_provider_schema")
    counts = {
        "resource_type_count": 0,
        "resource_count": 0,
        "argument_count": 0,
        "nested_block_count": 0,
    }

    def check_type(value: Any, depth: int = 0) -> None:
        _require(depth <= 64, "invalid_provider_schema")
        if isinstance(value, str):
            _require(value in {"string", "number", "bool", "dynamic"}, "invalid_provider_schema")
            return
        _require(isinstance(value, list) and len(value) == 2, "invalid_provider_schema")
        kind, inner = value
        _require(isinstance(kind, str), "invalid_provider_schema")
        if kind in {"list", "set", "map"}:
            check_type(inner, depth + 1)
        elif kind == "object":
            _require(isinstance(inner, dict), "invalid_provider_schema")
            for item in inner.values():
                check_type(item, depth + 1)
        elif kind == "tuple":
            _require(isinstance(inner, list), "invalid_provider_schema")
            for item in inner:
                check_type(item, depth + 1)
        else:
            raise NativeError("invalid_provider_schema")

    def check_attribute(attribute: Any, depth: int = 0) -> None:
        _require(isinstance(attribute, dict) and depth <= 64, "invalid_provider_schema")
        _require(("type" in attribute) != ("nested_type" in attribute), "invalid_provider_schema")
        if "type" in attribute:
            check_type(attribute["type"])
        else:
            nested = attribute["nested_type"]
            _require(isinstance(nested, dict), "invalid_provider_schema")
            _require(
                nested.get("nesting_mode") in {"single", "list", "set", "map", "group"},
                "invalid_provider_schema",
            )
            _require(isinstance(nested.get("attributes"), dict), "invalid_provider_schema")
            for item in nested["attributes"].values():
                check_attribute(item, depth + 1)

    def check_block(body: Any, block: Any, resource: bool = False) -> None:
        _require(isinstance(body, dict) and isinstance(block, dict), "invalid_provider_schema")
        attributes, blocks = block.get("attributes", {}), block.get("block_types", {})
        _require(
            isinstance(attributes, dict) and isinstance(blocks, dict), "invalid_provider_schema"
        )
        for name, value in body.items():
            if resource and name in {"lifecycle", "depends_on"}:
                continue
            if name in attributes:
                attribute = attributes[name]
                check_attribute(attribute)
                _require(
                    not (
                        attribute.get("computed") is True
                        and not (attribute.get("optional") or attribute.get("required"))
                    ),
                    "schema_argument_mismatch",
                )
                counts["argument_count"] += 1
            else:
                _require(
                    name in blocks and isinstance(blocks[name], dict), "schema_argument_mismatch"
                )
                nested = blocks[name]
                mode = nested.get("nesting_mode")
                _require(
                    mode in {"single", "list", "set", "map", "group"}, "invalid_provider_schema"
                )
                bodies = (
                    list(value.values()) if mode == "map" and isinstance(value, dict) else value
                )
                if isinstance(bodies, dict):
                    bodies = [bodies]
                _require(isinstance(bodies, list), "schema_argument_mismatch")
                for child in bodies:
                    counts["nested_block_count"] += 1
                    check_block(child, nested.get("block"))

    def versioned_block(value: Any) -> Any:
        _require(isinstance(value, dict), "invalid_provider_schema")
        # This is Terraform's schema migration version, not the provider release.
        _require(
            type(value.get("version")) is int and value["version"] >= 0, "invalid_provider_schema"
        )
        return value.get("block")

    configured_providers = configuration.get("provider", {})
    _require(
        isinstance(configured_providers, dict) and set(configured_providers) == {"aws"},
        "schema_argument_mismatch",
    )
    aws = configured_providers["aws"]
    for body in aws if isinstance(aws, list) else [aws]:
        check_block(body, versioned_block(schema.get("provider")))
    resources = configuration.get("resource", {})
    resource_schemas = schema.get("resource_schemas")
    _require(
        isinstance(resources, dict) and isinstance(resource_schemas, dict),
        "invalid_provider_schema",
    )
    _require(
        not configuration.get("data") and not configuration.get("module"),
        "schema_argument_mismatch",
    )
    for resource_type, instances in resources.items():
        _require(
            resource_type in resource_schemas and isinstance(instances, dict),
            "schema_argument_mismatch",
        )
        counts["resource_type_count"] += 1
        for body in instances.values():
            counts["resource_count"] += 1
            check_block(body, versioned_block(resource_schemas[resource_type]), resource=True)
    return {"format_version": "1.0", "provider_count": 1, **counts}


def _manifest_rows(text: str, product: str, version: str) -> dict[str, str]:
    _require(len(text) <= MIB, "invalid_manifest")
    rows: dict[str, str] = {}
    pattern = re.compile(
        r"([0-9a-f]{64})  (" + re.escape(product + "_" + version) + r"_[a-z0-9_]+\.(?:zip|json))"
    )
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        _require(match is not None, "invalid_manifest")
        assert match is not None
        checksum, filename = match.groups()
        _require(filename not in rows and len(rows) < 64, "invalid_manifest")
        rows[filename] = checksum
    _require(bool(rows), "invalid_manifest")
    return rows


def check_lock(text: str, official_manifest: str) -> dict[str, Any]:
    _require(len(text) <= MIB, "invalid_lock")
    rows = _manifest_rows(official_manifest, "terraform-provider-aws", PROVIDER_VERSION)
    for platform_name in ("linux_amd64", "windows_amd64"):
        filename = f"terraform-provider-aws_{PROVIDER_VERSION}_{platform_name}.zip"
        _require(rows.get(filename) == ARCHIVE_HASHES[filename], "invalid_manifest")
    clean = re.sub(r"(?m)^\s*#.*$", "", text)
    match = re.fullmatch(
        r'\s*provider\s+"([^"\n]+)"\s*\{\s*version\s*=\s*"([^"\n]+)"\s*'
        r'constraints\s*=\s*"([^"\n]+)"\s*hashes\s*=\s*\[(.*?)\]\s*\}\s*',
        clean,
        flags=re.DOTALL,
    )
    _require(match is not None, "invalid_lock")
    assert match is not None
    address, version, constraint, payload = match.groups()
    _require(
        address == PROVIDER_ADDRESS
        and version == PROVIDER_VERSION
        and constraint in {"6.71.0", "= 6.71.0"},
        "invalid_lock",
    )
    _require(re.fullmatch(r'\s*(?:"[^"\n]+"\s*,\s*)+', payload) is not None, "invalid_lock")
    hashes = re.findall(r'"([^"\n]+)"', payload)
    _require(len(hashes) == len(set(hashes)) and len(hashes) <= 128, "invalid_lock")
    h1, zh = [], []
    for value in hashes:
        if value.startswith("h1:"):
            try:
                decoded = base64.b64decode(value[3:], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise NativeError("invalid_lock") from exc
            _require(
                len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == value[3:],
                "invalid_lock",
            )
            h1.append(value)
        else:
            _require(re.fullmatch(r"zh:[0-9a-f]{64}", value) is not None, "invalid_lock")
            zh.append(value)
    _require(len(h1) >= 2 and set(zh) == {"zh:" + h for h in rows.values()}, "invalid_lock")
    return {
        "provider": address,
        "version": version,
        "constraint": "= 6.71.0",
        "h1_count": len(h1),
        "zh_count": len(zh),
        "hashes": sorted(hashes),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> Any:
        raise NativeError("download_failed")


def _download(url: str, destination: Path, limit: int) -> None:
    _require(
        url in DOWNLOAD_URLS and type(limit) is int and 0 < limit <= 320 * MIB, "download_failed"
    )
    # Pin the OS CA file too: OpenSSL must not consult ambient SSL_CERT_* values.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context)
    )
    deadline = time.monotonic() + 300
    try:
        with opener.open(url, timeout=45) as response, destination.open("xb") as output:
            _require(response.status == 200 and response.geturl() == url, "download_failed")
            total = 0
            while chunk := response.read(MIB):
                _require(time.monotonic() <= deadline, "download_failed")
                total += len(chunk)
                _require(total <= limit, "download_too_large")
                output.write(chunk)
            _require(total > 0, "download_failed")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise NativeError("download_failed") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(MIB):
            digest.update(chunk)
    return digest.hexdigest()


def _process(
    command: list[str], cwd: Path, env: dict[str, str], logs: Path, label: str, timeout: int = 300
) -> tuple[str, int]:
    _require(
        bool(command) and re.fullmatch(r"[a-z0-9-]{1,32}", label) is not None, "command_failed"
    )
    if command[0] == "/usr/bin/gpg":
        _require(
            len(command) >= 10
            and command[1:3] == ["--no-options", "--homedir"]
            and command[4:8]
            == ["--batch", "--no-tty", "--no-auto-key-retrieve", "--no-auto-key-import"],
            "command_failed",
        )
        suffix = command[8:]
        operation = next(
            (name for name, flags in GPG_COMMANDS.items() if suffix[: len(flags)] == list(flags)),
            None,
        )
        _require(operation is not None, "command_failed")
        assert operation is not None
        paths = [command[3], *suffix[len(GPG_COMMANDS[operation]) :]]
        _require(len(paths) == (3 if operation == "verify" else 2), "command_failed")
        _require(
            all(
                Path(p).is_absolute() and Path(p).resolve().is_relative_to(cwd.resolve())
                for p in paths
            ),
            "command_failed",
        )
    else:
        _require(
            Path(command[0]).is_absolute()
            and Path(command[0]).name == "terraform"
            and tuple(command[1:]) in TERRAFORM_COMMANDS.values(),
            "command_failed",
        )
    out, err = logs / f"{label}.stdout", logs / f"{label}.stderr"
    try:
        with out.open("wb") as stdout, err.open("wb") as stderr:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise NativeError("command_timeout") from exc
    _require(err.stat().st_size <= 32 * MIB, "output_too_large")
    return _read(out, 192 * MIB), result.returncode


def _terraform(
    binary: Path, name: str, cwd: Path, env: dict[str, str], logs: Path, label: str | None = None
) -> tuple[str, int]:
    _require(binary.is_absolute() and name in TERRAFORM_COMMANDS, "command_failed")
    try:
        result = _process([str(binary), *TERRAFORM_COMMANDS[name]], cwd, env, logs, label or name)
        _require(result[1] == 0 or name == "validate", "command_failed", label or name)
        return result
    except NativeError as exc:
        exc.stage = label or name
        raise


def _verify_signatures(work: Path, env: dict[str, str], manifests: list[tuple[Path, Path]]) -> str:
    keydir = work / "gnupg"
    keydir.mkdir(mode=0o700)

    def gpg(name: str, paths: list[Path], label: str) -> str:
        command = [
            "/usr/bin/gpg",
            "--no-options",
            "--homedir",
            str(keydir),
            "--batch",
            "--no-tty",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            *GPG_COMMANDS[name],
            *map(str, paths),
        ]
        stdout, code = _process(command, work, env, work, label, timeout=30)
        _require(code == 0, "signature_failed")
        return stdout

    key = work / "hashicorp.asc"
    listing = gpg("inspect", [key], "key-inspect")
    fingerprints: list[str] = []
    primary = False
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            if fields[0] == "pub":
                _require(
                    len(fields) > 1 and fields[1] not in {"e", "r", "d", "i"},
                    "signature_failed",
                    "signature",
                )
            primary = fields[0] == "pub"
        elif fields[0] == "fpr" and primary:
            _require(len(fields) > 9, "signature_failed")
            fingerprints.append(fields[9])
            primary = False
    _require(fingerprints == [SIGNING_FINGERPRINT], "signature_failed")
    gpg("import", [key], "key-import")
    for index, (manifest, signature) in enumerate(manifests):
        status = gpg("verify", [signature, manifest], f"signature-{index}")
        bad = {
            "BADSIG",
            "ERRSIG",
            "EXPSIG",
            "EXPKEYSIG",
            "REVKEYSIG",
            "KEYEXPIRED",
            "KEYREVOKED",
            "SIGEXPIRED",
            "FAILURE",
            "NODATA",
            "ERROR",
        }
        for line in status.splitlines():
            if line.startswith("[GNUPG:] "):
                fields = line.split()
                _require(len(fields) >= 2 and fields[1] not in bad, "signature_failed", "signature")
        signatures = [
            line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        _require(
            len(signatures) == 1
            and len(signatures[0]) >= 12
            and signatures[0][-1] == SIGNING_FINGERPRINT,
            "signature_failed",
        )
        _require(signatures[0][9] in {"8", "9", "10", "11"}, "signature_failed", "signature")
    _require(bool(manifests), "signature_failed", "signature")
    return SIGNING_FINGERPRINT


def _archive_binary(path: Path, name: str, limit: int, destination: Path | None = None) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            _require(1 <= len(members) <= 8, "unsafe_archive")
            _require(len({m.filename for m in members}) == len(members), "unsafe_archive")
            for member in members:
                for filename in (member.filename, member.orig_filename):
                    parts = PurePosixPath(filename)
                    _require(
                        not parts.is_absolute()
                        and ".." not in parts.parts
                        and "\\" not in filename
                        and ":" not in filename
                        and all(ord(c) >= 32 for c in filename),
                        "unsafe_archive",
                    )
                _require(
                    not stat.S_ISLNK(member.external_attr >> 16) and not member.flag_bits & 1,
                    "unsafe_archive",
                )
            _require(sum(m.file_size for m in members) <= limit + MIB, "unsafe_archive")
            target = archive.getinfo(name)
            _require(0 < target.file_size <= limit and not target.is_dir(), "unsafe_archive")
            digest, total = hashlib.sha256(), 0
            with archive.open(target) as source:
                output = destination.open("xb") if destination is not None else None
                try:
                    while chunk := source.read(MIB):
                        total += len(chunk)
                        _require(total <= limit, "unsafe_archive")
                        digest.update(chunk)
                        if output is not None:
                            output.write(chunk)
                finally:
                    if output is not None:
                        output.close()
            _require(total == target.file_size, "unsafe_archive")
            if destination is not None:
                destination.chmod(0o700)
            return digest.hexdigest()
    except (zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError) as exc:
        raise NativeError("unsafe_archive") from exc


def _toolchain(work: Path, env: dict[str, str]) -> tuple[Path, str, str, dict[str, Any]]:
    _download(KEY_URL, work / "hashicorp.asc", 128 * 1024)
    manifests: list[tuple[Path, Path]] = []
    for product, version in (
        ("terraform", TERRAFORM_VERSION),
        ("terraform-provider-aws", PROVIDER_VERSION),
    ):
        base = f"https://releases.hashicorp.com/{product}/{version}/"
        manifest = work / f"{product}_{version}_SHA256SUMS"
        signature = manifest.with_name(manifest.name + ".72D7468F.sig")
        _download(base + manifest.name, manifest, MIB)
        _download(base + signature.name, signature, 64 * 1024)
        manifests.append((manifest, signature))
    fingerprint = _verify_signatures(work, env, manifests)
    for (product, version), (manifest, _) in zip(
        (("terraform", TERRAFORM_VERSION), ("terraform-provider-aws", PROVIDER_VERSION)),
        manifests,
        strict=True,
    ):
        rows = _manifest_rows(_read(manifest), product, version)
        for platform_name in ("linux_amd64", "windows_amd64"):
            filename = f"{product}_{version}_{platform_name}.zip"
            _require(rows.get(filename) == ARCHIVE_HASHES[filename], "archive_hash_mismatch")
            archive = work / filename
            _download(
                f"https://releases.hashicorp.com/{product}/{version}/{filename}",
                archive,
                (320 if product.endswith("aws") else 80) * MIB,
            )
            _require(_sha256(archive) == ARCHIVE_HASHES[filename], "archive_hash_mismatch")
    binary = work / "terraform"
    cli_hash = _archive_binary(
        work / "terraform_1.17.1_linux_amd64.zip", "terraform", 160 * MIB, binary
    )
    linux_hash = _archive_binary(
        work / "terraform-provider-aws_6.71.0_linux_amd64.zip", PROVIDER_BINARY, 1536 * MIB
    )
    observations = {
        "signatures_verified": True,
        "signing_fingerprint": fingerprint,
        "signed_manifest_sha256": {manifest.name: _sha256(manifest) for manifest, _ in manifests},
        "terraform_binary_sha256": cli_hash,
        "verified_archive_sha256": dict(ARCHIVE_HASHES),
        "verified_platforms": ["linux_amd64", "windows_amd64"],
    }
    return binary, linux_hash, _read(manifests[1][0]), observations


def _run(
    work: Path, configuration_text: str, lock_text: str | None, bootstrap: bool
) -> dict[str, Any]:
    env = isolated_environment(work / "environment")
    binary, provider_binary_hash, manifest, observations = _toolchain(work, env)
    version, code = _terraform(binary, "version", work, env, work)
    identity = _json(version)
    _require(
        code == 0
        and isinstance(identity, dict)
        and identity.get("terraform_version") == TERRAFORM_VERSION
        and identity.get("platform") == "linux_amd64",
        "version_mismatch",
    )
    generated, validation = work / "generated", work / "validation"
    for directory in (generated, validation):
        directory.mkdir(mode=0o700)
        (directory / "main.tf.json").write_text(configuration_text, encoding="utf-8")
    locked, code = _terraform(binary, "lock", generated, env, work)
    _require(
        code == 0 and locked.count("signed by HashiCorp") >= 2 and "self-signed" not in locked,
        "signature_failed",
    )
    generated_text = _read(generated / ".terraform.lock.hcl")
    generated_lock = check_lock(generated_text, manifest)
    if bootstrap:
        return {
            **observations,
            "lock": generated_lock,
            "generated_lock": generated_text,
            "native_validation": "not_run_bootstrap",
        }
    if lock_text is not None:
        _require(check_lock(lock_text, manifest) == generated_lock, "lock_mismatch")
    else:
        _require(bootstrap, "missing_committed_lock")
        lock_text = generated_text
    (validation / ".terraform.lock.hcl").write_text(lock_text, encoding="utf-8")
    _, code = _terraform(binary, "fmt", validation, env, work)
    _require(code == 0, "command_failed")
    _, code = _terraform(binary, "init", validation, env, work)
    _require(code == 0, "command_failed")
    installed = (
        validation
        / ".terraform"
        / "providers"
        / PROVIDER_ADDRESS
        / PROVIDER_VERSION
        / "linux_amd64"
        / PROVIDER_BINARY
    )
    _require(
        installed.is_file()
        and not installed.is_symlink()
        and installed.resolve().is_relative_to(validation.resolve()),
        "provider_binary_mismatch",
    )
    _require(installed.stat().st_size <= 1536 * MIB, "provider_binary_mismatch")
    _require(_sha256(installed) == provider_binary_hash, "provider_binary_mismatch")
    stdout, code = _terraform(binary, "validate", validation, env, work)
    try:
        result = parse_validate_output(stdout, code)
    except NativeError as exc:
        exc.stage = "validate"
        raise
    _require(result["valid"], "validation_failed")
    stdout, code = _terraform(binary, "schema", validation, env, work)
    _require(code == 0, "command_failed")
    try:
        schema = check_provider_schema(_json(stdout), _json(configuration_text))
    except NativeError as exc:
        exc.stage = "schema"
        raise
    _, code = _terraform(binary, "init", validation, env, work, "reinit")
    _require(code == 0, "command_failed")
    _require(
        check_lock(_read(validation / ".terraform.lock.hcl"), manifest) == generated_lock,
        "lock_mismatch",
    )
    _require(_sha256(installed) == provider_binary_hash, "provider_binary_mismatch")
    stdout, code = _terraform(binary, "validate", validation, env, work, "revalidate")
    try:
        revalidation = parse_validate_output(stdout, code)
    except NativeError as exc:
        exc.stage = "revalidate"
        raise
    _require(revalidation["valid"], "validation_failed")
    return {
        **observations,
        "validation": result,
        "revalidation": revalidation,
        "provider_schema": schema,
        "lock": generated_lock,
        "lock_reproduced": True,
        "provider_binary_verified": True,
        "linux_provider_binary_sha256": provider_binary_hash,
        "fmt": "completed_json_syntax_not_formatted",
        "native_validation": "passed",
        "generated_lock": generated_text,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--work-parent", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--bootstrap-lock", action="store_true")
    args = parser.parse_args(argv)
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "terraform_version": TERRAFORM_VERSION,
        "provider_address": PROVIDER_ADDRESS,
        "provider_version": PROVIDER_VERSION,
        "signing_fingerprint_pin": SIGNING_FINGERPRINT,
        "archive_sha256_pins": ARCHIVE_HASHES,
        "backend_disabled": True,
        "aws_credentials_supplied": False,
    }
    try:
        _require(
            re.fullmatch(r"[0-9a-fA-F]{40}", args.source_revision) is not None,
            "invalid_source_revision",
            "arguments",
        )
        receipt["source_revision"] = args.source_revision.lower()
        _require(
            sys.platform == "linux" and platform.machine() in {"x86_64", "AMD64"},
            "unsupported_host",
        )
        source = Path(__file__).resolve().parents[1] / "infra" / "aws-offline"
        from scripts.check_terraform import check_directory

        _require(not check_directory(source), "unreviewed_source", "source_policy")
        configuration_text = _read(source / "main.tf.json")
        lock_path = source / ".terraform.lock.hcl"
        lock_text = _read(lock_path) if lock_path.exists() else None
        # _read decodes UTF-8 and normalizes CRLF/CR to LF before hashing and
        # copying. These bind the exact validation input text, not Git objects.
        receipt["input_hash_encoding"] = "UTF-8 text with LF-normalized newlines"
        receipt["configuration_sha256"] = hashlib.sha256(
            configuration_text.encode("utf-8")
        ).hexdigest()
        if lock_text is not None:
            receipt["committed_lock_sha256"] = hashlib.sha256(lock_text.encode("utf-8")).hexdigest()
        _require(
            lock_text is not None or args.bootstrap_lock, "missing_committed_lock", "source_lock"
        )
        _require(not (lock_text is not None and args.bootstrap_lock), "bootstrap_not_needed")
        args.work_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="terraform-native-", dir=args.work_parent
        ) as directory:
            private = Path(directory)
            private.chmod(0o700)
            result = _run(private, configuration_text, lock_text, args.bootstrap_lock)
            generated_lock = result.pop("generated_lock")
            receipt.update(result)
            if args.bootstrap_lock:
                args.receipt.parent.mkdir(parents=True, exist_ok=True)
                (args.receipt.parent / ".terraform.lock.hcl").write_text(
                    generated_lock, encoding="utf-8"
                )
                receipt["bootstrap_lock_available"] = True
                raise NativeError("missing_committed_lock", "source_lock")
            receipt["status"] = "passed"
    except NativeError as exc:
        receipt["error_code"] = exc.code
        if exc.stage in STAGES:
            receipt["failure_stage"] = exc.stage
    except OSError:
        receipt["error_code"] = "filesystem_error"
    except Exception:
        receipt["error_code"] = "unexpected_error"
    try:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError:
        print(json.dumps({"status": "failed", "error_code": "filesystem_error"}))
        return 1
    print(json.dumps({"status": receipt["status"], "error_code": receipt.get("error_code")}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
