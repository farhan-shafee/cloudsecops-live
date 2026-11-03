"""Explicit private, self-signed loopback TLS without installing OS trust."""

from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def safe_path(path: Path) -> None:
    """Reject links/junctions in the full path, including existing ancestors."""
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("unsafe_private_path")


def _current_sid() -> str:
    result = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
    sid = next(csv.reader(io.StringIO(result.stdout)))[1]
    if not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise ValueError("private_acl_failed")
    return sid


def restrict_private(path: Path, *, directory: bool = False) -> None:
    safe_path(path)
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    # Same current-user-only ACL policy as scripts/local_postgres.py. An
    # unexpected explicit grant is rejected by private_file(), never ignored.
    sid = _current_sid()
    subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:" + ("(OI)(CI)F" if directory else "F"),
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )


def private_file(path: Path, *, max_bytes: int) -> bytes:
    safe_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= max_bytes:
        raise ValueError("unsafe_private_file")
    if os.name == "nt":
        script = (
            "$ErrorActionPreference='Stop';"
            "$a=Get-Acl -LiteralPath $env:CSL_PRIVATE_CHECK_PATH;"
            "@($a.Access | Where-Object {$_.AccessControlType -eq 'Allow'} | "
            "ForEach-Object {$_.IdentityReference.Translate("
            "[System.Security.Principal.SecurityIdentifier]).Value}) | ConvertTo-Json -Compress"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            env={
                **{
                    key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"
                },
                "CSL_PRIVATE_CHECK_PATH": str(path.absolute()),
            },
            capture_output=True,
            check=True,
            text=True,
            timeout=10,
        )
        identities = json.loads(result.stdout)
        if isinstance(identities, str):
            identities = [identities]
        if not isinstance(identities, list) or set(identities) - {
            _current_sid(),
            "S-1-5-18",
            "S-1-5-32-544",
        }:
            raise ValueError("unsafe_private_permissions")
    elif info.st_mode & 0o077:
        raise ValueError("unsafe_private_permissions")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("unsafe_private_file")
        value = stream.read(max_bytes + 1)
    if not 0 < len(value) <= max_bytes:
        raise ValueError("unsafe_private_file")
    return value


def validate_tls(certificate: Path, key: Path) -> None:
    try:
        cert = x509.load_pem_x509_certificate(private_file(certificate, max_bytes=65536))
        private = serialization.load_pem_private_key(private_file(key, max_bytes=65536), None)
        now = datetime.now(UTC)
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("invalid_tls")
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if ipaddress.ip_address("127.0.0.1") not in san.get_values_for_type(x509.IPAddress):
            raise ValueError("invalid_tls")
        if private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError("invalid_tls")
    except (OSError, TypeError, x509.ExtensionNotFound) as exc:
        raise ValueError("invalid_tls") from exc


def create_tls(directory: Path) -> tuple[Path, Path]:
    safe_path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    restrict_private(directory, directory=True)
    certificate, key_path = directory / "loopback-cert.pem", directory / "loopback-key.pem"
    if certificate.exists() or key_path.exists():
        raise ValueError("tls_files_exist")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CloudSecOps local workspace")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    for path, value in (
        (
            key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
        (certificate, cert.public_bytes(serialization.Encoding.PEM)),
    ):
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        restrict_private(path)
    validate_tls(certificate, key_path)
    return certificate, key_path
