"""Windows ACL parser policy runs on every OS; file reads still use real descriptors."""

from __future__ import annotations

import base64
import json
import os
from types import SimpleNamespace

import pytest

SYNTHETIC_SID = "S-1-5-21-100-200-300-1001"


@pytest.mark.parametrize(
    ("identities", "accepted", "nofollow_available"),
    [
        (SYNTHETIC_SID, True, True),
        ([SYNTHETIC_SID, "S-1-5-18", "S-1-5-32-544"], True, False),
        ([SYNTHETIC_SID, "S-1-1-0"], False, True),
        ({"unexpected": SYNTHETIC_SID}, False, True),
    ],
    ids=["single-user-json", "user-system-administrators", "foreign-everyone", "invalid-shape"],
)
def test_simulated_windows_acl_allowlist_and_safe_command_environment(
    tmp_path,
    monkeypatch,
    identities,
    accepted,
    nofollow_available,
):
    from cloudsecops_live import workspace_tls as module

    path = tmp_path / "private fixture.bin"
    path.write_bytes(b"synthetic private-file bytes")
    commands, opened = [], []
    actual_open = os.open

    def open_file(actual_path, flags):
        opened.append(actual_path)
        return actual_open(actual_path, flags)

    # Replace only the module's OS facade, preserving pathlib and the real host OS.
    # No native ACL is inferred from these deliberately simulated command outputs.
    facade = SimpleNamespace(
        name="nt",
        environ={
            "PSMODULEPATH": "untrusted-module-path",
            "pSmOdUlEpAtH": "also-untrusted",
            "LAB_MARKER": "preserved",
        },
        O_RDONLY=os.O_RDONLY,
        open=open_file,
        fdopen=os.fdopen,
        fstat=os.fstat,
    )
    if nofollow_available and hasattr(os, "O_NOFOLLOW"):
        facade.O_NOFOLLOW = os.O_NOFOLLOW
    monkeypatch.setattr(module, "os", facade)

    def run(command, **options):
        commands.append((command, options))
        if command[0] == "powershell.exe":
            return SimpleNamespace(stdout=json.dumps(identities))
        assert command == ["whoami", "/user", "/fo", "csv", "/nh"]
        return SimpleNamespace(stdout=f'"synthetic-user","{SYNTHETIC_SID}"')

    monkeypatch.setattr(module.subprocess, "run", run)
    if accepted:
        assert module.private_file(path, max_bytes=100) == b"synthetic private-file bytes"
        assert opened == [path]
    else:
        with pytest.raises(ValueError, match="unsafe_private_permissions"):
            module.private_file(path, max_bytes=100)
        assert not opened

    command, options = commands[0]
    assert command[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    script = base64.b64decode(command[4]).decode("utf-16-le")
    assert "Get-Acl -LiteralPath $env:CSL_PRIVATE_CHECK_PATH" in script
    assert str(path.absolute()) not in script
    assert all(str(path.absolute()) not in item for item in command)
    assert options["env"]["CSL_PRIVATE_CHECK_PATH"] == str(path.absolute())
    assert options["env"]["LAB_MARKER"] == "preserved"
    assert all(key.upper() != "PSMODULEPATH" for key in options["env"])
    assert options["check"] is True and options["timeout"] == 10
