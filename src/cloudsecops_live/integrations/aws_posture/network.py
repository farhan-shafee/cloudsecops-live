"""Separate default-deny posture bootstrap guard, with no live policy issuer.

This Python guard supplements native lifecycle containment. It is not an OS
firewall or a sandbox against arbitrary same-user/native code. Real egress and
OS containment approval remain mandatory live preflight gates.
"""

from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
from typing import Any, NoReturn


def _denied(*args: Any, **kwargs: Any) -> NoReturn:
    raise PermissionError(errno.EACCES, "AWS4A_EGRESS_OR_PROCESS_DENIED")


def install_posture_guard() -> None:
    """No flags, endpoints or caller metadata can relax this bootstrap guard."""
    for name in (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "getnameinfo",
        "getfqdn",
        "create_connection",
    ):
        setattr(socket, name, _denied)
    # Patch the shared class, not only a replacement subclass: SSLSocket's
    # inherited connect path must be denied too. Native bypass is outside this
    # Python boundary and therefore cannot support an enabled execution claim.
    for name in ("connect", "connect_ex", "bind", "sendto", "sendmsg"):
        if hasattr(socket.socket, name):
            setattr(socket.socket, name, _denied)
    subprocess.Popen = _denied  # type: ignore[misc, assignment]
    for name in ("system", "fork", "forkpty", "posix_spawn", "posix_spawnp", "setsid", "setpgid"):
        if hasattr(os, name):
            setattr(os, name, _denied)

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event in {
            "subprocess.Popen",
            "os.system",
            "os.fork",
            "os.forkpty",
            "os.exec",
            "os.posix_spawn",
        }:
            _denied()

    sys.addaudithook(audit)
