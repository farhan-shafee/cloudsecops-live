"""Offline worker socket guard: numeric loopback fixtures only, no DNS.

This guard applies to trusted Python worker code. It is not an OS network
sandbox against native extensions, subprocesses or deliberate monkeypatching.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
from typing import Any, NoReturn


def _denied(*args: Any, **kwargs: Any) -> NoReturn:
    raise OSError(errno.EACCES, "AWS_RUNNER_NETWORK_DENIED")


def _address(address: object) -> None:
    if not isinstance(address, tuple) or not 2 <= len(address) <= 4:
        _denied()
    host = address[0]
    if not isinstance(host, str):
        _denied()
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        _denied()
    if not parsed.is_loopback or "%" in host:
        _denied()


def install_offline_guard() -> None:
    """Install before importing any worker, SDK or HTTP dependency."""
    original_getaddrinfo = socket.getaddrinfo

    class LoopbackSocket(socket.socket):
        def connect(self, address: Any) -> None:
            _address(address)
            return super().connect(address)

        def connect_ex(self, address: Any) -> int:
            _address(address)
            return super().connect_ex(address)

        def bind(self, address: Any) -> None:
            _address(address)
            return super().bind(address)

        def sendto(self, data: Any, *args: Any) -> int:
            if not args:
                _denied()
            _address(args[-1])
            return super().sendto(data, *args)

        if hasattr(socket.socket, "sendmsg"):

            def sendmsg(
                self, buffers: Any, ancdata: Any = (), flags: int = 0, address: Any = None
            ) -> int:
                if address is not None:
                    _address(address)
                parent: Any = super()
                return int(parent.sendmsg(buffers, ancdata, flags, address))

    def numeric_getaddrinfo(
        host: Any,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[Any]:
        _address((host, port))
        return original_getaddrinfo(host, port, family, type, proto, flags | socket.AI_NUMERICHOST)

    socket_module: Any = socket
    socket_module.socket = LoopbackSocket
    socket.getaddrinfo = numeric_getaddrinfo
    socket.gethostbyname = _denied
    socket.gethostbyname_ex = _denied
    socket.gethostbyaddr = _denied
    socket.getnameinfo = _denied
    socket.getfqdn = _denied
