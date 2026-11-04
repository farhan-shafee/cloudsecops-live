"""Direct socket behavior tests restore every global patch after each guard."""

import socket
from contextlib import contextmanager

import pytest

from cloudsecops_live.integrations.aws_runner.network import _address, install_offline_guard


@contextmanager
def guarded(monkeypatch):
    names = (
        "socket",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "getnameinfo",
        "getfqdn",
    )
    with monkeypatch.context() as patch:
        for name in names:
            patch.setattr(socket, name, getattr(socket, name))
        install_offline_guard()
        yield


@pytest.mark.parametrize(
    "address",
    [
        None,
        "127.0.0.1",
        [],
        (),
        ("127.0.0.1",),
        ("127.0.0.1", 1, 2, 3, 4),
        (b"127.0.0.1", 443),
        ("localhost", 443),
        ("192.0.2.1", 443),
        ("0.0.0.0", 443),
        ("::1%1", 443),
    ],
)
def test_invalid_or_nonloopback_addresses_are_denied(address):
    with pytest.raises(OSError, match="AWS_RUNNER_NETWORK_DENIED"):
        _address(address)


def test_real_guarded_tcp_connect_and_connect_ex_stay_on_loopback(monkeypatch):
    with guarded(monkeypatch):
        with socket.socket() as listener:
            listener.settimeout(1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            for use_connect_ex in (False, True):
                with socket.socket() as client:
                    client.settimeout(1)
                    if use_connect_ex:
                        assert client.connect_ex(listener.getsockname()) == 0
                    else:
                        client.connect(listener.getsockname())
                    connection, address = listener.accept()
                    with connection:
                        client.sendall(b"offline")
                        assert connection.recv(7) == b"offline"
                        assert address[0] == "127.0.0.1"


def test_guarded_udp_uses_numeric_loopback_and_rejects_remote_destinations(monkeypatch):
    with guarded(monkeypatch):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.settimeout(1)
            server.bind(("127.0.0.1", 0))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                assert client.sendto(b"offline", server.getsockname()) == 7
                assert server.recvfrom(32)[0] == b"offline"
                for args in ((), (("192.0.2.1", 443),)):
                    with pytest.raises(OSError, match="AWS_RUNNER_NETWORK_DENIED"):
                        client.sendto(b"denied", *args)
                if hasattr(client, "sendmsg"):
                    assert client.sendmsg([b"offline"], [], 0, server.getsockname()) == 7
                    assert server.recvfrom(32)[0] == b"offline"
                    client.connect(server.getsockname())
                    assert client.sendmsg([b"connected"]) == 9
                    assert server.recvfrom(32)[0] == b"connected"
                    with pytest.raises(OSError, match="AWS_RUNNER_NETWORK_DENIED"):
                        client.sendmsg([b"denied"], [], 0, ("192.0.2.1", 443))


def test_guard_rejects_remote_connect_ex_bind_and_all_dns_helpers(monkeypatch):
    with guarded(monkeypatch):
        with socket.socket() as client:
            for method in (client.connect, client.connect_ex, client.bind):
                with pytest.raises(OSError, match="AWS_RUNNER_NETWORK_DENIED"):
                    method(("192.0.2.1", 443))
        for helper, args in (
            (socket.getaddrinfo, ("localhost", 443)),
            (socket.gethostbyname, ("example.invalid",)),
            (socket.gethostbyname_ex, ("example.invalid",)),
            (socket.gethostbyaddr, ("127.0.0.1",)),
            (socket.getnameinfo, (("127.0.0.1", 443), 0)),
            (socket.getfqdn, ()),
        ):
            with pytest.raises(OSError, match="AWS_RUNNER_NETWORK_DENIED"):
                helper(*args)
        numeric = socket.getaddrinfo("127.0.0.1", 443, type=socket.SOCK_STREAM)
        assert numeric and all(item[4][0] == "127.0.0.1" for item in numeric)


def test_guard_restores_original_socket_functions(monkeypatch):
    before = socket.socket, socket.getaddrinfo, socket.getfqdn
    with guarded(monkeypatch):
        assert socket.socket is not before[0]
    assert (socket.socket, socket.getaddrinfo, socket.getfqdn) == before
