"""Fixed local negative probes; never selected through the production request."""

import os
import socket
import subprocess
import time


def guard_probe(value):
    from cloudsecops_live.integrations.aws_posture.network import install_posture_guard

    install_posture_guard()

    def socket_probe(method, address):
        with socket.socket() as client:
            return getattr(client, method)(address)

    operations = [
        lambda: socket.getaddrinfo("127.0.0.1", 443),
        lambda: socket.gethostbyname("example.invalid"),
        lambda: socket.getfqdn("example.invalid"),
        lambda: socket.create_connection(("127.0.0.1", 443)),
        lambda: socket_probe("connect", ("127.0.0.1", 443)),
        lambda: socket_probe("connect_ex", ("127.0.0.1", 443)),
        lambda: socket_probe("bind", ("127.0.0.1", 0)),
        lambda: subprocess.Popen(["not-an-executable"]),
        lambda: os.system("not-a-command"),
    ]
    denied = 0
    for operation in operations:
        try:
            operation()
        except PermissionError:
            denied += 1
    return {"denied": denied, "authenticated": False}


def wire_fault(value):
    """A trusted numeric-loopback fixture, not the disabled production entrypoint."""
    import http.client

    from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
    from cloudsecops_live.integrations.aws_posture.wire import BoundedReader
    from tests.aws4a_helpers import NOW, decision, session

    assert type(value) is dict
    phase = value["phase"]
    if phase in {"dns", "retry", "close"}:
        time.sleep(60)
        raise AssertionError("uncooperative fixture unexpectedly resumed")
    if phase == "crash":
        os._exit(7)
    # Actual socket/TLS faults keep the existing loopback-only bootstrap guard.
    if phase == "tls":
        from tests.runner_network import network_fault

        return network_fault(value)
    connection = socket.create_connection(("127.0.0.1", value["port"]))
    with connection:
        connection.sendall(b"GET /bounded-offline-fault HTTP/1.1\r\nHost: localhost\r\n\r\n")
        budget = PostureBudget(decision(), session(), clock=lambda: NOW, monotonic=time.monotonic)

        class FramedSocket:
            def makefile(self, *args, **kwargs):
                return BoundedReader(connection.makefile(*args, **kwargs), budget)

        # Use the real HTTP header/chunk/content-length parser over the same
        # bounded pre-framing reader used by the guarded SDK transport.
        response = http.client.HTTPResponse(FramedSocket())
        try:
            response.begin()
            data = response.read(4097)
            if len(data) > 4096 or len(data) != value.get("expected_bytes", 4096):
                raise ValueError("controlled incomplete/oversized body")
            return {
                "bytes": len(data),
                "authenticated": False,
                "trusted_findings_available": False,
                "closure_available": False,
            }
        finally:
            response.close()
