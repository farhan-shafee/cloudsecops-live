"""Trusted loopback-only fault workers, never AWS clients."""

import http.client
import socket
import ssl
import time


def network_fault(request: object) -> object:
    assert isinstance(request, dict)
    phase, port = request["phase"], request.get("port")
    if phase == "dns":
        # Simulate a resolver that ignores socket timeouts, without DNS traffic.
        def resolver(*args, **kwargs):
            time.sleep(60)

        socket.getaddrinfo = resolver
        socket.getaddrinfo("never-query.invalid", 443)
    elif phase in ("retry", "close"):
        time.sleep(60)
    elif phase == "tls":
        connection = socket.create_connection(("127.0.0.1", port))
        context = ssl.create_default_context()
        context.wrap_socket(connection, server_hostname="localhost")
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port)
        connection.request("GET", "/controlled-test")
        response = connection.getresponse()
        body = response.read(4097)
        if len(body) > 4096:
            raise ValueError("oversize-controlled-response")
        # Force Content-Length/chunk EOF validation even with a short read.
        if phase == "interrupted":
            response.read()
        return {"bytes": len(body)}
    return {"unexpected": "blocked work returned"}
