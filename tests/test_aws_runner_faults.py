"""Real local sockets exercise blocking phases beyond SDK read/connect timeouts."""

import json
import socket
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def fault_server(phase):
    stop = threading.Event()
    accepted = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    port = listener.getsockname()[1]

    def serve():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                accepted.set()
                connection.settimeout(0.2)
                if phase == "tls":
                    stop.wait(5)
                    return
                try:
                    connection.recv(8192)
                    if phase == "headers":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Len")
                    elif phase in ("chunks", "malformed_chunk"):
                        connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        connection.sendall(b"g\r\n" if phase == "malformed_chunk" else b"4000")
                        if phase == "malformed_chunk":
                            return
                    elif phase == "body":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nx")
                    elif phase == "interrupted":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nx")
                        return
                    elif phase == "oversized":
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n" + b"x" * 8192
                        )
                        return
                    stop.wait(5)
                except OSError:
                    return
            return

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, accepted
    finally:
        stop.set()
        listener.close()
        thread.join(1)
        assert not thread.is_alive()


def invoke(phase, port=None):
    from cloudsecops_live.integrations.aws_runner.process import WorkerRef, run_isolated

    started = time.monotonic()
    result = run_isolated(
        WorkerRef("tests.runner_network", "network_fault", ROOT),
        json.dumps({"phase": phase, "port": port}).encode(),
        timeout=2.5,
    )
    assert time.monotonic() - started < 2.5
    assert result.tree_terminated
    assert result.response is None
    assert result.to_public_dict()["authenticated"] is False
    return result


@pytest.mark.parametrize("phase", ["dns", "retry", "close"])
def test_watchdog_interrupts_blocking_work_without_cooperation(phase):
    assert invoke(phase).status == "deadline"


@pytest.mark.parametrize("phase", ["tls", "headers", "chunks", "body"])
def test_total_deadline_interrupts_real_loopback_protocol_stalls(phase):
    with fault_server(phase) as (port, accepted):
        result = invoke(phase, port)
        assert accepted.is_set(), "fault must reach the intended real socket phase"
        assert result.status == "deadline"


@pytest.mark.parametrize("phase", ["malformed_chunk", "interrupted", "oversized"])
def test_hostile_or_incomplete_body_never_returns_success(phase):
    with fault_server(phase) as (port, accepted):
        assert invoke(phase, port).status == "failed"
        assert accepted.is_set()
