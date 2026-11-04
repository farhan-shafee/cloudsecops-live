"""Trusted offline workers used by real isolated-runner tests."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def echo(request: object) -> object:
    return {"echo": request, "pid": os.getpid()}


def mark(request: object) -> object:
    assert isinstance(request, dict)
    Path(request["marker"]).write_text("started")
    return {"started": True}


def hang(request: object) -> object:
    while True:
        time.sleep(1)


def fail(request: object) -> object:
    raise RuntimeError("private-marker-should-never-escape")


def crash(request: object) -> object:
    os._exit(17)


def oversized(request: object) -> object:
    return "x" * 65536


def non_json(request: object) -> object:
    return {"unsupported"}


def noisy(request: object) -> object:
    print("private-marker-should-never-escape" * 10000)
    print("private-marker-should-never-escape", file=sys.stderr)
    return {"safe": True}


def environment(request: object) -> object:
    return {"keys": sorted(os.environ), "python_isolated": sys.flags.isolated}


def network_denial(request: object) -> object:
    denied: list[str] = []
    for name, action in (
        ("dns", lambda: socket.getaddrinfo("example.invalid", 443)),
        ("remote", lambda: socket.socket().connect(("192.0.2.1", 443))),
        ("hostname", lambda: socket.socket().connect(("localhost", 443))),
    ):
        try:
            action()
        except OSError:
            denied.append(name)
    return denied


def tree(request: object) -> object:
    assert isinstance(request, dict)
    marker = Path(request["marker"])
    child_code = (
        "import os,signal,subprocess,sys,time; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        "p=subprocess.Popen([sys.executable,'-I','-c',"
        "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)']); "
        "open(sys.argv[1],'w').write(str(os.getpid())+' '+str(p.pid)); time.sleep(60)"
    )
    subprocess.Popen([sys.executable, "-I", "-c", child_code, str(marker)])
    if request.get("success"):
        end = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < end:
            time.sleep(0.01)
        return {"done": True}
    return hang(request)
