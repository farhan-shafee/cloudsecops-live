"""Private gated bootstrap. No command-line operation or live client factory."""

from __future__ import annotations

import importlib
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO

MAX_CONTROL_BYTES = 1024 * 1024 + 65536


def _send(protocol: BinaryIO, value: object) -> None:
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    pending = memoryview(struct.pack("!I", len(encoded)) + encoded)
    while pending:
        written = protocol.write(pending)
        if written is None or written <= 0:
            raise OSError("AWS_RUNNER_PROTOCOL")
        pending = pending[written:]


def _exact(source: BinaryIO, size: int) -> bytes:
    staged = bytearray()
    while len(staged) < size:
        chunk = source.read(min(16384, size - len(staged)))
        if not chunk:
            raise OSError("AWS_RUNNER_PROTOCOL")
        staged.extend(chunk)
    return bytes(staged)


def main() -> int:
    # The protocol FD is not inherited by worker-created children. Ordinary
    # stdout/stderr, including dependency output and tracebacks, are discarded.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    os.set_inheritable(protocol.fileno(), False)
    with open(os.devnull, "wb", buffering=0) as discarded:
        os.dup2(discarded.fileno(), 1)
        os.dup2(discarded.fileno(), 2)
    try:
        # Before this gate, only stdlib bootstrap imports have run. No worker,
        # site/.pth code, network client or subprocess can run before assignment.
        if sys.stdin.buffer.read(1) != b"G":
            return 2
        header = _exact(sys.stdin.buffer, 4)
        size = struct.unpack("!I", header)[0]
        if not 1 <= size <= MAX_CONTROL_BYTES:
            return 2
        raw = _exact(sys.stdin.buffer, size)
        control = json.loads(raw)
        if time.monotonic() >= control["work_cutoff"]:
            return 2
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from cloudsecops_live.integrations.aws_runner.network import install_offline_guard

        install_offline_guard()
        # -S avoids code in site/.pth files before containment. Explicit package
        # paths supplied by the trusted parent make dependencies importable.
        for root in reversed(control["paths"]):
            sys.path.insert(0, root)
        module = importlib.import_module(control["module"])
        action: Any = getattr(module, control["function"])
        if time.monotonic() >= control["work_cutoff"]:
            return 2
        response = action(control["request"])
        encoded = json.dumps(
            response, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode()
        if len(encoded) > control["max_response_bytes"]:
            _send(protocol, {"status": "failed", "reason": "AWS_RUNNER_RESPONSE_LIMIT"})
        else:
            _send(protocol, {"status": "ok", "response": response})
    except BaseException:
        try:
            _send(protocol, {"status": "failed", "reason": "AWS_RUNNER_WORKER_FAILED"})
        except BaseException:
            pass
        return 2
    finally:
        protocol.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
