"""Fixed posture bootstrap. No code path enables AWS execution in this release."""

from __future__ import annotations

import json
import logging
import math
import os
import struct
import sys
import time
from pathlib import Path
from typing import BinaryIO


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("AWS4A_PROTOCOL")
        value[key] = child
    return value


def _constant(value: str) -> object:
    raise ValueError("AWS4A_PROTOCOL")


def _exact(source: BinaryIO, count: int) -> bytes:
    output = bytearray()
    while len(output) < count:
        chunk = source.read(min(16384, count - len(output)))
        if not chunk:
            raise ValueError("AWS4A_PROTOCOL")
        output.extend(chunk)
    return bytes(output)


def _send(protocol: BinaryIO, reason: str) -> None:
    raw = json.dumps({"status": "failed", "reason": reason}, separators=(",", ":")).encode()
    pending = memoryview(struct.pack("!I", len(raw)) + raw)
    while pending:
        size = protocol.write(pending)
        if size is None or size <= 0:
            raise ValueError("AWS4A_PROTOCOL")
        pending = pending[size:]


def main() -> int:
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    os.set_inheritable(protocol.fileno(), False)
    with open(os.devnull, "wb", buffering=0) as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        if sys.argv[1:] or sys.stdin.buffer.read(1) != b"G":
            return 2
        size = struct.unpack("!I", _exact(sys.stdin.buffer, 4))[0]
        if not 1 <= size <= 1024 * 1024 + 65536:
            return 2
        control = json.loads(
            _exact(sys.stdin.buffer, size), object_pairs_hook=_pairs, parse_constant=_constant
        )
        if (
            type(control) is not dict
            or set(control)
            != {"module", "function", "paths", "request", "max_response_bytes", "work_cutoff"}
            or control["module"] != "cloudsecops_live.integrations.aws_posture.worker"
            or control["function"] != "execute"
            or type(control["paths"]) is not list
            or len(control["paths"]) > 64
            or any(type(root) is not str or len(root) > 4096 for root in control["paths"])
            or type(control["max_response_bytes"]) is not int
            or not 1 <= control["max_response_bytes"] <= 1024 * 1024
            or type(control["work_cutoff"]) not in (int, float)
            or not math.isfinite(control["work_cutoff"])
            or time.monotonic() >= control["work_cutoff"]
        ):
            return 2
        # Native ownership has been established before the parent sends G.
        # No worker/dependency or .pth code executes before that gate.
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        logging.disable(logging.CRITICAL)
        from cloudsecops_live.integrations.aws_posture.network import install_posture_guard

        install_posture_guard()
        # Disabled execution needs only the package's pure request validator.
        # Parent dependency search paths are deliberately NOT imported. No SDK,
        # owner-record loader, credential handle or client is reached here.
        from cloudsecops_live.errors import EvidenceError
        from cloudsecops_live.integrations.aws_posture.worker import execute

        if time.monotonic() >= control["work_cutoff"]:
            return 2
        try:
            execute(control["request"])
        except EvidenceError as error:
            if error.code == "AWS4A_EXECUTION_DISABLED":
                _send(protocol, "AWS4A_EXECUTION_DISABLED")
                return 2
            raise
    except BaseException:
        try:
            _send(protocol, "AWS_RUNNER_WORKER_FAILED")
        except BaseException:
            pass
        return 2
    finally:
        protocol.close()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
