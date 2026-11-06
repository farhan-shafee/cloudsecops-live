"""Internal offline process runner with an independent supervisor thread.

Entrypoints are trusted local code references, never request-selected commands.
The supervisor imports no worker code and is independent of blocked worker I/O.
Linux fixed workers must keep all descendants in their inherited process group.
OS process creation/scheduling cannot be made realtime by Python; a late launch
remains behind its gate and is terminated without invoking the operation.
"""

from __future__ import annotations

import json
import math
import os
import re
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Literal

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_runner.containment import ProcessTree

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
_REASONS = {"AWS_RUNNER_RESPONSE_LIMIT", "AWS_RUNNER_WORKER_FAILED"}


@dataclass(frozen=True)
class WorkerRef:
    """Trusted code control supplied by a fixed local registry, not JSON input."""

    module: str
    function: str
    import_root: Path = field(repr=False)


@dataclass(frozen=True)
class IsolatedResult:
    status: Literal["ok", "deadline", "cancelled", "failed"]
    response: bytes | None = field(repr=False)
    elapsed_seconds: float
    tree_terminated: bool
    reason: str

    def to_public_dict(self) -> dict[str, object]:
        """Sanitized lifecycle receipt; worker payload never becomes a receipt."""
        return {
            "status": self.status,
            "reason": self.reason,
            "elapsed_ms": round(self.elapsed_seconds * 1000, 3),
            "tree_terminated": self.tree_terminated,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
        }


def _reject_constant(value: str) -> object:
    raise ValueError("AWS_RUNNER_JSON")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("AWS_RUNNER_JSON")
        output[key] = value
    return output


def _json(raw: bytes) -> object:
    value: object = json.loads(
        raw.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_pairs
    )
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 32 or count > 100_000:
            raise ValueError("AWS_RUNNER_JSON")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def _environment() -> dict[str, str]:
    environment = {
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "BOTO_CONFIG": os.devnull,
    }
    if sys.platform == "win32":
        for key in ("SystemRoot", "WINDIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def _read_frame(
    source: BinaryIO, cap: int, received: list[bytes | None], ready: threading.Event
) -> None:
    try:
        header = bytearray()
        while len(header) < 4:
            piece = source.read(4 - len(header))
            if not piece:
                return
            header.extend(piece)
        size = struct.unpack("!I", header)[0]
        if not 1 <= size <= cap:
            return
        staged = bytearray()
        while len(staged) < size:
            piece = source.read(min(16384, size - len(staged)))
            if not piece:
                return
            staged.extend(piece)
        # One bounded frame followed by EOF is the entire private protocol.
        # Waiting for EOF stays in this reader thread, outside the watchdog.
        if source.read(1):
            return
        received[0] = bytes(staged)
    except (OSError, ValueError):
        pass
    finally:
        ready.set()


def _write_control(
    destination: BinaryIO,
    control: bytes,
    stop: threading.Event | None = None,
    cancel: threading.Event | None = None,
    work_cutoff: float = math.inf,
) -> None:
    try:
        pending = memoryview(b"G" + struct.pack("!I", len(control)) + control)
        while pending:
            if (
                (stop is not None and stop.is_set())
                or (cancel is not None and cancel.is_set())
                or time.monotonic() >= work_cutoff
            ):
                return
            written = destination.write(pending)
            if written is None or written <= 0:
                return
            pending = pending[written:]
    except (OSError, ValueError):
        pass


def _reap_killed(process: subprocess.Popen[bytes]) -> None:
    """Retain/reap a killed late launch after an unconfirmed public receipt.

    Some OS creation APIs cannot be interrupted. The caller has already received
    a negative receipt; this helper never releases the operation gate or sends a
    signal using a reaped/reusable PID.
    """
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def run_isolated(
    entrypoint: WorkerRef,
    request: bytes,
    *,
    timeout: float = 5.0,
    cancel: threading.Event | None = None,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> IsolatedResult:
    """Original fixture entrypoint, retaining its fixed offline bootstrap."""
    return _run_with_bootstrap(
        entrypoint,
        request,
        timeout=timeout,
        cancel=cancel,
        max_response_bytes=max_response_bytes,
        bootstrap_name="fixture",
    )


def _run_with_bootstrap(
    entrypoint: WorkerRef,
    request: bytes,
    *,
    timeout: float = 5.0,
    cancel: threading.Event | None = None,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    bootstrap_name: str,
) -> IsolatedResult:
    """Run fixed trusted Python code with bounded JSON IPC and owned cleanup.

    The timeout includes startup and a reserved shutdown interval. Failure to
    confirm tree shutdown is reported explicitly and can never produce success.
    """
    started = time.monotonic()
    if (
        type(timeout) not in (int, float)
        or not 0.2 <= timeout <= 30
        or type(max_response_bytes) is not int
        or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
        or type(entrypoint) is not WorkerRef
        or type(request) is not bytes
        or not 1 <= len(request) <= MAX_REQUEST_BYTES
        or not isinstance(entrypoint.import_root, Path)
        or not entrypoint.import_root.is_absolute()
        or type(entrypoint.module) is not str
        or type(entrypoint.function) is not str
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", entrypoint.module) is None
        or re.fullmatch(r"[A-Za-z_]\w*", entrypoint.function) is None
        or sys.platform not in ("win32", "linux")
        or type(bootstrap_name) is not str
        or bootstrap_name not in {"fixture", "posture"}
    ):
        raise EvidenceError("AWS_RUNNER_CONFIG")
    deadline = started + timeout
    work_cutoff = deadline - min(0.5, timeout * 0.25)
    bootstrap = (
        Path(__file__).with_name("bootstrap.py")
        if bootstrap_name == "fixture"
        else Path(__file__).parents[1] / "aws_posture" / "bootstrap.py"
    )
    reasons = _REASONS if bootstrap_name == "fixture" else _REASONS | {"AWS4A_EXECUTION_DISABLED"}
    try:
        parsed = _json(request)
        # Explicit installed-package paths are data, not site/.pth execution.
        paths = list(
            dict.fromkeys(
                [
                    str(entrypoint.import_root),
                    *(item for item in sys.path if item and Path(item).is_absolute()),
                ]
            )
        )
        control = json.dumps(
            {
                "module": entrypoint.module,
                "function": entrypoint.function,
                "paths": paths,
                "request": parsed,
                "max_response_bytes": max_response_bytes,
                "work_cutoff": work_cutoff,
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
        if len(control) > MAX_REQUEST_BYTES + 65536:
            raise ValueError()
    except (TypeError, ValueError, RecursionError):
        raise EvidenceError("AWS_RUNNER_REQUEST") from None
    finished, stop = threading.Event(), threading.Event()
    result: list[IsolatedResult | None] = [None]

    def outcome(
        status: Literal["ok", "deadline", "cancelled", "failed"],
        response: bytes | None,
        cleaned: bool,
        reason: str,
    ) -> IsolatedResult:
        return IsolatedResult(status, response, time.monotonic() - started, cleaned, reason)

    if cancel is not None and cancel.is_set():
        return outcome("cancelled", None, True, "AWS_RUNNER_CANCELLED")

    def supervise() -> None:
        process: subprocess.Popen[bytes] | None = None
        tree: ProcessTree | None = None
        status: Literal["ok", "deadline", "cancelled", "failed"] = "failed"
        reason, response, cleaned = "AWS_RUNNER_WORKER_FAILED", None, False
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", str(bootstrap)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_environment(),
                close_fds=True,
                bufsize=0,
                start_new_session=sys.platform == "linux",
            )
            # The operation remains behind its gate if launch completes late.
            tree = ProcessTree(process)
            if stop.is_set() or time.monotonic() >= work_cutoff:
                status, reason = "deadline", "AWS_RUNNER_DEADLINE"
            elif cancel is not None and cancel.is_set():
                status, reason = "cancelled", "AWS_RUNNER_CANCELLED"
            else:
                assert process.stdin is not None and process.stdout is not None
                ready = threading.Event()
                received: list[bytes | None] = [None]
                reader = threading.Thread(
                    target=_read_frame,
                    args=(process.stdout, max_response_bytes + 256, received, ready),
                    daemon=True,
                )
                writer = threading.Thread(
                    target=_write_control,
                    args=(process.stdin, control, stop, cancel, work_cutoff),
                    daemon=True,
                )
                reader.start()
                writer.start()
                while True:
                    if cancel is not None and cancel.is_set():
                        status, reason = "cancelled", "AWS_RUNNER_CANCELLED"
                        break
                    if stop.is_set() or time.monotonic() >= work_cutoff:
                        status, reason = "deadline", "AWS_RUNNER_DEADLINE"
                        break
                    if ready.wait(min(0.01, max(0.0, work_cutoff - time.monotonic()))):
                        raw = received[0]
                        if raw is None:
                            reason = "AWS_RUNNER_PROTOCOL"
                            break
                        envelope = _json(raw)
                        if type(envelope) is not dict:
                            reason = "AWS_RUNNER_PROTOCOL"
                            break
                        if envelope.get("status") == "ok" and set(envelope) == {
                            "status",
                            "response",
                        }:
                            response = json.dumps(
                                envelope["response"],
                                ensure_ascii=False,
                                allow_nan=False,
                                separators=(",", ":"),
                            ).encode()
                            if len(response) <= max_response_bytes:
                                status, reason = "ok", "AWS_RUNNER_OK"
                            else:
                                response, reason = None, "AWS_RUNNER_RESPONSE_LIMIT"
                        elif (
                            envelope.get("status") == "failed"
                            and set(envelope) == {"status", "reason"}
                            and envelope.get("reason") in reasons
                        ):
                            reason = str(envelope["reason"])
                        else:
                            reason = "AWS_RUNNER_PROTOCOL"
                        break
        except Exception:
            reason = (
                "AWS_RUNNER_CONTAINMENT"
                if process is not None and tree is None
                else "AWS_RUNNER_WORKER_FAILED"
            )
        finally:
            if tree is not None:
                try:
                    cleaned = tree.terminate(deadline)
                except Exception:
                    cleaned = False
                finally:
                    tree.close()
            elif process is not None:
                # No operation has crossed the gate on containment failure.
                try:
                    process.kill()
                    process.wait(timeout=max(0.0, deadline - time.monotonic()))
                    cleaned = True
                except (OSError, subprocess.TimeoutExpired):
                    cleaned = False
            else:
                cleaned = True
            if process is not None:
                if process.returncode is None:
                    threading.Thread(target=_reap_killed, args=(process,), daemon=True).start()
                for channel in (process.stdin, process.stdout):
                    if channel is not None:
                        channel.close()
            if not cleaned:
                status, response, reason = "failed", None, "AWS_RUNNER_CLEANUP"
            if cancel is not None and cancel.is_set() and status == "ok":
                status, response, reason = "cancelled", None, "AWS_RUNNER_CANCELLED"
            if time.monotonic() >= deadline and status == "ok":
                status, response, reason = "deadline", None, "AWS_RUNNER_DEADLINE"
            result[0] = outcome(status, response, cleaned, reason)
            finished.set()

    watchdog = threading.Thread(target=supervise, daemon=True, name="aws-offline-watchdog")
    watchdog.start()
    if not finished.wait(max(0.0, deadline - time.monotonic())):
        stop.set()
        return outcome("deadline", None, False, "AWS_RUNNER_SHUTDOWN_UNCONFIRMED")
    assert result[0] is not None
    return result[0]
