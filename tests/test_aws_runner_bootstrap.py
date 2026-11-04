"""Exercise bootstrap policy with fake descriptors, never redirect test FDs."""

import io
import json
import runpy
import struct
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from cloudsecops_live.integrations.aws_runner import bootstrap, network


class Protocol(io.BytesIO):
    def fileno(self):
        return 92

    def close(self):
        self.was_closed = True


def control(**changes):
    return {
        "work_cutoff": time.monotonic() + 5,
        "paths": ["trusted-fixtures"],
        "module": "trusted.registry",
        "function": "worker",
        "request": {"fixture": "offline"},
        "max_response_bytes": 1024,
        **changes,
    }


def framed(value):
    encoded = json.dumps(value).encode()
    return b"G" + struct.pack("!I", len(encoded)) + encoded


@contextmanager
def bootstrap_context(
    monkeypatch, raw, action=lambda request: {"echo": request}, clock=time.monotonic
):
    output, calls = Protocol(), []
    with monkeypatch.context() as patch:
        patch.setattr(bootstrap.sys, "stdout", SimpleNamespace(fileno=lambda: 91))
        patch.setattr(bootstrap.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
        patch.setattr(bootstrap.sys, "path", list(bootstrap.sys.path))
        patch.setattr(bootstrap.os, "dup", lambda fd: 92)
        patch.setattr(bootstrap.os, "fdopen", lambda *args, **kwargs: output)
        patch.setattr(
            bootstrap.os, "set_inheritable", lambda *args: calls.append(("inherit", args))
        )
        patch.setattr(bootstrap.os, "dup2", lambda *args: calls.append(("discard", args)))
        patch.setattr(bootstrap, "time", SimpleNamespace(monotonic=clock))
        patch.setattr(network, "install_offline_guard", lambda: calls.append(("guard",)))

        def import_worker(name):
            assert ("guard",) in calls, "guard must be installed before worker imports"
            calls.append(("import", name))
            return SimpleNamespace(worker=action)

        patch.setattr(bootstrap, "importlib", SimpleNamespace(import_module=import_worker))
        yield output, calls


def envelope(output):
    data = output.getvalue()
    assert len(data) >= 4
    assert struct.unpack("!I", data[:4])[0] == len(data) - 4
    return json.loads(data[4:])


def test_bootstrap_gates_then_guards_before_import_and_discards_child_output(monkeypatch):
    with bootstrap_context(monkeypatch, framed(control())) as (output, calls):
        assert bootstrap.main() == 0
    assert envelope(output) == {"status": "ok", "response": {"echo": {"fixture": "offline"}}}
    assert ("inherit", (92, False)) in calls
    assert [call[1][1] for call in calls if call[0] == "discard"] == [1, 2]
    assert output.was_closed


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"X",
        b"G",
        b"G\x00\x00\x00\x00",
        b"G" + struct.pack("!I", bootstrap.MAX_CONTROL_BYTES + 1),
        b"G\x00\x00\x00\x02{",
        b"G\x00\x00\x00\x01!",
    ],
)
def test_bootstrap_rejects_missing_gate_or_invalid_control_before_import(monkeypatch, raw):
    with bootstrap_context(monkeypatch, raw) as (output, calls):
        assert bootstrap.main() == 2
    assert not any(call[0] in ("guard", "import") for call in calls)
    assert output.was_closed


def test_bootstrap_expired_dispatch_never_imports_worker(monkeypatch):
    with bootstrap_context(monkeypatch, framed(control(work_cutoff=10)), clock=lambda: 11) as (
        output,
        calls,
    ):
        assert bootstrap.main() == 2
    assert not any(call[0] in ("guard", "import") for call in calls)
    assert output.getvalue() == b""


def test_bootstrap_rechecks_deadline_after_import_before_action(monkeypatch):
    ticks = iter([1, 11])
    invoked = []
    with bootstrap_context(
        monkeypatch,
        framed(control(work_cutoff=10)),
        action=lambda request: invoked.append(request),
        clock=lambda: next(ticks),
    ) as (output, calls):
        assert bootstrap.main() == 2
    assert ("import", "trusted.registry") in calls
    assert invoked == []
    assert output.getvalue() == b""


@pytest.mark.parametrize("value", [object(), float("nan"), {"unsupported"}])
def test_bootstrap_cannot_serialize_nonjson_or_nonfinite_response(monkeypatch, value):
    with bootstrap_context(monkeypatch, framed(control()), action=lambda request: value) as (
        output,
        calls,
    ):
        assert bootstrap.main() == 2
    assert envelope(output) == {"status": "failed", "reason": "AWS_RUNNER_WORKER_FAILED"}


def test_bootstrap_rejects_oversized_response_and_sanitizes_worker_exception(monkeypatch):
    with bootstrap_context(
        monkeypatch, framed(control(max_response_bytes=4)), action=lambda request: "too large"
    ) as (output, calls):
        assert bootstrap.main() == 0
    assert envelope(output) == {"status": "failed", "reason": "AWS_RUNNER_RESPONSE_LIMIT"}

    def failed(request):
        raise RuntimeError("private-marker")

    with bootstrap_context(monkeypatch, framed(control()), action=failed) as (output, calls):
        assert bootstrap.main() == 2
    assert b"private-marker" not in output.getvalue()
    assert envelope(output)["reason"] == "AWS_RUNNER_WORKER_FAILED"


def test_bootstrap_broken_protocol_does_not_escape_worker_exception(monkeypatch):
    with bootstrap_context(monkeypatch, framed(control())) as (output, calls):

        def broken(block):
            raise BrokenPipeError("private-marker")

        monkeypatch.setattr(output, "write", broken)
        assert bootstrap.main() == 2
    assert output.getvalue() == b""
    assert output.was_closed


@pytest.mark.parametrize("result", [None, 0])
def test_bootstrap_nonprogressing_protocol_write_is_rejected(result):
    with pytest.raises(OSError, match="AWS_RUNNER_PROTOCOL"):
        bootstrap._send(SimpleNamespace(write=lambda block: result), {"safe": True})


def test_bootstrap_completes_partial_frame_reads_and_writes():
    class Partial(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 1))

        def write(self, block):
            return super().write(block[:1])

    assert bootstrap._exact(Partial(b"offline"), 7) == b"offline"
    destination = Partial()
    bootstrap._send(destination, {"safe": True})
    assert envelope(destination) == {"safe": True}


def test_private_bootstrap_script_has_no_ungated_operation_entry(monkeypatch):
    with bootstrap_context(monkeypatch, b"") as (output, calls):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(bootstrap.__file__, run_name="__main__")
    assert stopped.value.code == 2
    assert not any(call[0] == "import" for call in calls)
