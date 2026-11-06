"""Private framing and disabled gate tests never redirect the pytest process FDs."""

import io
import json
import runpy
import struct
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture import bootstrap, network, worker


class Protocol(io.BytesIO):
    def fileno(self):
        return 92

    def close(self):
        self.was_closed = True


def control(**changes):
    return {
        "module": "cloudsecops_live.integrations.aws_posture.worker",
        "function": "execute",
        "paths": ["must-not-be-consumed-as-an-import-root"],
        "request": {
            "schema_version": "aws4a-posture-request/1",
            "decision_ref": "a" * 64,
            "nonce": "b" * 64,
        },
        "work_cutoff": time.monotonic() + 5,
        "max_response_bytes": 1024,
        **changes,
    }


def framed(value):
    raw = json.dumps(value).encode()
    return b"G" + struct.pack("!I", len(raw)) + raw


@contextmanager
def context(monkeypatch, raw, *, action=None, clock=time.monotonic):
    output, calls = Protocol(), []
    with monkeypatch.context() as patch:
        patch.setattr(bootstrap.sys, "argv", ["fixed-bootstrap"])
        patch.setattr(bootstrap.sys, "stdout", SimpleNamespace(fileno=lambda: 91))
        patch.setattr(bootstrap.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
        patch.setattr(bootstrap.sys, "path", list(bootstrap.sys.path))
        patch.setattr(bootstrap.os, "dup", lambda fd: 92)
        patch.setattr(bootstrap.os, "fdopen", lambda *a, **k: output)
        patch.setattr(bootstrap.os, "set_inheritable", lambda *a: calls.append(("inherit", a)))
        patch.setattr(bootstrap.os, "dup2", lambda *a: calls.append(("discard", a)))
        patch.setattr(bootstrap.logging, "disable", lambda *a: calls.append(("logging-off",)))
        patch.setattr(bootstrap, "time", SimpleNamespace(monotonic=clock))
        patch.setattr(network, "install_posture_guard", lambda: calls.append(("guard",)))
        original = worker.execute

        def execute(value):
            assert ("guard",) in calls
            assert "must-not-be-consumed-as-an-import-root" not in bootstrap.sys.path
            calls.append(("execute",))
            return original(value) if action is None else action(value)

        patch.setattr(worker, "execute", execute)
        yield output, calls


def result(output):
    raw = output.getvalue()
    assert struct.unpack("!I", raw[:4])[0] == len(raw) - 4
    return json.loads(raw[4:])


def test_valid_control_guards_and_disables_without_credential_or_dependency_lookup(monkeypatch):
    with context(monkeypatch, framed(control())) as (output, calls):
        assert bootstrap.main() == 2
    assert result(output) == {"status": "failed", "reason": "AWS4A_EXECUTION_DISABLED"}
    assert ("execute",) in calls and ("inherit", (92, False)) in calls
    assert [c[1][1] for c in calls if c[0] == "discard"] == [1, 2]
    assert output.was_closed


@pytest.mark.parametrize(
    "raw",
    [b"", b"X", b"G", b"G" + struct.pack("!I", 0), b"G" + struct.pack("!I", 2**30), framed([])],
)
def test_invalid_gate_or_frame_never_imports_worker(monkeypatch, raw):
    with context(monkeypatch, raw) as (output, calls):
        assert bootstrap.main() == 2
    assert ("guard",) not in calls and ("execute",) not in calls


@pytest.mark.parametrize(
    "changes",
    [
        {"module": "os"},
        {"function": "system"},
        {"unexpected": True},
        {"paths": {}},
        {"paths": ["x"] * 65},
        {"paths": [None]},
        {"paths": ["x" * 4097]},
        {"max_response_bytes": True},
        {"max_response_bytes": 0},
        {"work_cutoff": "later"},
        {"work_cutoff": float("nan")},
        {"work_cutoff": 1},
    ],
)
def test_control_cannot_select_code_limits_or_unbounded_values(monkeypatch, changes):
    with context(monkeypatch, framed(control(**changes))) as (output, calls):
        assert bootstrap.main() == 2
    assert ("guard",) not in calls


def test_duplicate_control_keys_are_not_last_wins(monkeypatch):
    value = json.dumps(control())[:-1] + ',"function":"execute"}'
    raw = value.encode()
    with context(monkeypatch, b"G" + struct.pack("!I", len(raw)) + raw) as (output, calls):
        assert bootstrap.main() == 2
    assert ("guard",) not in calls


def test_deadline_is_rechecked_after_guard_import(monkeypatch):
    ticks = iter([1, 10])
    with context(monkeypatch, framed(control(work_cutoff=5)), clock=lambda: next(ticks)) as (
        output,
        calls,
    ):
        assert bootstrap.main() == 2
    assert ("guard",) in calls and ("execute",) not in calls


@pytest.mark.parametrize(
    "error", [RuntimeError("private-fake-marker"), EvidenceError("PRIVATE_FAKE_REASON")]
)
def test_unknown_failures_never_echo_exception_details(monkeypatch, error):
    def broken(value):
        raise error

    with context(monkeypatch, framed(control()), action=broken) as (output, calls):
        assert bootstrap.main() == 2
    assert result(output) == {"status": "failed", "reason": "AWS_RUNNER_WORKER_FAILED"}
    assert b"private-fake-marker" not in output.getvalue()


def test_broken_protocol_is_negative_and_standalone_script_has_no_ungated_entry(monkeypatch):
    with context(monkeypatch, framed(control())) as (output, calls):
        monkeypatch.setattr(output, "write", lambda _: 0)
        assert bootstrap.main() == 2
    with context(monkeypatch, b"") as (output, calls):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(bootstrap.__file__, run_name="__main__")
    assert stopped.value.code == 2 and output.getvalue() == b""


def test_protocol_progress_is_bounded_and_partial_io_supported():
    class Partial(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 1))

        def write(self, value):
            return super().write(value[:1])

    assert bootstrap._exact(Partial(b"test"), 4) == b"test"
    stream = Partial()
    bootstrap._send(stream, "AWS4A_EXECUTION_DISABLED")
    assert result(stream)["reason"] == "AWS4A_EXECUTION_DISABLED"
    for value in (0, None):
        with pytest.raises(ValueError):
            bootstrap._send(
                SimpleNamespace(write=lambda block, value=value: value), "AWS4A_EXECUTION_DISABLED"
            )
