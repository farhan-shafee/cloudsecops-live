"""Real offline process isolation, bounded shutdown and owned-tree checks."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def runner():
    from cloudsecops_live.integrations.aws_runner import process

    return process


def invoke(name, request=None, **kwargs):
    module = runner()
    return module.run_isolated(
        module.WorkerRef("tests.runner_fixtures", name, ROOT),
        json.dumps(request).encode(),
        **kwargs,
    )


def alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = wintypes.DWORD()
        try:
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        status = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return status.rsplit(")", 1)[1].split()[0] != "Z"


def test_real_worker_success_is_a_distinct_process():
    result = invoke("echo", {"hello": "offline"}, timeout=3)
    assert result.status == "ok"
    response = json.loads(result.response)
    assert response["echo"] == {"hello": "offline"}
    assert response["pid"] != os.getpid()
    assert result.tree_terminated is True
    assert result.elapsed_seconds < 3


@pytest.mark.parametrize("name", ["hang", "tree"])
def test_deadline_covers_worker_and_owned_descendants(name, tmp_path):
    marker = tmp_path / "pids"
    sentinel = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
    started = time.monotonic()
    try:
        result = invoke(name, {"marker": str(marker)}, timeout=1.5)
        elapsed = time.monotonic() - started
        assert result.status == "deadline"
        assert result.tree_terminated is True
        assert elapsed < 1.8
        assert sentinel.poll() is None
        if name == "tree":
            assert marker.exists(), "test must exercise actual child and grandchild creation"
            assert all(not alive(int(pid)) for pid in marker.read_text().split())
    finally:
        sentinel.kill()
        sentinel.wait(timeout=3)


def test_success_cleans_lingering_descendants(tmp_path):
    marker = tmp_path / "pids"
    result = invoke("tree", {"marker": str(marker), "success": True}, timeout=3)
    assert result.status == "ok"
    assert result.tree_terminated is True
    assert marker.exists()
    assert all(not alive(int(pid)) for pid in marker.read_text().split())


def test_cancel_has_bounded_shutdown():
    cancel = threading.Event()
    timer = threading.Timer(0.3, cancel.set)
    timer.start()
    try:
        result = invoke("hang", timeout=3, cancel=cancel)
    finally:
        timer.cancel()
    assert result.status == "cancelled"
    assert result.tree_terminated is True
    assert result.elapsed_seconds < 1.5


def test_precancel_never_launches(monkeypatch):
    module = runner()
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("launched"))
    assert invoke("echo", cancel=cancel).status == "cancelled"


@pytest.mark.parametrize("name", ["fail", "crash", "non_json"])
def test_worker_failure_is_fixed_and_private(name, capsys):
    result = invoke(name, timeout=3)
    assert result.status == "failed"
    assert result.response is None
    assert "private-marker" not in repr(result)
    assert result.tree_terminated is True
    assert "private-marker" not in str(capsys.readouterr())


def test_response_bytes_are_bounded():
    result = invoke("oversized", timeout=3, max_response_bytes=1024)
    assert result.status == "failed"
    assert result.response is None
    assert result.reason == "AWS_RUNNER_RESPONSE_LIMIT"


def test_child_stdout_and_stderr_cannot_become_protocol(capsys):
    result = invoke("noisy", timeout=3)
    assert result.status == "ok"
    assert json.loads(result.response) == {"safe": True}
    assert "private-marker" not in str(capsys.readouterr())


def test_worker_environment_has_no_ambient_credentials_or_proxy(monkeypatch):
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "HTTPS_PROXY"):
        monkeypatch.setenv(key, "private-marker")
    response = json.loads(invoke("environment", timeout=3).response)
    assert response["python_isolated"] == 1
    assert not {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "HTTPS_PROXY"} & set(
        response["keys"]
    )


def test_real_child_guard_denies_dns_hostnames_and_remote_network():
    result = invoke("network_denial", timeout=3)
    assert result.status == "ok"
    assert json.loads(result.response) == ["dns", "remote", "hostname"]


@pytest.mark.parametrize("timeout", [0, -1, 31, float("nan"), float("inf"), True, 10**1000])
def test_invalid_budget_is_rejected_before_launch(timeout):
    from cloudsecops_live.errors import EvidenceError

    with pytest.raises(EvidenceError, match="AWS_RUNNER_CONFIG"):
        invoke("echo", timeout=timeout)


@pytest.mark.parametrize(
    "field,value", [("module", None), ("module", 7), ("function", None), ("function", 7)]
)
def test_wrong_typed_trusted_entrypoint_is_a_sanitized_configuration_failure(field, value):
    from cloudsecops_live.errors import EvidenceError

    module = runner()
    values = {"module": "tests.runner_fixtures", "function": "echo", "import_root": ROOT}
    values[field] = value
    with pytest.raises(EvidenceError, match="AWS_RUNNER_CONFIG"):
        module.run_isolated(module.WorkerRef(**values), b"{}")


def test_fragmented_frame_header_and_body_are_received():
    module = runner()

    class Fragmented(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 1))

    source = Fragmented(b"\x00\x00\x00\x02{}")
    received, ready = [None], threading.Event()
    module._read_frame(source, 1024, received, ready)
    assert received == [b"{}"]
    assert ready.is_set()


def test_control_partial_writes_are_completed():
    module = runner()

    class Partial(io.BytesIO):
        def write(self, value):
            return super().write(value[:1])

    destination = Partial()
    module._write_control(destination, b"{}")
    assert destination.getvalue() == b"G\x00\x00\x00\x02{}"


def test_hung_bootstrap_is_inside_deadline(monkeypatch):
    module = runner()
    original = module.subprocess.Popen

    def hung(command, **kwargs):
        return original([sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", hung)
    result = invoke("echo", timeout=0.6)
    assert result.status == "deadline"
    assert result.tree_terminated is True
    assert result.elapsed_seconds < 0.8


def test_late_launch_stays_gated_and_is_eventually_reaped(monkeypatch):
    module = runner()
    original = module.subprocess.Popen
    created = []

    def late(command, **kwargs):
        time.sleep(0.6)
        child = original(command, **kwargs)
        created.append(child)
        return child

    monkeypatch.setattr(module.subprocess, "Popen", late)
    result = invoke("echo", timeout=0.3)
    assert result.status == "deadline"
    assert result.response is None
    assert result.tree_terminated is False
    assert result.elapsed_seconds < 0.5
    until = time.monotonic() + 3
    while (not created or created[0].returncode is None) and time.monotonic() < until:
        time.sleep(0.01)
    assert created and created[0].returncode is not None


@pytest.mark.parametrize(
    "wire",
    [
        b"\x00\x00\x00\x01!",
        b"\x7f\xff\xff\xff",
        b"\x00\x00\x00\x02{",
        len(b'{"status":"ok","response":null}').to_bytes(4, "big")
        + b'{"status":"ok","response":null}trailing',
    ],
)
def test_malformed_child_ipc_never_becomes_success(monkeypatch, wire):
    module = runner()
    original = module.subprocess.Popen

    def malformed(command, **kwargs):
        script = "import os,sys; sys.stdin.buffer.read(1); os.write(1," + repr(wire) + ")"
        return original([sys.executable, "-I", "-S", "-c", script], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", malformed)
    result = invoke("echo", timeout=1)
    assert result.status == "failed"
    assert result.response is None
    assert result.tree_terminated is True


def test_containment_failure_never_releases_operation_gate(monkeypatch):
    module = runner()

    def broken(child):
        raise OSError("private-marker")

    monkeypatch.setattr(module, "ProcessTree", broken)
    result = invoke("hang", timeout=1)
    assert result.status == "failed"
    assert result.reason == "AWS_RUNNER_CONTAINMENT"
    assert result.tree_terminated is True


def test_delayed_gate_writer_cannot_dispatch_after_caller_deadline(monkeypatch, tmp_path):
    module = runner()
    original_start = threading.Thread.start
    writer_finished = threading.Event()

    def delayed_start(thread):
        if thread._target is module._write_control:
            time.sleep(0.6)
            try:
                return original_start(thread)
            finally:
                writer_finished.set()
        return original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", delayed_start)
    marker = tmp_path / "operation"
    result = invoke("mark", {"marker": str(marker)}, timeout=0.3)
    assert result.status == "deadline"
    assert result.response is None
    assert writer_finished.wait(2)
    time.sleep(0.1)
    assert not marker.exists()


def test_gate_writer_checks_stop_before_any_byte():
    module = runner()
    stopped = threading.Event()
    stopped.set()
    destination = io.BytesIO()
    module._write_control(destination, b"{}", stopped, None, time.monotonic() + 1)
    assert destination.getvalue() == b""


def test_success_payload_is_private_in_repr_and_public_receipt():
    result = invoke("echo", {"private": "private-marker"}, timeout=3)
    assert result.status == "ok"
    assert "private-marker" in result.response.decode()
    assert "private-marker" not in repr(result)
    assert "private-marker" not in json.dumps(result.to_public_dict())


def test_linux_unreadable_existing_group_cannot_be_reported_empty(monkeypatch):
    from cloudsecops_live.integrations.aws_runner.containment import ProcessTree

    tree = object.__new__(ProcessTree)
    tree.process = SimpleNamespace(pid=123)
    monkeypatch.setattr(os, "killpg", lambda group, signal: None, raising=False)
    monkeypatch.setattr(os, "getpgid", lambda pid: 123, raising=False)
    monkeypatch.setattr(os, "listdir", lambda path: ["123"])

    def unreadable(*args, **kwargs):
        raise PermissionError("private-marker")

    monkeypatch.setattr("builtins.open", unreadable)
    assert tree._linux_live_members(time.monotonic() + 1) is True


@pytest.mark.parametrize("failure", ["unreadable", "malformed"])
def test_linux_readable_zombie_cannot_hide_an_unknown_owned_member(monkeypatch, failure):
    from cloudsecops_live.integrations.aws_runner.containment import ProcessTree

    tree = object.__new__(ProcessTree)
    tree.process = SimpleNamespace(pid=123)
    queries = []
    monkeypatch.setattr(
        os, "killpg", lambda group, signal: queries.append((group, signal)), raising=False
    )
    monkeypatch.setattr(os, "getpgid", lambda pid: 123, raising=False)
    monkeypatch.setattr(os, "listdir", lambda path: ["123", "456"])

    def membership(path, **kwargs):
        if path == "/proc/123/stat":
            return io.StringIO("123 (owned zombie) Z 1 123 123")
        if failure == "unreadable":
            raise PermissionError("private-marker")
        return io.StringIO("malformed-stat")

    monkeypatch.setattr("builtins.open", membership)
    assert tree._linux_live_members(time.monotonic() + 1) is True
    assert queries == [(123, 0)], "membership inspection must not send termination signals"


@pytest.mark.parametrize("remaining", ["unrelated", "vanished"])
def test_linux_zombie_cleanup_tolerates_unrelated_or_vanished_pids(monkeypatch, remaining):
    from cloudsecops_live.integrations.aws_runner.containment import ProcessTree

    tree = object.__new__(ProcessTree)
    tree.process = SimpleNamespace(pid=123)
    monkeypatch.setattr(os, "killpg", lambda group, signal: None, raising=False)
    monkeypatch.setattr(os, "listdir", lambda path: ["123", "456"])

    def group(pid):
        if pid == 123:
            return 123
        if remaining == "vanished":
            raise ProcessLookupError()
        return 999

    monkeypatch.setattr(os, "getpgid", group, raising=False)

    def membership(path, **kwargs):
        if path == "/proc/123/stat":
            return io.StringIO("123 (owned zombie) Z 1 123 123")
        pytest.fail("unrelated or vanished PID must not require a readable stat file")

    monkeypatch.setattr("builtins.open", membership)
    assert tree._linux_live_members(time.monotonic() + 1) is False


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b'{"a":1,"a":2}',
        b"NaN",
        b"Infinity",
        b"[" * 33 + b"0" + b"]" * 33,
        b"[" + b"0," * 100_000 + b"0]",
    ],
)
def test_hostile_request_json_is_rejected_before_launch(monkeypatch, raw):
    from cloudsecops_live.errors import EvidenceError

    module = runner()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("launched"))
    with pytest.raises(EvidenceError, match="AWS_RUNNER_REQUEST"):
        module.run_isolated(module.WorkerRef("tests.runner_fixtures", "echo", ROOT), raw)


def test_oversized_trusted_control_is_rejected_before_launch(monkeypatch):
    from cloudsecops_live.errors import EvidenceError

    module = runner()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *a, **k: pytest.fail("launched"))
    root = ROOT / ("x" * (module.MAX_REQUEST_BYTES + 65536))
    with pytest.raises(EvidenceError, match="AWS_RUNNER_REQUEST"):
        module.run_isolated(module.WorkerRef("tests.runner_fixtures", "echo", root), b"{}")


def test_failed_process_creation_is_sanitized_and_has_no_tree(monkeypatch):
    module = runner()

    def denied(*args, **kwargs):
        raise OSError("private-marker")

    monkeypatch.setattr(module.subprocess, "Popen", denied)
    result = invoke("echo")
    assert result.status == "failed"
    assert result.tree_terminated
    assert "private-marker" not in repr(result)


def test_cancellation_during_startup_never_dispatches(monkeypatch, tmp_path):
    module = runner()
    original = module.subprocess.Popen
    cancel = threading.Event()

    def cancelled_start(*args, **kwargs):
        child = original(*args, **kwargs)
        cancel.set()
        return child

    monkeypatch.setattr(module.subprocess, "Popen", cancelled_start)
    marker = tmp_path / "operation"
    result = invoke("mark", {"marker": str(marker)}, timeout=2, cancel=cancel)
    assert result.status == "cancelled"
    assert result.tree_terminated
    assert not marker.exists()


@pytest.mark.parametrize("behavior", ["cancel", "exception", "late"])
def test_cleanup_acknowledgment_can_never_restore_success(monkeypatch, behavior):
    module = runner()
    original = module.ProcessTree
    cancel = threading.Event()
    clock_offset = [0.0]
    real_clock = time.monotonic
    monkeypatch.setattr(
        module, "time", SimpleNamespace(monotonic=lambda: real_clock() + clock_offset[0])
    )

    class Cleanup:
        def __init__(self, child):
            self.tree = original(child)

        def terminate(self, deadline):
            cleaned = self.tree.terminate(deadline)
            if behavior == "cancel":
                cancel.set()
            elif behavior == "exception":
                raise OSError("private-marker")
            else:
                clock_offset[0] = 5
            return cleaned

        def close(self):
            self.tree.close()

    monkeypatch.setattr(module, "ProcessTree", Cleanup)
    result = invoke("echo", {"private": "private-marker"}, timeout=2, cancel=cancel)
    expected = {"cancel": "cancelled", "exception": "failed", "late": "deadline"}
    assert result.status == expected[behavior]
    assert result.response is None
    assert "private-marker" not in repr(result)
    assert result.tree_terminated is (behavior != "exception")


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {"status": "forged", "authenticated": True},
        {"status": "failed", "reason": "private-marker"},
    ],
)
def test_well_formed_json_with_invalid_protocol_envelope_is_rejected(monkeypatch, envelope):
    module = runner()
    original = module.subprocess.Popen
    encoded = json.dumps(envelope).encode()
    wire = len(encoded).to_bytes(4, "big") + encoded

    def malformed(command, **kwargs):
        script = "import os,sys; sys.stdin.buffer.read(1); os.write(1," + repr(wire) + ")"
        return original([sys.executable, "-I", "-S", "-c", script], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", malformed)
    result = invoke("echo", timeout=1)
    assert result.status == "failed"
    assert result.reason == "AWS_RUNNER_PROTOCOL"
    assert result.tree_terminated
    assert "private-marker" not in repr(result)


def test_payload_limit_is_rechecked_independently_of_worker_envelope(monkeypatch):
    module = runner()
    original = module.subprocess.Popen
    encoded = json.dumps({"status": "ok", "response": "x" * 1025}).encode()
    wire = len(encoded).to_bytes(4, "big") + encoded

    def forged(command, **kwargs):
        script = "import os,sys; sys.stdin.buffer.read(1); os.write(1," + repr(wire) + ")"
        return original([sys.executable, "-I", "-S", "-c", script], **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", forged)
    result = invoke("echo", timeout=1, max_response_bytes=1024)
    assert result.status == "failed"
    assert result.reason == "AWS_RUNNER_RESPONSE_LIMIT"
    assert result.response is None
    assert result.tree_terminated


def test_closed_protocol_reader_notifies_watchdog():
    module = runner()
    source = io.BytesIO()
    source.close()
    received, ready = [None], threading.Event()
    module._read_frame(source, 1024, received, ready)
    assert received == [None]
    assert ready.is_set()


@pytest.mark.parametrize("write_result", [None, 0])
def test_closed_or_nonprogressing_control_writer_stops(write_result):
    module = runner()
    module._write_control(SimpleNamespace(write=lambda block: write_result), b"{}")
    destination = io.BytesIO()
    destination.close()
    module._write_control(destination, b"{}")


@pytest.mark.parametrize("condition", ["cancelled", "expired"])
def test_gate_writer_rechecks_cancellation_and_deadline(condition):
    module = runner()
    cancelled = threading.Event()
    if condition == "cancelled":
        cancelled.set()
    destination = io.BytesIO()
    cutoff = time.monotonic() + (1 if condition == "cancelled" else -1)
    module._write_control(destination, b"{}", None, cancelled, cutoff)
    assert destination.getvalue() == b""


def test_missing_optional_windows_environment_never_discovers_credentials(monkeypatch):
    module = runner()
    monkeypatch.setattr(module, "os", SimpleNamespace(environ={}, devnull=os.devnull))
    environment = module._environment()
    assert environment == {
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "BOTO_CONFIG": os.devnull,
    }
