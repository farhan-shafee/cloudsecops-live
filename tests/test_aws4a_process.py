"""Independent disabled-entrypoint and separate process/egress boundaries."""

import hashlib
import json
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.contracts import PostureRequest
from cloudsecops_live.integrations.aws_posture.registry import run_posture_network
from cloudsecops_live.integrations.aws_runner.process import WorkerRef, run_isolated
from tests.test_aws_runner_faults import fault_server

ROOT = Path(__file__).resolve().parents[1]


def request():
    return PostureRequest("a" * 64, "b" * 64)


def test_fixed_posture_bootstrap_is_disabled_and_cannot_return_success():
    result = run_posture_network(request(), timeout=5)
    assert result.status == "failed"
    assert result.reason == "AWS4A_EXECUTION_DISABLED"
    assert result.response is None and result.tree_terminated
    assert result.to_public_dict()["authenticated"] is False


@pytest.mark.parametrize("value", [None, {}, {"enabled": True}, "live", object()])
def test_public_entrypoint_has_no_json_or_live_toggle_escape(value):
    with pytest.raises(EvidenceError):
        run_posture_network(value)


def test_disabled_entrypoint_supports_pre_cancellation_without_credentials():
    cancel = threading.Event()
    cancel.set()
    result = run_posture_network(request(), cancel=cancel)
    assert result.status == "cancelled" and result.response is None and result.tree_terminated


def test_new_bootstrap_has_no_executable_argv_worker_or_secret_channel():
    bootstrap = ROOT / "src/cloudsecops_live/integrations/aws_posture/bootstrap.py"
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(bootstrap), "live", "arbitrary.module"],
        input=b"",
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stdout == b"" and completed.stderr == b""


def test_separate_guard_rejects_egress_and_python_child_escape_in_owned_process():
    worker = WorkerRef("tests.aws4a_process_fixtures", "guard_probe", ROOT)
    result = run_isolated(worker, b"{}", timeout=5)
    assert result.status == "ok" and result.tree_terminated
    output = json.loads(result.response)
    assert output == {"denied": 9, "authenticated": False}


def test_old_offline_guard_and_facades_keep_their_original_code():
    # Independent LF-byte fingerprints at reviewed base 1d9e978. Literal values
    # also work in shallow PR checkouts where parent commit objects are absent.
    expected = {
        "src/cloudsecops_live/integrations/aws_runner/bootstrap.py": (
            "196ffc16db5440ab79ed009205bf5793cb"  # pragma: allowlist secret - public SHA256
            "db21d2d52cb07d8284f0d95343eff1"  # pragma: allowlist secret - public SHA256
        ),
        "src/cloudsecops_live/integrations/aws_runner/network.py": (
            "2fcc5cebc5f3b222d820646008ce262137"  # pragma: allowlist secret - public SHA256
            "04d0f0e58bbc100874a4e95420b534"  # pragma: allowlist secret - public SHA256
        ),
        "src/cloudsecops_live/integrations/aws_readiness/registry.py": (
            "e5b898f366a2b22b881a2100d08b5ddd9"  # pragma: allowlist secret - public SHA256
            "81d87e19599a3dbc5f3a9f45352e788"  # pragma: allowlist secret - public SHA256
        ),
    }
    for path, digest in expected.items():
        assert (
            hashlib.sha256((ROOT / path).read_bytes().replace(b"\r\n", b"\n")).hexdigest() == digest
        )


@pytest.mark.parametrize("phase", ["tls", "headers", "chunks", "body"])
def test_new_wire_path_stalls_are_bounded_by_the_shared_independent_watchdog(phase):
    with fault_server(phase) as (port, accepted):
        result = run_isolated(
            WorkerRef("tests.aws4a_process_fixtures", "wire_fault", ROOT),
            json.dumps({"phase": phase, "port": port}).encode(),
            timeout=2.5,
        )
        assert accepted.is_set(), "fault must reach its actual socket phase"
        assert result.status == "deadline" and result.response is None
        assert result.tree_terminated and result.elapsed_seconds < 2.5


@contextmanager
def good_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"valid")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(1)
        assert not thread.is_alive()


def test_same_wire_fixture_accepts_a_complete_bounded_benign_reply():
    with good_server() as port:
        result = run_isolated(
            WorkerRef("tests.aws4a_process_fixtures", "wire_fault", ROOT),
            json.dumps({"phase": "valid", "port": port, "expected_bytes": 5}).encode(),
            timeout=5,
        )
    assert result.status == "ok" and result.tree_terminated
    assert json.loads(result.response) == {
        "bytes": 5,
        "authenticated": False,
        "trusted_findings_available": False,
        "closure_available": False,
    }


@pytest.mark.parametrize("phase", ["malformed_chunk", "interrupted", "oversized"])
def test_hostile_local_wire_fault_never_produces_success(phase):
    with fault_server(phase) as (port, accepted):
        result = run_isolated(
            WorkerRef("tests.aws4a_process_fixtures", "wire_fault", ROOT),
            json.dumps({"phase": phase, "port": port}).encode(),
            timeout=5,
        )
        assert accepted.is_set()
        assert result.status == "failed" and result.response is None and result.tree_terminated


@pytest.mark.parametrize("phase", ["dns", "retry", "close", "crash"])
def test_uncooperative_faults_and_crash_keep_negative_cleanup_receipts(phase):
    result = run_isolated(
        WorkerRef("tests.aws4a_process_fixtures", "wire_fault", ROOT),
        json.dumps({"phase": phase}).encode(),
        timeout=2.5,
    )
    assert result.status == ("failed" if phase == "crash" else "deadline")
    assert result.response is None and result.tree_terminated


def test_supervisor_rejects_an_unrecognized_bootstrap_instead_of_accepting_a_path():
    from cloudsecops_live.integrations.aws_runner.process import _run_with_bootstrap

    with pytest.raises(EvidenceError, match="AWS_RUNNER_CONFIG"):
        _run_with_bootstrap(
            WorkerRef("tests.aws4a_process_fixtures", "guard_probe", ROOT),
            b"{}",
            bootstrap_name="untrusted.py",
        )
