"""One fixed disabled posture entrypoint; no worker or credential selection."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.requests import PostureRequest
from cloudsecops_live.integrations.aws_runner.process import IsolatedResult, _run_with_bootstrap
from cloudsecops_live.integrations.aws_runner.process import WorkerRef as _WorkerRef

__all__ = ["run_posture_network"]
_POSTURE = _WorkerRef(
    "cloudsecops_live.integrations.aws_posture.worker",
    "execute",
    Path(__file__).resolve().parents[3],
)


def run_posture_network(
    request: PostureRequest, *, timeout: float = 5.0, cancel: threading.Event | None = None
) -> IsolatedResult:
    if type(request) is not PostureRequest:
        raise EvidenceError("AWS4A_REQUEST")
    # The frame contains references only. No owner file, credential, network
    # endpoint, module, operation or enabling flag can be supplied in the data.
    raw = json.dumps(request.to_metadata(), separators=(",", ":")).encode()
    return _run_with_bootstrap(
        _POSTURE, raw, timeout=timeout, cancel=cancel, bootstrap_name="posture"
    )
