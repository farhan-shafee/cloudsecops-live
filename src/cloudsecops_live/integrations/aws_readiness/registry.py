"""Named fixed-worker facades. Request data can never select executable code."""

from __future__ import annotations

import threading
from pathlib import Path

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_readiness.requests import (
    CollectionRequest,
    PostureRequest,
    VerificationRequest,
    encode,
)
from cloudsecops_live.integrations.aws_runner.process import (
    IsolatedResult,
)
from cloudsecops_live.integrations.aws_runner.process import WorkerRef as _WorkerRef
from cloudsecops_live.integrations.aws_runner.process import run_isolated as _run_isolated

__all__ = ["run_posture_inspection", "run_archive_collection", "run_archive_verification"]

# Paths derive solely from the installed project package. No request-supplied
# registry, import root, worker identifier or alternate callback is supported.
_ROOT = Path(__file__).resolve().parents[3]
_POSTURE = _WorkerRef(
    "cloudsecops_live.integrations.aws_readiness.workers", "inspect_posture", _ROOT
)
_COLLECTOR = _WorkerRef(
    "cloudsecops_live.integrations.aws_readiness.workers", "collect_archive", _ROOT
)
_VERIFIER = _WorkerRef(
    "cloudsecops_live.integrations.aws_readiness.workers", "verify_archive", _ROOT
)


def run_posture_inspection(
    request: PostureRequest, *, timeout: float = 5.0, cancel: threading.Event | None = None
) -> IsolatedResult:
    if type(request) is not PostureRequest:
        raise EvidenceError("AWS3_REQUEST")
    return _run_isolated(_POSTURE, encode(request.to_metadata()), timeout=timeout, cancel=cancel)


def run_archive_collection(
    request: CollectionRequest, *, timeout: float = 5.0, cancel: threading.Event | None = None
) -> IsolatedResult:
    if type(request) is not CollectionRequest:
        raise EvidenceError("AWS3_REQUEST")
    return _run_isolated(_COLLECTOR, encode(request.to_metadata()), timeout=timeout, cancel=cancel)


def run_archive_verification(
    request: VerificationRequest, *, timeout: float = 5.0, cancel: threading.Event | None = None
) -> IsolatedResult:
    if type(request) is not VerificationRequest:
        raise EvidenceError("AWS3_REQUEST")
    return _run_isolated(_VERIFIER, encode(request.to_metadata()), timeout=timeout, cancel=cancel)
