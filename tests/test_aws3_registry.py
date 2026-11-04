"""Named AWS3 facades execute only fixed project workers behind AWS2 containment."""

import inspect
import json
import threading

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_readiness.registry import (
    run_archive_collection,
    run_archive_verification,
    run_posture_inspection,
)
from cloudsecops_live.integrations.aws_readiness.requests import (
    CollectionRequest,
    PostureRequest,
    VerificationRequest,
)
from tests.aws3_helpers import archive_metadata, posture_metadata


def test_facade_module_does_not_export_low_level_worker_controls():
    from cloudsecops_live.integrations.aws_readiness import registry

    assert set(registry.__all__) == {
        "run_posture_inspection",
        "run_archive_collection",
        "run_archive_verification",
    }
    assert not hasattr(registry, "WorkerRef")
    assert not hasattr(registry, "run_isolated")


@pytest.mark.parametrize(
    "facade,make_request,purpose",
    [
        (
            run_posture_inspection,
            lambda: PostureRequest.from_metadata(posture_metadata()),
            "posture",
        ),
        (
            run_archive_collection,
            lambda: CollectionRequest.from_metadata(archive_metadata()),
            "collector",
        ),
        (
            run_archive_verification,
            lambda: VerificationRequest.from_metadata(archive_metadata("verifier")),
            "verifier",
        ),
    ],
)
def test_named_facades_run_real_owned_children(facade, make_request, purpose):
    assert set(inspect.signature(facade).parameters) == {"request", "timeout", "cancel"}
    result = facade(make_request(), timeout=5)
    assert result.status == "ok"
    assert result.tree_terminated
    payload = json.loads(result.response)
    assert payload["purpose"] == purpose
    assert payload["authenticated"] is False
    assert payload["trusted_findings_available"] is False
    assert payload["closure_available"] is False


def test_facade_rejects_raw_and_wrong_purpose_requests_before_dispatch():
    for value in (
        posture_metadata(),
        object(),
        CollectionRequest.from_metadata(archive_metadata()),
    ):
        with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
            run_posture_inspection(value)
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        run_archive_collection(PostureRequest.from_metadata(posture_metadata()))
    with pytest.raises(EvidenceError, match="AWS3_REQUEST"):
        run_archive_verification(CollectionRequest.from_metadata(archive_metadata()))


def test_cancellation_and_stalled_fixture_have_no_success_payload():
    cancel = threading.Event()
    cancel.set()
    result = run_posture_inspection(PostureRequest.from_metadata(posture_metadata()), cancel=cancel)
    assert result.status == "cancelled" and result.response is None
    data = posture_metadata()
    data["tape"][0]["fault"] = "stall"
    result = run_posture_inspection(PostureRequest.from_metadata(data), timeout=0.8)
    assert result.status == "deadline" and result.response is None and result.tree_terminated
