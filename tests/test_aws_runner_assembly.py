"""Process + actual guarded adapter + fake clients, without AWS connectivity."""

import json
from pathlib import Path

import pytest

from cloudsecops_live.integrations.aws_runner.process import WorkerRef, run_isolated

ROOT = Path(__file__).resolve().parents[1]


def run(request):
    return run_isolated(
        WorkerRef("tests.runner_sdk", "inspect_fixture", ROOT),
        json.dumps(request).encode(),
        timeout=5,
    )


def test_prepared_process_and_sdk_share_guards_without_trust_promotion():
    result = run({})
    assert result.status == "ok"
    assert result.tree_terminated
    payload = json.loads(result.response)
    assert payload["authenticated"] is False
    assert payload["budget"]["calls"] == 8
    assert payload["budget"]["operations"] == 8
    assert payload["budget"]["trusted_findings_available"] is False


@pytest.mark.parametrize("payload", [{"calls": 1}, {"substitute": True}, {"mutate": True}])
def test_security_failure_has_no_successful_payload_or_evidence_receipt(payload):
    result = run(payload)
    assert result.status == "failed"
    assert result.tree_terminated
    assert result.response is None
    receipt = result.to_public_dict()
    assert receipt["authenticated"] is False
    assert receipt["closure_available"] is False
