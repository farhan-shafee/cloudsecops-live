"""Disposable PostgreSQL rejects posture observations without changing case authority."""

import gzip
import json
import socket

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import ingest
from tests.integration.test_nul_quarantine import (
    assert_only_quarantine_changed,
    populate_demo,
    snapshot,
)
from tests.test_aws4a_engine import make, run


@pytest.mark.parametrize("populated", [False, True])
@pytest.mark.parametrize("forged", [False, True])
def test_posture_observation_cannot_acquire_synthetic_workflow_authority(
    db, populated, forged, monkeypatch
):
    def denied(*args, **kwargs):
        pytest.fail("posture authority test must never contact AWS")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    if populated:
        populate_demo(db)
    observation = run(*make())
    assert observation["execution_state"] == "disabled"
    assert observation["authenticated"] is observation["closure_available"] is False
    if forged:
        observation.update(
            authenticated=True, trusted_findings_available=True, closure_available=True
        )
    data = gzip.compress(json.dumps(observation).encode(), mtime=0)
    before = snapshot(db)
    with pytest.raises(EvidenceError, match="INVALID_FIXTURE_ENVELOPE"):
        ingest(db, [("posture-observation.json.gz", data)], checkpoint="aws4a-blocked")
    # Explicit table inventory includes recommendations, reviews, verification,
    # closure, history and audit. Only the bounded quarantine record may change.
    assert_only_quarantine_changed(db, before, "aws4a-blocked", reason="INVALID_FIXTURE_ENVELOPE")
