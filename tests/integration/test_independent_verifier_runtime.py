"""Restricted original retrieval and independently calculated real SQL receipts."""

from __future__ import annotations

import secrets

from tests.integration.support import one
from tests.integration.workflow_support import (  # noqa: F401
    workflow,
    workspace,
    workspace_password_hash,
)


def test_real_verifier_receipt_and_acknowledgment_retry_are_exactly_once(workflow):  # noqa: F811
    recommendation = workflow.recommend()
    workflow.review(recommendation)
    run_id = secrets.token_hex(16)
    first = workflow.verify(recommendation, run_id)
    second = workflow.verify(recommendation, run_id)
    assert first == second
    assert first["result"] == "verified"
    assert first["scope"] == "offline_synthetic_only"
    assert first["source_kind"] == "synthetic"
    assert first["authenticated"] is False
    assert one(workflow.db, "SELECT count(*) AS n FROM csl.ws_verifications")["n"] == 1


def test_real_proof_ignores_production_normalization_and_detection_decisions(workflow, monkeypatch):  # noqa: F811
    import cloudsecops_live.detection as detection
    import cloudsecops_live.ingestion as ingestion

    recommendation = workflow.recommend()
    workflow.review(recommendation)

    def forbidden(*args, **kwargs):
        raise AssertionError("production detector used as proof")

    for name in ("detect", "_components", "_reasons", "_finding"):
        monkeypatch.setattr(detection, name, forbidden)
    monkeypatch.setattr(ingestion, "_session", lambda *args: (None, "forged_decision"))
    monkeypatch.setattr(ingestion, "_canonical", lambda *args: "{}")
    assert workflow.verify(recommendation)["result"] == "verified"


def test_private_reference_only_cli_emits_receipt_without_evidence_or_credentials(
    workflow,  # noqa: F811
    tmp_path,
    capsys,
):  # noqa: F811
    from cloudsecops_live.verifier_cli import main
    from cloudsecops_live.workspace_config import write_private_json

    recommendation = workflow.recommend()
    workflow.review(recommendation)
    private = tmp_path / "verifier.json"
    write_private_json(private, workflow.verifier_account)
    assert (
        main(
            [
                "--config",
                str(private),
                "--recommendation-id",
                recommendation["recommendation_id"],
                "--version",
                "1",
            ]
        )
        == 0
    )
    output = capsys.readouterr()
    assert '"verification_id"' in output.out
    assert '"result": "verified"' in output.out
    assert "SYNTHETIC_KEY_" not in output.out
    assert workflow.verifier_account["dsn"] not in output.out
    assert not output.err
