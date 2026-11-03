"""Separately executed verifier using one private, case-scoped SQL identity."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudsecops_live.database import Database
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.independent_verifier import (
    CHECKER_DEFINITION_SHA256,
    CHECKER_POLICY,
    CHECKER_VERSION,
    source_digest,
    verify_snapshot,
)
from cloudsecops_live.workflow_store import VerifierStore
from cloudsecops_live.workspace_tls import private_file


@dataclass(frozen=True)
class VerifierConfig:
    db: Database = field(repr=False)
    verifier_id: str
    case_id: str


def _hex(value: Any, size: int) -> bool:
    return (
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value) is not None
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("invalid_verifier_config")
        value[key] = item
    return value


def load_config(path: Path) -> VerifierConfig:
    value = json.loads(private_file(path, max_bytes=65536), object_pairs_hook=_pairs)
    if (
        not isinstance(value, dict)
        or set(value) != {"dsn", "verifier_id", "case_id"}
        or not isinstance(value["dsn"], str)
        or not _hex(value["verifier_id"], 32)
        or not _hex(value["case_id"], 64)
    ):
        raise ValueError("invalid_verifier_config")
    return VerifierConfig(Database(value["dsn"]), value["verifier_id"], value["case_id"])


def _store(db: Database) -> VerifierStore:
    return VerifierStore(db)


def run_verification(
    config: VerifierConfig, recommendation_id: str, version: int, run_id: str | None = None
) -> dict[str, Any]:
    """Submit only the independently calculated report; stale SQL finalization raises.

    The SQL adapter validates the actual LOGIN's catalog and scoped grant. The
    private file's identifiers are consistency checks, never authority labels.
    A retained run reference permits acknowledgment-loss recovery without a second
    receipt. Archive bytes are fetched individually and never written to disk.
    """
    if (
        not _hex(recommendation_id, 64)
        or type(version) is not int
        or not 1 <= version <= 64
        or (run_id is not None and not _hex(run_id, 32))
        or not _hex(config.verifier_id, 32)
        or not _hex(config.case_id, 64)
    ):
        raise EvidenceError("VERIFIER_REFERENCE")
    store = _store(config.db)
    identity = store.identity()
    if (
        identity.get("verifier_id") != config.verifier_id
        or identity.get("case_id") != config.case_id
    ):
        raise EvidenceError("VERIFIER_IDENTITY")
    if (
        identity.get("checker_policy") != CHECKER_POLICY
        or identity.get("checker_version") != CHECKER_VERSION
        or identity.get("checker_source_digest") != source_digest()
    ):
        raise EvidenceError("VERIFIER_CHECKER")
    bundle = store.begin(recommendation_id, version, run_id)
    if bundle.get("case_id") != config.case_id:
        raise EvidenceError("VERIFIER_CASE")
    if "retained_receipt" in bundle:
        receipt = bundle["retained_receipt"]
        if (
            not isinstance(receipt, dict)
            or receipt.get("case_id") != config.case_id
            or receipt.get("verifier_id") != config.verifier_id
            or receipt.get("request_id") != bundle["request_id"]
            or receipt.get("source_kind") != "synthetic"
            or receipt.get("authenticated") is not False
            or receipt.get("scope") != "offline_synthetic_only"
            or receipt.get("result") not in {"verified", "contradicted", "inconclusive"}
            or receipt.get("checker_version") != CHECKER_VERSION
            or receipt.get("checker_digest") != CHECKER_DEFINITION_SHA256
            or receipt.get("source_digest") != source_digest()
        ):
            raise EvidenceError("VERIFIER_RECEIPT")
        return receipt
    report = verify_snapshot(bundle, lambda raw_id: store.original(bundle["request_id"], raw_id))
    return store.finish(bundle["request_id"], report)
