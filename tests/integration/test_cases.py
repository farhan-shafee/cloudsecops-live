"""Hand-authored expectations: no detector is used as its own oracle."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier

import pytest

from cloudsecops_live.cases import revise_case
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.storage import ingest, verify_store
from cloudsecops_live.worker import work_once
from tests.helpers import archive, event
from tests.integration.support import add, current, one, rows


def test_late_extension_keeps_case_identity_and_appends_immutable_revision(db):
    add(db, [0, 20, 40])
    assert work_once(db)["status"] == "succeeded"
    initial = current(db)
    assert len(initial) == 1
    assert initial[0]["payload"]["evidence_event_ids"] == ["e0", "e20", "e40"]
    assert initial[0]["current_revision"] == 1
    add(db, [10], "late")
    assert one(db, "SELECT status FROM csl.cases")["status"] == "pending"
    assert work_once(db)["status"] == "succeeded"
    revised = current(db)
    assert len(revised) == 1
    assert revised[0]["case_id"] == initial[0]["case_id"]
    assert revised[0]["current_revision"] == 2
    assert revised[0]["payload"]["evidence_event_ids"] == ["e0", "e10", "e20", "e40"]
    assert revised[0]["fingerprint"] != initial[0]["fingerprint"]
    assert (
        one(db, "SELECT payload FROM csl.case_revisions WHERE revision=1")["payload"]
        == initial[0]["payload"]
    )
    assert verify_store(db)["verified"] is True


def test_late_bridge_supersedes_both_parents_and_retains_lineage(db):
    add(db, [40, 0, 20])
    work_once(db)
    add(db, [140, 100, 120], "separate")
    work_once(db)
    parents = current(db)
    assert len(parents) == 2
    assert {tuple(row["payload"]["evidence_event_ids"]) for row in parents} == {
        ("e0", "e20", "e40"),
        ("e100", "e120", "e140"),
    }
    add(db, [70], "bridge")
    assert {row["status"] for row in rows(db, "SELECT status FROM csl.cases")} == {"pending"}
    work_once(db)
    merged = current(db)
    assert len(merged) == 1
    assert merged[0]["case_id"] not in {row["case_id"] for row in parents}
    assert merged[0]["payload"]["evidence_event_ids"] == [
        "e0",
        "e20",
        "e40",
        "e70",
        "e100",
        "e120",
        "e140",
    ]
    assert {
        row["case_id"]
        for row in rows(db, "SELECT case_id FROM csl.cases WHERE status='superseded'")
    } == {row["case_id"] for row in parents}
    links = rows(db, "SELECT parent_case_id,child_case_id FROM csl.case_lineage")
    assert {(row["parent_case_id"], row["child_case_id"]) for row in links} == {
        (row["case_id"], merged[0]["case_id"]) for row in parents
    }


def test_unknown_source_field_conflict_immediately_invalidates_current_case(db):
    add(db, [0, 20, 40])
    work_once(db)
    changed = event("e20", 20)
    changed["unknownFutureField"] = {"value": "changed"}
    result = ingest(db, [("synthetic/conflict.gz", archive([changed]))], checkpoint="conflict")
    assert result["conflicting"] == 1
    assert current(db) == []
    assert one(db, "SELECT status FROM csl.cases")["status"] == "pending"
    work_once(db)
    assert current(db) == []
    assert one(db, "SELECT status FROM csl.cases")["status"] == "withdrawn"


def test_optimistic_revision_conflict_does_not_append_history(db):
    add(db, [0, 20, 40])
    work_once(db)
    snapshot = current(db)[0]
    revision = one(db, "SELECT * FROM csl.case_revisions")
    with db.connect() as conn:
        next_revision = revise_case(
            conn,
            snapshot["case_id"],
            1,
            deepcopy(snapshot["payload"]),
            revision["finding_id"],
            revision["generation"],
        )
    assert next_revision == 2
    with pytest.raises(EvidenceError, match="STALE_REVISION"), db.connect() as conn:
        revise_case(
            conn,
            snapshot["case_id"],
            1,
            snapshot["payload"],
            revision["finding_id"],
            revision["generation"],
        )
    assert one(db, "SELECT count(*) AS n FROM csl.case_revisions")["n"] == 2


def test_case_payload_remains_explicitly_unreviewed_and_synthetic(db):
    add(db, [0, 20, 40])
    work_once(db)
    payload = current(db)[0]["payload"]
    assert payload["source_kind"] == "synthetic"
    assert payload["authenticated"] is False
    assert payload["rule_id"] == "AWS-LAB-001"
    assert payload["rule_version"] == "1.0"
    assert payload["attack"]["technique_id"] == "T1580"
    assert len(payload["evidence"]) == 3
    assert len(payload["limitations"]) >= 3
    assert payload["unreviewed"] is True


def test_simultaneous_revisions_have_one_compare_and_swap_winner(db):
    add(db, [0, 20, 40])
    work_once(db)
    revision = one(db, "SELECT * FROM csl.case_revisions")
    start = Barrier(2)

    def revise():
        start.wait(timeout=10)
        try:
            with db.connect() as conn:
                revise_case(
                    conn,
                    revision["case_id"],
                    1,
                    revision["payload"],
                    revision["finding_id"],
                    revision["generation"],
                )
            return "committed"
        except EvidenceError as exc:
            assert exc.code == "STALE_REVISION"
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: revise(), range(2)))
    assert sorted(results) == ["committed", "stale"]
    assert one(db, "SELECT count(*) AS n FROM csl.case_revisions")["n"] == 2
