"""The only sink is local; its receipt is not a searchable SIEM alert."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from cloudsecops_live.outbox import deliver_once
from cloudsecops_live.worker import work_once
from tests.integration.support import add, explode_fault, one


@pytest.mark.parametrize(
    "point,receipt",
    [
        ("after_outbox_claim", False),
        ("before_sink_commit", False),
        ("after_sink_commit", True),
        ("before_outbox_ack", True),
        ("after_outbox_ack", True),
    ],
)
def test_outbox_fault_replay_has_one_logical_sink_effect(db, point, receipt):
    add(db, [0, 20, 40])
    work_once(db)
    with pytest.raises(RuntimeError, match="controlled_test_fault"):
        deliver_once(db, fault=explode_fault(point))
    assert one(db, "SELECT count(*) AS n FROM csl.offline_sink")["n"] == int(receipt)
    with db.connect() as conn:
        conn.execute(
            "UPDATE csl.outbox SET lease_until=clock_timestamp()-interval '1 second' "
            "WHERE status='attempted'"
        )
    result = deliver_once(db)
    assert result["status"] == ("idle" if point == "after_outbox_ack" else "locally_acknowledged")
    assert one(db, "SELECT count(*) AS n FROM csl.offline_sink")["n"] == 1
    saved = one(db, "SELECT status,payload FROM csl.outbox")
    assert saved["status"] == "locally_acknowledged"
    assert saved["payload"]["delivery_class"] == "offline_test_only"
    assert deliver_once(db)["status"] == "idle"


def test_simultaneous_sink_delivery_is_idempotent(db):
    add(db, [0, 20, 40])
    work_once(db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: deliver_once(db), range(2)))
    assert sorted(result["status"] for result in results) == ["idle", "locally_acknowledged"]
    assert one(db, "SELECT count(*) AS n FROM csl.offline_sink")["n"] == 1


@pytest.mark.parametrize("terminal", ["retryable", "failed", "expired"])
def test_final_attempt_reconciles_committed_sink_receipt(db, terminal):
    add(db, [0, 20, 40])
    work_once(db)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            deliver_once(db, fault=explode_fault("before_sink_commit"))
    with pytest.raises(RuntimeError):
        deliver_once(db, fault=explode_fault("after_sink_commit"))
    with db.connect() as conn:
        if terminal == "expired":
            conn.execute(
                "UPDATE csl.outbox SET status='attempted',claim_token='old',"
                "lease_until=clock_timestamp()-interval '1 second'"
            )
        elif terminal == "retryable":
            conn.execute("UPDATE csl.outbox SET status='retryable'")
    assert deliver_once(db)["status"] == "locally_acknowledged"
    assert one(db, "SELECT count(*) AS n FROM csl.offline_sink")["n"] == 1
    assert one(db, "SELECT attempts,status FROM csl.outbox") == {
        "attempts": 3,
        "status": "locally_acknowledged",
    }
