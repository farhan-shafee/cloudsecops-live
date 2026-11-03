"""Literal contract expectations; no SDK, AWS credentials or network transport."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CallerIdentity,
    CollectionLimits,
    MemoryLedger,
    ObjectBody,
    ObjectVersion,
    RetryableReadError,
    VersionPage,
    collect,
    require_authenticated,
)
from tests.aws_helpers import archive, event, scope

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class FakeTransport:
    """Explicit in-memory service observations, never a real AWS client."""

    def __init__(self):
        self.scope = scope()
        self.data = archive([event(f"aaaaaaaa-bbbb-4ccc-8ddd-{i:012x}", i * 30) for i in range(3)])
        self.ref = ObjectVersion(
            self.scope.bucket,
            self.scope.log_prefix + "2026/01/01/log.json.gz",
            "v-one",
            len(self.data),
            NOW,
            False,
            True,
        )
        self.identity = CallerIdentity(
            self.scope.account,
            self.scope.region,
            f"arn:aws:sts::{self.scope.account}:assumed-role/OfflineCollector/offline",
            self.scope.role_id + ":offline",
            NOW,
            NOW + timedelta(minutes=5),
        )
        self.pages = {None: VersionPage(True, (self.ref,), False, None)}
        self.calls = []
        self.failures = 0
        self.version = "v-one"

    def caller_identity(self):
        self.calls.append("identity")
        return self.identity

    def list_versions(self, expected, prefix, marker):
        assert expected == self.scope
        assert prefix == self.scope.log_prefix
        self.calls.append(("list", marker))
        if self.failures:
            self.failures -= 1
            raise RetryableReadError()
        return self.pages[marker]

    def head_current(self, ref):
        self.calls.append("head")
        return self.version

    def get_object(self, ref, max_bytes):
        self.calls.append("get")
        assert max_bytes > 0
        return ObjectBody(ref, self.scope.account, BytesIO(self.data))


def run(fake=None, ledger=None, **kwargs):
    fake = fake or FakeTransport()
    return collect(
        fake, fake.scope, ledger or MemoryLedger(), "poll-one", clock=lambda: NOW, **kwargs
    )


def test_complete_poll_is_untrusted_and_checkpoint_replay_has_no_transport_effect():
    fake, ledger = FakeTransport(), MemoryLedger()
    result = run(fake, ledger)
    assert result.to_public_dict()["source_kind"] == "aws_shaped_unverified"
    assert result.authenticated is False
    assert result.unique_event_count == 3
    assert ledger.generation == 1
    before = list(fake.calls)
    assert run(fake, ledger) == result
    assert fake.calls == before
    with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
        require_authenticated(result)


@pytest.mark.parametrize(
    "field,value",
    [
        ("account", "2" * 12),
        ("region", "us-west-2"),
        ("arn", "arn:aws:sts::" + "1" * 12 + ":assumed-role/Other/offline"),
        ("user_id", "WRONG:offline"),
        ("expires_at", NOW),
        ("observed_at", NOW - timedelta(minutes=2)),
        ("observed_at", NOW + timedelta(seconds=1)),
    ],
)
def test_bad_identity_stops_before_source_access(field, value):
    fake = FakeTransport()
    fake.identity = replace(fake.identity, **{field: value})
    with pytest.raises(EvidenceError):
        run(fake)
    assert fake.calls == ["identity"]


def test_pagination_requires_both_progressing_service_markers():
    fake = FakeTransport()
    marker = (fake.ref.key, "v-one")
    fake.pages = {
        None: VersionPage(True, (), True, marker),
        marker: VersionPage(True, (fake.ref,), False, None),
    }
    assert run(fake).unique_event_count == 3
    assert ("list", marker) in fake.calls
    for bad in [
        VersionPage(False, (), False, None),
        VersionPage(True, (), True, None),
        VersionPage(True, (), False, marker),
        {"Error": "not empty success"},
    ]:
        fake = FakeTransport()
        fake.pages[None] = bad
        ledger = MemoryLedger()
        with pytest.raises(EvidenceError):
            run(fake, ledger)
        assert ledger.generation == 0


def test_repeated_markers_and_page_limits_do_not_commit():
    fake = FakeTransport()
    marker = (fake.ref.key, "v-one")
    fake.pages = {
        None: VersionPage(True, (), True, marker),
        marker: VersionPage(True, (), True, marker),
    }
    with pytest.raises(EvidenceError, match="PAGINATION"):
        run(fake)
    with pytest.raises(EvidenceError, match="LISTING_LIMIT"):
        run(fake, limits=CollectionLimits(max_pages=1))


@pytest.mark.parametrize(
    "change",
    [
        {"bucket": "wrong-bucket"},
        {"key": "arbitrary/log.json.gz"},
        {"version_id": "null"},
        {"size": 0},
        {"size": True},
        {"is_delete_marker": True},
        {"is_latest": False},
    ],
)
def test_wrong_source_or_unsupported_version_history_is_permanent(change):
    fake = FakeTransport()
    fake.ref = replace(fake.ref, **change)
    fake.pages[None] = VersionPage(True, (fake.ref,), False, None)
    ledger = MemoryLedger()
    with pytest.raises(EvidenceError):
        run(fake, ledger)
    assert ledger.generation == 0
    assert "get" not in fake.calls


def test_version_change_and_declared_size_mismatch_rollback():
    for version, data in [("v-two", b"version change"), ("v-one", b"short")]:
        fake, ledger = FakeTransport(), MemoryLedger()
        fake.version, fake.data = version, data
        with pytest.raises(EvidenceError):
            run(fake, ledger)
        assert ledger.generation == 0


def test_bounded_retry_and_unexpected_transport_failures():
    fake = FakeTransport()
    fake.failures = 2
    assert run(fake).unique_event_count == 3
    fake = FakeTransport()
    fake.failures = 3
    ledger = MemoryLedger()
    with pytest.raises(EvidenceError, match="TRANSPORT_RETRY_EXHAUSTED"):
        run(fake, ledger)
    assert ledger.generation == 0


def test_interruption_before_commit_and_lost_ack_after_commit():
    class Before(MemoryLedger):
        def commit(self, *args):
            raise InterruptedError("private payload must not escape")

    fake, ledger = FakeTransport(), Before()
    with pytest.raises(EvidenceError, match="CHECKPOINT_COMMIT_FAILED"):
        run(fake, ledger)
    assert ledger.generation == 0

    class After(MemoryLedger):
        def commit(self, *args):
            super().commit(*args)
            raise InterruptedError("lost acknowledgment")

    fake, ledger = FakeTransport(), After()
    with pytest.raises(EvidenceError, match="CHECKPOINT_COMMIT_FAILED"):
        run(fake, ledger)
    assert ledger.generation == 1
    assert run(fake, ledger).unique_event_count == 3
