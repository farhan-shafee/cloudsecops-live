"""Hard limits and malformed protocol objects reject before checkpoint publication."""

from dataclasses import replace
from datetime import datetime
from io import BytesIO

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CollectionLimits,
    MemoryLedger,
    ObjectBody,
    VersionPage,
    collect,
)
from cloudsecops_live.integrations.aws_cloudtrail.validation import assess_digest
from tests.test_aws_collection import NOW, FakeTransport, run
from tests.test_aws_validation import fixture


@pytest.mark.parametrize(
    "field,bad",
    [
        ("max_pages", 0),
        ("max_pages", 257),
        ("max_objects", 65),
        ("max_archive_bytes", 10 * 1024 * 1024 + 1),
        ("max_content_bytes", 100 * 1024 * 1024 + 1),
        ("attempts", 4),
        ("attempts", True),
    ],
)
def test_configuration_hard_ceiling_and_strict_numeric_types(field, bad):
    with pytest.raises(EvidenceError, match="AWS_COLLECTION_LIMITS"):
        CollectionLimits(**{field: bad})


@pytest.mark.parametrize("checkpoint", ["", "x" * 65, "../private", None])
def test_unsafe_checkpoint_labels_never_access_transport(checkpoint):
    fake = FakeTransport()
    with pytest.raises(EvidenceError, match="AWS_CHECKPOINT_REQUIRED"):
        collect(fake, fake.scope, MemoryLedger(), checkpoint, clock=lambda: NOW)
    assert fake.calls == []


def test_scope_and_limits_are_explicit_typed_contracts():
    fake = FakeTransport()
    with pytest.raises(EvidenceError, match="AWS_SCOPE_REQUIRED"):
        collect(fake, None, MemoryLedger(), "poll", clock=lambda: NOW)
    with pytest.raises(EvidenceError, match="AWS_SCOPE_REQUIRED"):
        run(fake, limits={"max_objects": 1})


@pytest.mark.parametrize("identity", [None, {}, "verified"])
def test_missing_or_untyped_identity_is_not_a_successful_read(identity):
    fake = FakeTransport()
    fake.identity = identity
    with pytest.raises(EvidenceError, match="AWS_IDENTITY_REQUIRED"):
        run(fake)
    assert fake.calls == ["identity"]


@pytest.mark.parametrize(
    "changes",
    [
        {"user_id": None},
        {"user_id": "no-session"},
        {"expires_at": datetime(2026, 1, 1)},
    ],
)
def test_malformed_identity_fields_are_permanent(changes):
    fake = FakeTransport()
    fake.identity = replace(fake.identity, **changes)
    with pytest.raises(EvidenceError):
        run(fake)
    assert fake.calls == ["identity"]


def test_page_cardinality_and_reference_metadata_conflicts_are_rejected():
    fake = FakeTransport()
    fake.pages[None] = VersionPage(True, (fake.ref, fake.ref), False, None)
    with pytest.raises(EvidenceError, match="AWS_LISTING_LIMIT"):
        run(fake, limits=CollectionLimits(max_objects=1))
    for variant in [
        replace(fake.ref, size=fake.ref.size + 1),
        replace(fake.ref, version_id="second-version"),
    ]:
        fake.pages[None] = VersionPage(True, (fake.ref, variant), False, None)
        with pytest.raises(EvidenceError, match="CONFLICT|HISTORY"):
            run(fake)
    fake.pages[None] = VersionPage(True, (None,), False, None)
    with pytest.raises(EvidenceError, match="AWS_SOURCE_METADATA"):
        run(fake)


def test_batch_compressed_and_expanded_limits_rollback_all_objects():
    fake = FakeTransport()
    second = replace(fake.ref, key=fake.ref.key.replace("log.json", "second.json"))
    fake.pages[None] = VersionPage(True, (fake.ref, second), False, None)
    for limits in [
        CollectionLimits(max_archive_bytes=fake.ref.size),
        CollectionLimits(max_content_bytes=1),
    ]:
        ledger = MemoryLedger()
        with pytest.raises(EvidenceError, match="LIMIT"):
            run(fake, ledger, limits=limits)
        assert ledger.generation == 0


def test_untyped_body_is_not_an_empty_accepted_archive():
    fake = FakeTransport()
    fake.get_object = lambda *args: {"error": "private"}
    with pytest.raises(EvidenceError, match="AWS_OBJECT_RESPONSE"):
        run(fake)


def test_pathologically_small_stream_chunks_have_a_finite_read_budget():
    fake = FakeTransport()
    fake.data = b"x" * 2048
    fake.ref = replace(fake.ref, size=len(fake.data))
    fake.pages[None] = VersionPage(True, (fake.ref,), False, None)

    class SlowStream(BytesIO):
        calls = 0

        def read(self, amount):
            self.calls += 1
            return super().read(min(amount, 1))

    stream = SlowStream(fake.data)
    fake.get_object = lambda *args: ObjectBody(fake.ref, fake.scope.account, stream)
    ledger = MemoryLedger()
    with pytest.raises(EvidenceError, match="AWS_OBJECT_READ_LIMIT"):
        run(fake, ledger)
    assert stream.calls == 1024
    assert stream.closed
    assert ledger.generation == 0


def test_clock_reversal_rejects_source_receipt():
    fake = FakeTransport()
    times = [NOW]

    def get_object(ref, max_bytes):
        from datetime import timedelta

        times[0] = NOW - timedelta(seconds=1)
        return ObjectBody(ref, fake.scope.account, BytesIO(fake.data))

    fake.get_object = get_object
    # Identity freshness is rechecked first; both clock movement and scope remain fail-closed.
    with pytest.raises(EvidenceError, match="AWS_IDENTITY_EXPIRED|AWS_SOURCE_CHANGED"):
        collect(fake, fake.scope, MemoryLedger(), "clock", clock=lambda: times[0])


@pytest.mark.parametrize(
    "changes",
    [
        {"exit_code": True},
        {"members": []},
        {"members": (None,)},
        {"signature": "valid"},
        {"complete": "true"},
    ],
)
def test_receipt_types_are_not_truthy_validation_flags(changes):
    obj, receipt = fixture()
    with pytest.raises(EvidenceError, match="AWS_VALIDATION_RECEIPT"):
        assess_digest(obj, replace(receipt, **changes))


def test_forged_stored_hash_is_not_even_consistent_controlled_evidence():
    obj, receipt = fixture()
    changed = replace(obj, log=replace(obj.log, content_sha256="a" * 64))
    result = assess_digest(changed, receipt)
    assert result.reason == "AWS_LOCAL_HASH_MISMATCH"
    assert result.authenticated is False


def test_same_checkpoint_race_reuses_identical_content_despite_different_read_times():
    from datetime import timedelta

    ledger = MemoryLedger()
    retained = []

    class Concurrent(FakeTransport):
        def get_object(self, ref, max_bytes):
            retained.append(run(FakeTransport(), ledger))
            return super().get_object(ref, max_bytes)

    fake = Concurrent()
    result = collect(fake, fake.scope, ledger, "poll-one", clock=lambda: NOW + timedelta(seconds=1))
    assert result is retained[0]
    assert ledger.generation == 1


def test_parser_upgrade_cannot_redefine_a_retained_checkpoint(monkeypatch):
    from cloudsecops_live.integrations.aws_cloudtrail import collection

    fake, ledger = FakeTransport(), MemoryLedger()
    run(fake, ledger)
    fake.calls.clear()
    monkeypatch.setattr(collection, "PARSER_VERSION", "future-parser-version")
    with pytest.raises(EvidenceError, match="AWS_CHECKPOINT_CONFLICT"):
        run(fake, ledger)
    assert fake.calls == []
