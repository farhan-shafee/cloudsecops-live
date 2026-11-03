"""Independent fake-only attempts to cross the offline evidence boundary."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from io import BytesIO

import pytest

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_bytes
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CollectionLimits,
    MemoryLedger,
    ObjectBody,
    RetryableReadError,
    VersionPage,
    collect,
    require_authenticated,
)
from cloudsecops_live.integrations.aws_cloudtrail.validation import (
    CheckOutcome,
    ControlledValidation,
    DigestMember,
    assess_digest,
)
from tests.aws_helpers import archive, event
from tests.test_aws_collection import NOW, FakeTransport


def poll(fake, ledger=None, *, clock=None, checkpoint="adversarial", **kwargs):
    return collect(
        fake,
        fake.scope,
        MemoryLedger() if ledger is None else ledger,
        checkpoint,
        clock=(lambda: NOW) if clock is None else clock,
        **kwargs,
    )


class ManyObjects(FakeTransport):
    def __init__(self, count=2):
        super().__init__()
        self.refs = tuple(
            replace(self.ref, key=self.scope.log_prefix + f"2026/01/01/{i:03}.json.gz")
            for i in range(count)
        )
        self.current = {ref.key: ref.version_id for ref in self.refs}
        self.pages = {None: VersionPage(True, self.refs, False, None)}

    def head_current(self, ref):
        self.calls.append(("head", ref.key))
        return self.current[ref.key]

    def get_object(self, ref, max_bytes):
        self.calls.append(("get", ref.key, max_bytes))
        return ObjectBody(ref, self.scope.account, BytesIO(self.data))


@pytest.mark.parametrize(
    "marker",
    [
        ("foreign-account/private.json.gz", "v-one"),
        ("offline-lab/AWSLogs/" + "2" * 12 + "/CloudTrail/us-east-1/a.json.gz", "v-one"),
        ("offline-lab/AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1/../a.json.gz", "v-one"),
        ("offline-lab/AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1//a.json.gz", "v-one"),
        ("offline-lab/AWSLogs/" + "1" * 12 + "/CloudTrail/us-east-1/a\x7f.json.gz", "v-one"),
    ],
)
def test_forged_pagination_key_is_rejected_before_forwarding(marker):
    fake, ledger = FakeTransport(), MemoryLedger()
    fake.pages = {
        None: VersionPage(True, (), True, marker),
        marker: VersionPage(True, (), False, None),
    }
    with pytest.raises(EvidenceError, match="AWS_PAGINATION"):
        poll(fake, ledger)
    assert fake.calls == ["identity", ("list", None)]
    assert ledger.generation == 0


def test_backwards_key_marker_cannot_skip_or_revisit_an_earlier_key_range():
    fake, ledger = FakeTransport(), MemoryLedger()
    later = (fake.scope.log_prefix + "z.json.gz", "opaque-version-z")
    earlier = (fake.scope.log_prefix + "a.json.gz", "opaque-version-a")
    fake.pages = {
        None: VersionPage(True, (), True, later),
        later: VersionPage(True, (), True, earlier),
        earlier: VersionPage(True, (), False, None),
    }
    with pytest.raises(EvidenceError, match="AWS_PAGINATION"):
        poll(fake, ledger)
    assert ("list", earlier) not in fake.calls
    assert ledger.generation == 0


def test_page_cannot_return_keys_before_its_request_marker():
    fake, ledger = FakeTransport(), MemoryLedger()
    marker = (fake.scope.log_prefix + "m.json.gz", "opaque-version")
    earlier = replace(fake.ref, key=fake.scope.log_prefix + "a.json.gz")
    fake.pages = {
        None: VersionPage(True, (), True, marker),
        marker: VersionPage(True, (earlier,), False, None),
    }
    with pytest.raises(EvidenceError, match="AWS_PAGINATION"):
        poll(fake, ledger)
    assert "get" not in fake.calls
    assert ledger.generation == 0


def test_next_marker_cannot_precede_the_largest_key_in_its_page():
    fake, ledger = FakeTransport(), MemoryLedger()
    prior = (fake.scope.log_prefix + "a.json.gz", "opaque-first-version")
    regressed = (fake.scope.log_prefix + "m.json.gz", "opaque-next-version")
    later = replace(fake.ref, key=fake.scope.log_prefix + "z.json.gz")
    fake.pages = {
        None: VersionPage(True, (), True, prior),
        prior: VersionPage(True, (later,), True, regressed),
        regressed: VersionPage(True, (), False, None),
    }
    with pytest.raises(EvidenceError, match="AWS_PAGINATION"):
        poll(fake, ledger)
    assert ("list", regressed) not in fake.calls
    assert "get" not in fake.calls
    assert ledger.generation == 0


@pytest.mark.parametrize(
    "marker",
    [
        None,
        (),
        ("only-one",),
        ("a", "b", "c"),
        ["a", "b"],
        ("", "v"),
        ("a", ""),
        ("a\x00", "v"),
        ("a", "v\n"),
        ("a" * 1025, "v"),
        ("a", "v" * 1025),
    ],
)
def test_malformed_pagination_never_becomes_an_empty_success(marker):
    fake, ledger = FakeTransport(), MemoryLedger()
    fake.pages[None] = VersionPage(True, (), True, marker)
    with pytest.raises(EvidenceError, match="AWS_PAGINATION"):
        poll(fake, ledger)
    assert ledger.generation == 0
    assert "get" not in fake.calls


@pytest.mark.parametrize(
    "page",
    [
        {"ResponseMetadata": {"HTTPStatusCode": 403}, "Versions": []},
        {"ResponseMetadata": {"HTTPStatusCode": 500}, "Versions": []},
        VersionPage(False, (), False, None),
        VersionPage(1, (), False, None),
        VersionPage(True, (), 0, None),
        VersionPage(True, [], False, None),
    ],
)
def test_http_errors_and_malformed_service_pages_fail_without_retry_or_commit(page):
    fake, ledger = FakeTransport(), MemoryLedger()
    fake.pages[None] = page
    with pytest.raises(EvidenceError, match="AWS_LISTING_RESPONSE"):
        poll(fake, ledger)
    assert fake.calls == ["identity", ("list", None)]
    assert ledger.generation == 0


def test_total_object_count_is_bounded_across_pages_before_any_get():
    fake, ledger = ManyObjects(3), MemoryLedger()
    marker = (fake.refs[0].key, fake.refs[0].version_id)
    fake.pages = {
        None: VersionPage(True, fake.refs[:1], True, marker),
        marker: VersionPage(True, fake.refs[1:], False, None),
    }
    with pytest.raises(EvidenceError, match="AWS_LISTING_LIMIT"):
        poll(fake, ledger, limits=CollectionLimits(max_objects=2))
    assert not any(isinstance(call, tuple) and call[0] == "get" for call in fake.calls)
    assert ledger.generation == 0


def test_page_limit_is_checked_before_requesting_an_excess_page():
    fake, ledger = FakeTransport(), MemoryLedger()
    marker = (fake.ref.key, fake.ref.version_id)
    fake.pages[None] = VersionPage(True, (), True, marker)
    with pytest.raises(EvidenceError, match="AWS_LISTING_LIMIT"):
        poll(fake, ledger, limits=CollectionLimits(max_pages=1))
    assert fake.calls == ["identity", ("list", None)]
    assert ledger.generation == 0


@pytest.mark.parametrize("stage", ["list", "head", "get"])
def test_identity_expiring_between_stages_blocks_later_access_and_checkpoint(stage):
    now = [NOW]

    class Expiring(FakeTransport):
        def list_versions(self, *args):
            result = super().list_versions(*args)
            if stage == "list":
                now[0] += timedelta(minutes=6)
            return result

        def head_current(self, ref):
            result = super().head_current(ref)
            if stage == "head":
                now[0] += timedelta(minutes=6)
            return result

        def get_object(self, *args):
            result = super().get_object(*args)
            if stage == "get":
                now[0] += timedelta(minutes=6)
            return result

    fake, ledger = Expiring(), MemoryLedger()
    with pytest.raises(EvidenceError, match="AWS_IDENTITY_EXPIRED"):
        poll(fake, ledger, clock=lambda: now[0])
    assert ledger.generation == 0
    assert fake.calls.count("head") == (0 if stage == "list" else 1)
    assert fake.calls.count("get") == (1 if stage == "get" else 0)


def test_previous_object_changing_during_later_retrieval_prevents_final_commit():
    class ChangedAfterRetrieval(ManyObjects):
        def get_object(self, ref, max_bytes):
            result = super().get_object(ref, max_bytes)
            if ref == self.refs[-1]:
                self.current[self.refs[0].key] = "replacement-version"
            return result

    fake, ledger = ChangedAfterRetrieval(), MemoryLedger()
    with pytest.raises(EvidenceError, match="AWS_SOURCE_CHANGED"):
        poll(fake, ledger)
    assert ledger.generation == 0


def test_legal_short_stream_reads_collect_complete_archive_with_bounded_requests():
    fake, ledger = FakeTransport(), MemoryLedger()

    class Chunked(BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.requests = []

        def read(self, amount):
            self.requests.append(amount)
            return super().read(min(amount, 17))

    stream = Chunked(fake.data)
    fake.get_object = lambda ref, max_bytes: ObjectBody(ref, fake.scope.account, stream)
    result = poll(fake, ledger)
    assert result.unique_event_count == 3
    assert result.authenticated is False
    assert ledger.generation == 1
    assert stream.closed
    assert len(stream.requests) > 1
    assert stream.requests[0] == fake.ref.size + 1
    assert all(0 < amount <= fake.ref.size + 1 for amount in stream.requests)


@pytest.mark.parametrize("mode", ["read_raises", "close_raises", "oversized", "not_bytes"])
def test_object_stream_failure_is_bounded_closed_and_never_commits(mode):
    fake, ledger = FakeTransport(), MemoryLedger()

    class Stream:
        calls = []
        closed = False

        def read(self, amount):
            self.calls.append(amount)
            if mode == "read_raises":
                raise OSError("private object payload")
            if mode == "oversized":
                return fake.data + b"extra"
            if mode == "not_bytes":
                return bytearray(fake.data)
            return fake.data if len(self.calls) == 1 else b""

        def close(self):
            self.closed = True
            if mode == "close_raises":
                raise OSError("private bucket and key")

    stream = Stream()
    fake.get_object = lambda ref, max_bytes: ObjectBody(ref, fake.scope.account, stream)
    with pytest.raises(EvidenceError) as caught:
        poll(fake, ledger)
    assert str(caught.value) in {"AWS_OBJECT_READ", "AWS_OBJECT_SIZE"}
    assert stream.calls[0] == fake.ref.size + 1
    assert all(0 < amount <= fake.ref.size + 1 for amount in stream.calls)
    assert stream.closed
    assert ledger.generation == 0


def test_wrong_owner_still_closes_stream_without_reading_or_commit():
    fake, ledger = FakeTransport(), MemoryLedger()

    class Stream(BytesIO):
        def read(self, amount):
            raise AssertionError("wrong-owner body must not be read")

    stream = Stream(fake.data)
    fake.get_object = lambda ref, max_bytes: ObjectBody(ref, "2" * 12, stream)
    with pytest.raises(EvidenceError, match="AWS_OBJECT_RESPONSE"):
        poll(fake, ledger)
    assert stream.closed
    assert ledger.generation == 0


def test_changed_checkpoint_scope_and_limits_are_rejected_before_transport():
    fake, ledger = FakeTransport(), MemoryLedger()
    result = poll(fake, ledger)
    fake.calls.clear()
    changed = replace(fake.scope, bucket="another-offline-bucket")
    with pytest.raises(EvidenceError, match="AWS_CHECKPOINT_CONFLICT"):
        collect(fake, changed, ledger, "adversarial", clock=lambda: NOW)
    with pytest.raises(EvidenceError, match="AWS_CHECKPOINT_CONFLICT"):
        poll(fake, ledger, limits=CollectionLimits(max_objects=1))
    assert poll(fake, ledger) is result
    assert fake.calls == []
    assert ledger.generation == 1


def test_concurrent_checkpoint_commit_loses_cas_without_partial_outer_entry():
    ledger = MemoryLedger()

    class Concurrent(FakeTransport):
        def get_object(self, *args):
            poll(FakeTransport(), ledger, checkpoint="concurrent-writer")
            return super().get_object(*args)

    fake = Concurrent()
    with pytest.raises(EvidenceError, match="AWS_CHECKPOINT_STALE"):
        poll(fake, ledger)
    assert ledger.generation == 1
    clean = FakeTransport()
    assert poll(clean, ledger).unique_event_count == 3
    assert ledger.generation == 2


def test_identical_duplicates_are_counted_and_unknown_field_variants_conflict():
    original = event()
    variant = deepcopy(original)
    variant["unrecognizedFutureField"] = {"nested": [False, None, "kept"]}
    fake = FakeTransport()
    fake.data = archive([original, deepcopy(original), variant, deepcopy(variant)])
    fake.ref = replace(fake.ref, size=len(fake.data))
    fake.pages = {None: VersionPage(True, (fake.ref,), False, None)}
    result = poll(fake)
    assert result.unique_event_count == 1
    assert result.duplicate_event_count == 2
    assert result.conflicts == ((fake.scope.account, fake.scope.region, original["eventID"]),)
    assert result.to_public_dict()["state"] == "conflicting"
    assert result.authenticated is False


def test_valid_looking_receipt_and_forged_attributes_cannot_open_authentication_gate():
    fake = FakeTransport()
    batch = poll(fake)
    obj = batch.objects[0]
    member = DigestMember(
        obj.reference.bucket, obj.reference.key, obj.reference.version_id, obj.log.content_sha256
    )
    receipt = ControlledValidation(
        "aws-cli/fake-only",
        0,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        (member,),
        True,
        True,
    )
    assessment = assess_digest(obj, receipt)
    assert assessment.consistency_passed
    assert assessment.authenticated is False
    assert assessment.state == "pending_source_authentication"
    assert batch.to_public_dict()["trusted_findings_available"] is False
    for forged in (batch, obj.log, assessment):
        object.__setattr__(forged, "authenticated", True)
        with pytest.raises(EvidenceError, match="AWS_AUTHENTICATION_UNAVAILABLE"):
            require_authenticated(forged)
    with pytest.raises(EvidenceError, match="INVALID_FIXTURE_ENVELOPE"):
        parse_bytes(fake.data)


def test_unclassified_service_exception_is_sanitized_and_never_retried():
    class ServiceFailure(FakeTransport):
        attempts = 0

        def list_versions(self, *args):
            self.attempts += 1
            raise RuntimeError("HTTP 403: private ARN and object key")

    fake, ledger = ServiceFailure(), MemoryLedger()
    with pytest.raises(EvidenceError, match="^AWS_TRANSPORT_FAILURE$") as caught:
        poll(fake, ledger)
    assert caught.value.__cause__ is None
    assert fake.attempts == 1
    assert ledger.generation == 0


def test_classified_read_retries_recheck_identity_before_retry():
    now = [NOW]

    class ExpiringRetry(FakeTransport):
        attempts = 0

        def list_versions(self, *args):
            self.attempts += 1
            now[0] += timedelta(minutes=6)
            raise RetryableReadError()

    fake, ledger = ExpiringRetry(), MemoryLedger()
    with pytest.raises(EvidenceError, match="AWS_IDENTITY_EXPIRED"):
        poll(fake, ledger, clock=lambda: now[0])
    assert fake.attempts == 1
    assert ledger.generation == 0
