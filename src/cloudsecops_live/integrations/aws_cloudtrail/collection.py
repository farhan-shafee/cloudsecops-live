"""Offline acquisition contracts. No SDK, credential discovery or network implementation."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from hashlib import sha256
from threading import Lock
from typing import BinaryIO, Literal, Protocol

from cloudsecops_live.contracts import PARSER_VERSION as SYNTAX_PARSER_VERSION
from cloudsecops_live.contracts import Limits
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.models import (
    CANONICALIZATION_VERSION,
    PARSER_VERSION,
    SCHEMA_VERSION,
    AwsLog,
    AwsScope,
)
from cloudsecops_live.integrations.aws_cloudtrail.parsing import parse_aws_shaped

COLLECTOR_VERSION = "aws-offline-collection/1"
Marker = tuple[str, str]


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    account: str
    region: str
    arn: str
    user_id: str
    observed_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ObjectVersion:
    bucket: str
    key: str
    version_id: str
    size: int
    last_modified: datetime
    is_delete_marker: bool = False
    is_latest: bool = True


@dataclass(frozen=True, slots=True)
class VersionPage:
    ok: bool
    versions: tuple[ObjectVersion, ...]
    truncated: bool
    next_marker: Marker | None


@dataclass(frozen=True, slots=True)
class ObjectBody:
    reference: ObjectVersion
    owner_account: str
    stream: BinaryIO


class RetryableReadError(Exception):
    """Only a classified transient transport failure may consume bounded retries."""


class ReadTransport(Protocol):
    """Future implementation must bound network time/body allocation before returning.

    STS does not return a region or expiry: those observations must come from the
    explicitly configured regional client and short-session credential provider.
    No concrete AWS implementation exists in this milestone.
    """

    def caller_identity(self) -> CallerIdentity: ...
    def list_versions(
        self, expected: AwsScope, prefix: str, marker: Marker | None
    ) -> VersionPage: ...
    def head_current(self, ref: ObjectVersion) -> str: ...
    def get_object(self, ref: ObjectVersion, max_bytes: int) -> ObjectBody: ...


@dataclass(frozen=True, slots=True)
class CollectionLimits:
    max_pages: int = 32
    max_objects: int = 16
    max_archive_bytes: int = 10 * 1024 * 1024
    max_content_bytes: int = 50 * 1024 * 1024
    attempts: int = 3

    def __post_init__(self) -> None:
        values = (
            self.max_pages,
            self.max_objects,
            self.max_archive_bytes,
            self.max_content_bytes,
            self.attempts,
        )
        if any(
            type(v) is not int or not 1 <= v <= ceiling
            for v, ceiling in zip(
                values, (256, 64, 10 * 1024 * 1024, 100 * 1024 * 1024, 3), strict=True
            )
        ):
            raise EvidenceError("AWS_COLLECTION_LIMITS")


@dataclass(frozen=True, slots=True)
class RetrievedLog:
    reference: ObjectVersion
    log: AwsLog
    retrieval_started: datetime
    retrieval_completed: datetime


@dataclass(frozen=True, slots=True)
class CollectionBatch:
    batch_id: str
    scope_fingerprint: str
    objects: tuple[RetrievedLog, ...]
    listing_pages: int
    unique_event_count: int
    duplicate_event_count: int
    conflicts: tuple[tuple[str, str, str], ...]
    source_kind: Literal["aws_shaped_unverified"] = field(
        default="aws_shaped_unverified", init=False
    )
    authenticated: Literal[False] = field(default=False, init=False)

    def to_public_dict(self) -> dict[str, object]:
        """Explicit allowlist: no accounts, keys, ARNs, locations, events or raw bytes."""
        return {
            "schema_version": COLLECTOR_VERSION,
            "batch_id": self.batch_id,
            "source_kind": self.source_kind,
            "authenticated": False,
            "state": "conflicting" if self.conflicts else "pending_source_authentication",
            "listing_complete": True,
            "listing_pages": self.listing_pages,
            "object_count": len(self.objects),
            "unique_event_count": self.unique_event_count,
            "duplicate_event_count": self.duplicate_event_count,
            "conflict_count": len(self.conflicts),
            "trusted_findings_available": False,
            "limitations": [
                "Offline contract only; no AWS source authenticated.",
                "In-memory checkpoint reference is not durable storage.",
                "No findings, review authority or case closure produced.",
            ],
        }


class MemoryLedger:
    """Atomic in-process reference implementation; no process-crash durability claim."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._generation = 0
        self._entries: dict[str, tuple[str, CollectionBatch]] = {}

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def lookup(self, checkpoint: str, fingerprint: str) -> CollectionBatch | None:
        with self._lock:
            prior = self._entries.get(checkpoint)
            if prior is not None and prior[0] != fingerprint:
                raise EvidenceError("AWS_CHECKPOINT_CONFLICT")
            return prior[1] if prior else None

    def commit(
        self, checkpoint: str, fingerprint: str, expected: int, batch: CollectionBatch
    ) -> CollectionBatch:
        with self._lock:
            prior = self._entries.get(checkpoint)
            if prior:
                if prior[0] != fingerprint or prior[1].batch_id != batch.batch_id:
                    raise EvidenceError("AWS_CHECKPOINT_CONFLICT")
                return prior[1]
            if expected != self._generation:
                raise EvidenceError("AWS_CHECKPOINT_STALE")
            self._entries[checkpoint] = (fingerprint, batch)
            self._generation += 1
            return batch


def _time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise EvidenceError("AWS_INVALID_TIME")
    return value.astimezone(UTC)


def _identity(value: CallerIdentity, scope: AwsScope, now: datetime) -> None:
    if type(value) is not CallerIdentity:
        raise EvidenceError("AWS_IDENTITY_REQUIRED")
    if not isinstance(value.user_id, str):
        raise EvidenceError("AWS_IDENTITY_MISMATCH")
    parts = value.user_id.split(":")
    if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{2,64}", parts[-1]):
        raise EvidenceError("AWS_IDENTITY_MISMATCH")
    role_name = scope.role_arn.rsplit("/", 1)[-1]
    expected = f"arn:aws:sts::{scope.account}:assumed-role/{role_name}/{parts[1]}"
    if (
        value.account != scope.account
        or value.region != scope.region
        or value.arn != expected
        or parts[0] != scope.role_id
    ):
        raise EvidenceError("AWS_IDENTITY_MISMATCH")
    observed, expires = _time(value.observed_at), _time(value.expires_at)
    if observed > now or now - observed > timedelta(seconds=60) or expires <= now:
        raise EvidenceError("AWS_IDENTITY_EXPIRED")


def _call[T](action: Callable[[], T], attempts: int, check: Callable[[], None]) -> T:
    for _ in range(attempts):
        check()
        try:
            return action()
        except RetryableReadError:
            continue
        except Exception:
            raise EvidenceError("AWS_TRANSPORT_FAILURE") from None
    raise EvidenceError("AWS_TRANSPORT_RETRY_EXHAUSTED")


def _reference(ref: ObjectVersion, scope: AwsScope, prefix: str, limit: int) -> None:
    if type(ref) is not ObjectVersion:
        raise EvidenceError("AWS_SOURCE_METADATA")
    if (
        ref.bucket != scope.bucket
        or not isinstance(ref.key, str)
        or not ref.key.startswith(prefix)
        or not ref.key.endswith(".json.gz")
        or not re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", ref.key)
        or "//" in ref.key
        or any(p in (".", "..") for p in ref.key.split("/"))
    ):
        raise EvidenceError("AWS_SOURCE_LOCATION")
    if (
        not isinstance(ref.version_id, str)
        or ref.version_id == "null"
        or not re.fullmatch(r"[A-Za-z0-9._+~=/:-]{1,1024}", ref.version_id)
    ):
        raise EvidenceError("AWS_OBJECT_VERSION")
    if type(ref.size) is not int or not 1 <= ref.size <= limit:
        raise EvidenceError("AWS_OBJECT_SIZE")
    if type(ref.is_delete_marker) is not bool or ref.is_delete_marker:
        raise EvidenceError("AWS_SOURCE_DELETED")
    if ref.is_latest is not True:
        raise EvidenceError("AWS_SOURCE_VERSION_HISTORY")
    _time(ref.last_modified)


_DEFAULT_LIMITS = CollectionLimits()


def collect(
    transport: ReadTransport,
    scope: AwsScope,
    ledger: MemoryLedger,
    checkpoint: str,
    *,
    clock: Callable[[], datetime],
    limits: CollectionLimits = _DEFAULT_LIMITS,
) -> CollectionBatch:
    """Stage the entire bounded poll; only then CAS its in-memory checkpoint.

    The supported contract rejects version history/delete markers rather than
    silently skipping evidence. Listing is complete only within the exact log
    prefix and supplied poll, not a snapshot guarantee over a changing bucket.
    Digests are handled by the separately unavailable authenticity boundary.
    """
    if type(scope) is not AwsScope or type(limits) is not CollectionLimits:
        raise EvidenceError("AWS_SCOPE_REQUIRED")
    if not isinstance(checkpoint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", checkpoint):
        raise EvidenceError("AWS_CHECKPOINT_REQUIRED")
    material = {
        "scope": asdict(scope),
        "limits": asdict(limits),
        "version": COLLECTOR_VERSION,
        "parser_versions": [
            SCHEMA_VERSION,
            PARSER_VERSION,
            CANONICALIZATION_VERSION,
            SYNTAX_PARSER_VERSION,
        ],
    }
    fingerprint = sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
    prior = ledger.lookup(checkpoint, fingerprint)
    if prior is not None:
        return prior
    generation = ledger.generation
    identity = _call(transport.caller_identity, limits.attempts, lambda: None)

    def check() -> None:
        _identity(identity, scope, _time(clock()))

    check()
    marker: Marker | None = None
    seen: set[Marker] = set()
    refs: dict[tuple[str, str], ObjectVersion] = {}
    keys: dict[str, str] = {}
    pages = 0
    while True:
        if pages >= limits.max_pages:
            raise EvidenceError("AWS_LISTING_LIMIT")
        page = _call(
            partial(transport.list_versions, scope, scope.log_prefix, marker),
            limits.attempts,
            check,
        )
        pages += 1
        if (
            type(page) is not VersionPage
            or page.ok is not True
            or type(page.truncated) is not bool
            or type(page.versions) is not tuple
        ):
            raise EvidenceError("AWS_LISTING_RESPONSE")
        if len(page.versions) > limits.max_objects:
            raise EvidenceError("AWS_LISTING_LIMIT")
        for ref in page.versions:
            _reference(ref, scope, scope.log_prefix, limits.max_archive_bytes)
            if marker is not None and ref.key < marker[0]:
                raise EvidenceError("AWS_PAGINATION")
            key = (ref.key, ref.version_id)
            if key in refs and refs[key] != ref:
                raise EvidenceError("AWS_SOURCE_METADATA_CONFLICT")
            if ref.key in keys and keys[ref.key] != ref.version_id:
                raise EvidenceError("AWS_SOURCE_VERSION_HISTORY")
            refs[key], keys[ref.key] = ref, ref.version_id
            if len(refs) > limits.max_objects:
                raise EvidenceError("AWS_LISTING_LIMIT")
        if not page.truncated:
            if page.next_marker is not None:
                raise EvidenceError("AWS_PAGINATION")
            break
        next_marker = page.next_marker
        if (
            type(next_marker) is not tuple
            or len(next_marker) != 2
            or any(
                not isinstance(v, str) or not 1 <= len(v) <= 1024 or any(ord(c) < 32 for c in v)
                for v in next_marker
            )
            or not next_marker[0].startswith(scope.log_prefix)
            or not re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", next_marker[0])
            or "//" in next_marker[0]
            or any(p in (".", "..") for p in next_marker[0].split("/"))
            or (marker is not None and next_marker[0] < marker[0])
            or next_marker[0] < max((r.key for r in page.versions), default=scope.log_prefix)
            or next_marker in seen
        ):
            raise EvidenceError("AWS_PAGINATION")
        seen.add(next_marker)
        marker = next_marker
    remaining_archive, remaining_content, event_count = (
        limits.max_archive_bytes,
        limits.max_content_bytes,
        0,
    )
    objects: list[RetrievedLog] = []
    variants: dict[tuple[str, str, str], set[bytes]] = {}
    for ref in sorted(refs.values(), key=lambda r: (r.key, r.version_id)):
        if ref.size > remaining_archive or remaining_content < 1:
            raise EvidenceError("AWS_BATCH_LIMIT")
        before = _call(partial(transport.head_current, ref), limits.attempts, check)
        if before != ref.version_id:
            raise EvidenceError("AWS_SOURCE_CHANGED")
        started = _time(clock())
        body = _call(partial(transport.get_object, ref, ref.size + 1), limits.attempts, check)
        if type(body) is not ObjectBody:
            raise EvidenceError("AWS_OBJECT_RESPONSE")
        try:
            if body.reference != ref or body.owner_account != scope.account:
                raise EvidenceError("AWS_OBJECT_RESPONSE")
            staged = bytearray()
            for _ in range(1024):
                remaining = ref.size + 1 - len(staged)
                piece = body.stream.read(remaining)
                if not isinstance(piece, bytes) or len(piece) > remaining:
                    raise EvidenceError("AWS_OBJECT_SIZE")
                staged.extend(piece)
                if len(staged) > ref.size:
                    raise EvidenceError("AWS_OBJECT_SIZE")
                if not piece:
                    break
            else:
                raise EvidenceError("AWS_OBJECT_READ_LIMIT")
            data = bytes(staged)
            if len(data) != ref.size:
                raise EvidenceError("AWS_OBJECT_SIZE")
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("AWS_OBJECT_READ") from None
        finally:
            try:
                body.stream.close()
            except Exception:
                raise EvidenceError("AWS_OBJECT_READ") from None
        after = _call(partial(transport.head_current, ref), limits.attempts, check)
        completed = _time(clock())
        if after != before or completed < started:
            raise EvidenceError("AWS_SOURCE_CHANGED")
        log = parse_aws_shaped(
            data,
            scope,
            limits=Limits(
                max_compressed_bytes=remaining_archive,
                max_expanded_bytes=remaining_content,
                max_records=max(1, 10_000 - event_count),
            ),
        )
        remaining_archive -= len(data)
        remaining_content -= len(log.content_bytes)
        event_count += len(log.events)
        if event_count > 10_000:
            raise EvidenceError("AWS_BATCH_LIMIT")
        objects.append(RetrievedLog(ref, log, started, completed))
        for event in log.events:
            variants.setdefault(event.identity, set()).add(event.canonical_record)
    # A later retrieval may have changed an earlier current object. This is a
    # bounded continuity check, not an atomic S3 snapshot or authentication.
    for obj in objects:
        if _call(partial(transport.head_current, obj.reference), limits.attempts, check) != (
            obj.reference.version_id
        ):
            raise EvidenceError("AWS_SOURCE_CHANGED")
    check()
    conflicts = tuple(sorted(key for key, records in variants.items() if len(records) > 1))
    binding = [
        (o.reference.key, o.reference.version_id, o.log.archive_sha256, o.log.content_sha256)
        for o in objects
    ]
    batch_id = sha256(
        json.dumps([fingerprint, binding], separators=(",", ":")).encode()
    ).hexdigest()
    batch = CollectionBatch(
        batch_id,
        fingerprint,
        tuple(objects),
        pages,
        len(variants),
        event_count - sum(len(records) for records in variants.values()),
        conflicts,
    )
    try:
        return ledger.commit(checkpoint, fingerprint, generation, batch)
    except EvidenceError:
        raise
    except Exception:
        raise EvidenceError("AWS_CHECKPOINT_COMMIT_FAILED") from None


def require_authenticated(value: object) -> None:
    """Fail closed even if a Python caller supplies forged fields or a fake receipt."""
    raise EvidenceError("AWS_AUTHENTICATION_UNAVAILABLE")
