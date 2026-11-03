"""Versioned immutable interfaces for synthetic evidence only."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal

SCHEMA_VERSION = "1.0"
PARSER_VERSION = "1.0.0"
CANONICALIZATION_VERSION = "1.0"


class ProvenanceState(StrEnum):
    SYNTHETIC = "synthetic"
    UNVERIFIED = "unverified"
    PENDING = "pending"
    CONFLICTING = "conflicting"


@dataclass(frozen=True, slots=True)
class Provenance:
    state: ProvenanceState = ProvenanceState.SYNTHETIC
    source_kind: Literal["synthetic"] = field(default="synthetic", init=False)
    authenticated: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.state, ProvenanceState):
            raise ValueError("unsupported provenance state")


@dataclass(frozen=True, slots=True)
class Limits:
    max_compressed_bytes: int = 10 * 1024 * 1024
    max_expanded_bytes: int = 100 * 1024 * 1024
    max_records: int = 10_000
    max_depth: int = 32
    max_string_length: int = 4096
    max_nodes: int = 200_000
    max_number_length: int = 128

    def __post_init__(self) -> None:
        ceilings = (10 * 1024 * 1024, 100 * 1024 * 1024, 10_000, 32, 4096, 200_000, 128)
        values = (
            self.max_compressed_bytes,
            self.max_expanded_bytes,
            self.max_records,
            self.max_depth,
            self.max_string_length,
            self.max_nodes,
            self.max_number_length,
        )
        if any(
            type(value) is not int or not 1 <= value <= ceiling
            for value, ceiling in zip(values, ceilings, strict=True)
        ):
            raise ValueError("limits must be positive integers within hard ceilings")


@dataclass(frozen=True, slots=True, order=True)
class EventIdentity:
    source_kind: Literal["synthetic"]
    account: str
    region: str
    event_id: str

    def __post_init__(self) -> None:
        if self.source_kind != "synthetic":
            raise ValueError("only synthetic source identities are supported")


@dataclass(frozen=True, slots=True, order=True)
class SessionIdentity:
    account: str
    region: str
    issuer_arn: str
    access_key_id: str
    creation_time: str


@dataclass(frozen=True, slots=True, order=True)
class RecordReference:
    source_ref: str
    record_index: int
    archive_sha256: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class RawEvidence:
    source_ref: str
    archive_bytes: bytes
    content_bytes: bytes
    archive_sha256: str
    content_sha256: str
    provenance: Provenance = field(default_factory=Provenance)
    schema_version: str = SCHEMA_VERSION
    parser_version: str = PARSER_VERSION
    canonicalization_version: str = CANONICALIZATION_VERSION


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    identity: EventIdentity
    event_time: datetime
    event_source: str
    event_name: str
    event_category: str
    event_type: str
    read_only: bool | None
    has_error: bool
    session: SessionIdentity | None
    identity_reason: str | None
    canonical_record: bytes
    record_sha256: str
    references: tuple[RecordReference, ...]
    provenance: Provenance = field(default_factory=Provenance)
    schema_version: str = SCHEMA_VERSION
    parser_version: str = PARSER_VERSION
    canonicalization_version: str = CANONICALIZATION_VERSION


@dataclass(frozen=True, slots=True)
class ParsedLog:
    evidence: RawEvidence
    events: tuple[NormalizedEvent, ...]
