"""Pure, bounded inventory-burst detection over synthetic normalized evidence."""

import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256

from cloudsecops_live.contracts import (
    CANONICALIZATION_VERSION,
    PARSER_VERSION,
    SCHEMA_VERSION,
    EventIdentity,
    NormalizedEvent,
    ParsedLog,
    ProvenanceState,
    RawEvidence,
    RecordReference,
    SessionIdentity,
)
from cloudsecops_live.errors import EvidenceError

RULE_ID = "AWS-LAB-001"
RULE_VERSION = "1.0"
_RULE_DEFINITION = (
    "AWS-LAB-001/1.0; synthetic; ec2.amazonaws.com; DescribeInstances; Management; "
    "AwsApiCall; readOnly is true; no errors; consistent AssumedRole credential session; "
    "3 unique full event identities per inclusive 60-second event-time window; "
    "all maximal windows; transitive union only through shared evidence"
)
RULE_DEFINITION_SHA256 = sha256(_RULE_DEFINITION.encode()).hexdigest()
_WINDOW = timedelta(seconds=60)
_VERSIONS = (SCHEMA_VERSION, PARSER_VERSION, CANONICALIZATION_VERSION)
_LIMITATIONS = (
    "Synthetic candidate only; these records authenticate no AWS source or activity.",
    "Benign administrators, inventory tools, pagination and SDK retries can cause bursts.",
    "Visibility is limited to the supplied records; missing activity cannot be ruled out.",
    "T1580 describes infrastructure enumeration; this is no validated attack or compromise.",
)


class NonqualifyingReason(StrEnum):
    EVENT_SOURCE_MISMATCH = "event_source_mismatch"
    EVENT_NAME_MISMATCH = "event_name_mismatch"
    EVENT_CATEGORY_MISMATCH = "event_category_mismatch"
    EVENT_TYPE_MISMATCH = "event_type_mismatch"
    NOT_READ_ONLY = "not_read_only"
    AWS_ERROR = "aws_error"
    INVALID_SESSION = "invalid_session"
    IDENTITY_CONFLICT = "identity_conflict"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EventSummary:
    identity: EventIdentity
    record_sha256s: tuple[str, ...]
    references: tuple[RecordReference, ...]
    reasons: tuple[NonqualifyingReason, ...]

    @property
    def qualifying(self) -> bool:
        return not self.reasons

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": asdict(self.identity),
            "record_sha256s": list(self.record_sha256s),
            "delivery_count": len(self.references),
            "references": [asdict(reference) for reference in self.references],
            "qualifying": self.qualifying,
            "reasons": [reason.value for reason in self.reasons],
        }


@dataclass(frozen=True, slots=True)
class IdentityConflict:
    identity: EventIdentity
    record_sha256s: tuple[str, ...]
    references: tuple[RecordReference, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": asdict(self.identity),
            "record_sha256s": list(self.record_sha256s),
            "references": [asdict(reference) for reference in self.references],
        }


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    session: SessionIdentity
    evidence: tuple[NormalizedEvent, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule_id": RULE_ID,
            "rule_version": RULE_VERSION,
            "rule_definition_sha256": RULE_DEFINITION_SHA256,
            "schema_version": SCHEMA_VERSION,
            "parser_version": PARSER_VERSION,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "status": "synthetic_candidate",
            "source_kind": "synthetic",
            "authenticated": False,
            "session": asdict(self.session),
            "count": len(self.evidence),
            "evidence_event_ids": [event.identity.event_id for event in self.evidence],
            "evidence": [
                {"identity": asdict(event.identity), "record_sha256": event.record_sha256}
                for event in self.evidence
            ],
            "window_start": _timestamp(self.evidence[0].event_time),
            "window_end": _timestamp(self.evidence[-1].event_time),
            "window_explanation": (
                "Union of maximal inclusive 60-second windows sharing evidence, transitively; "
                "the resulting component may span more than 60 seconds."
            ),
            "attack": {"technique_id": "T1580", "name": "Cloud Infrastructure Discovery"},
            "rationale": (
                "At least three unique successful EC2 DescribeInstances management API calls "
                "occurred in an inclusive 60-second window for one credential session."
            ),
            "limitations": list(_LIMITATIONS),
        }


@dataclass(frozen=True, slots=True)
class DetectionReport:
    findings: tuple[Finding, ...]
    events: tuple[EventSummary, ...]
    conflicts: tuple[IdentityConflict, ...]
    delivery_count: int

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "parser_version": PARSER_VERSION,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "source_kind": "synthetic",
            "authenticated": False,
            "provenance": "conflicting" if self.has_conflicts else "synthetic",
            "has_conflicts": self.has_conflicts,
            "delivery_count": self.delivery_count,
            "unique_event_count": len(self.events),
            "duplicate_delivery_count": self.delivery_count - len(self.events),
            "findings": [finding.to_dict() for finding in self.findings],
            "events": [event.to_dict() for event in self.events],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
        }


def _validate_derivative(value: RawEvidence | NormalizedEvent) -> None:
    versions = (value.schema_version, value.parser_version, value.canonicalization_version)
    if versions != _VERSIONS:
        raise EvidenceError("UNSUPPORTED_VERSION")
    provenance = value.provenance
    if (
        provenance.source_kind != "synthetic"
        or provenance.authenticated is not False
        or provenance.state != ProvenanceState.SYNTHETIC
    ):
        raise EvidenceError("INVALID_PROVENANCE")


def _reasons(event: NormalizedEvent) -> tuple[NonqualifyingReason, ...]:
    checks = (
        (event.event_source != "ec2.amazonaws.com", NonqualifyingReason.EVENT_SOURCE_MISMATCH),
        (event.event_name != "DescribeInstances", NonqualifyingReason.EVENT_NAME_MISMATCH),
        (event.event_category != "Management", NonqualifyingReason.EVENT_CATEGORY_MISMATCH),
        (event.event_type != "AwsApiCall", NonqualifyingReason.EVENT_TYPE_MISMATCH),
        (event.read_only is not True, NonqualifyingReason.NOT_READ_ONLY),
        (event.has_error, NonqualifyingReason.AWS_ERROR),
        (
            event.session is None
            or event.identity_reason is not None
            or event.session.account != event.identity.account
            or event.session.region != event.identity.region,
            NonqualifyingReason.INVALID_SESSION,
        ),
    )
    return tuple(reason for failed, reason in checks if failed)


def _components(events: Sequence[NormalizedEvent]) -> list[tuple[NormalizedEvent, ...]]:
    """Use a linear sweep over maximal windows; union only intersecting index sets."""
    right = 0
    previous_right = -1
    intervals: list[tuple[int, int]] = []
    for left, event in enumerate(events):
        while right < len(events) and events[right].event_time - event.event_time <= _WINDOW:
            right += 1
        # A window with the same end as its predecessor is a strict subset.
        if right - left >= 3 and right > previous_right:
            if intervals and left < intervals[-1][1]:
                intervals[-1] = (intervals[-1][0], right)
            else:
                intervals.append((left, right))
        previous_right = right
    return [tuple(events[left:right]) for left, right in intervals]


def _finding(session: SessionIdentity, events: tuple[NormalizedEvent, ...]) -> Finding:
    identity_material = {
        "domain": "cloudsecops-live/finding/1.0",
        "rule_id": RULE_ID,
        "rule_version": RULE_VERSION,
        "rule_definition_sha256": RULE_DEFINITION_SHA256,
        "versions": _VERSIONS,
        "session": asdict(session),
        "window": [_timestamp(events[0].event_time), _timestamp(events[-1].event_time)],
        "evidence": [
            {"identity": asdict(event.identity), "record_sha256": event.record_sha256}
            for event in events
        ],
    }
    encoded = json.dumps(identity_material, sort_keys=True, separators=(",", ":")).encode()
    return Finding(sha256(encoded).hexdigest(), session, events)


def detect(logs: Sequence[ParsedLog]) -> DetectionReport:
    """Deduplicate complete source records before qualifying and correlating evidence.

    A conflict anywhere blocks findings for the entire batch. References remain in
    separate immutable summaries; input events and preserved evidence are untouched.
    """
    if len(logs) > 64 or sum(len(log.events) for log in logs) > 10_000:
        raise EvidenceError("DETECTION_LIMIT")
    grouped: dict[EventIdentity, list[NormalizedEvent]] = defaultdict(list)
    for log in logs:
        _validate_derivative(log.evidence)
        for event in log.events:
            _validate_derivative(event)
            if event.identity.source_kind != "synthetic":
                raise EvidenceError("INVALID_PROVENANCE")
            if event.event_time.utcoffset() is None:
                raise EvidenceError("INVALID_EVENT_TIME")
            grouped[event.identity].append(event)

    summaries: list[EventSummary] = []
    conflicts: list[IdentityConflict] = []
    sessions: dict[SessionIdentity, list[NormalizedEvent]] = defaultdict(list)
    delivery_count = 0
    for identity, deliveries in sorted(grouped.items()):
        references = tuple(sorted(ref for event in deliveries for ref in event.references))
        delivery_count += len(references)
        hashes = tuple(sorted({sha256(event.canonical_record).hexdigest() for event in deliveries}))
        canonical_records = {event.canonical_record for event in deliveries}
        reasons: tuple[NonqualifyingReason, ...]
        if len(canonical_records) != 1:
            conflicts.append(IdentityConflict(identity, hashes, references))
            reasons = (NonqualifyingReason.IDENTITY_CONFLICT,)
        else:
            # All derivatives of the same canonical record/version are equivalent.
            event = deliveries[0]
            reasons = _reasons(event)
            if not reasons and event.session is not None:
                sessions[event.session].append(event)
        summaries.append(EventSummary(identity, hashes, references, reasons))

    findings: list[Finding] = []
    if not conflicts:
        for session, events in sorted(sessions.items()):
            events.sort(key=lambda event: (event.event_time, event.identity))
            findings.extend(_finding(session, component) for component in _components(events))
    return DetectionReport(tuple(findings), tuple(summaries), tuple(conflicts), delivery_count)
