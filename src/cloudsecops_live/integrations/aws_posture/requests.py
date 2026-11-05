"""Reference-only public requests; imports no SDK or credential dependencies."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import ClassVar

from cloudsecops_live.errors import EvidenceError

MAX_REQUEST_BYTES = 8192


def _reference(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise EvidenceError("AWS4A_REQUEST")
    return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise EvidenceError("AWS4A_REQUEST")
        value[key] = child
    return value


def _unsupported(value: str) -> object:
    raise EvidenceError("AWS4A_REQUEST")


@dataclass(frozen=True, slots=True)
class PostureRequest:
    """Only opaque references cross the ordinary request/control channel."""

    SCHEMA_VERSION: ClassVar[str] = "aws4a-posture-request/1"
    decision_ref: str = field(repr=False)
    nonce: str = field(repr=False)

    def __post_init__(self) -> None:
        _reference(self.decision_ref)
        _reference(self.nonce)

    def to_metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "decision_ref": self.decision_ref,
            "nonce": self.nonce,
        }

    def to_bytes(self) -> bytes:
        # Exact three-field shape plus two 64-byte references implies < 8 KiB.
        return json.dumps(self.to_metadata(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_metadata(cls, value: object) -> PostureRequest:
        if (
            type(value) is not dict
            or len(value) != 3
            or set(value) != {"schema_version", "decision_ref", "nonce"}
            or type(value["schema_version"]) is not str
            or value["schema_version"] != cls.SCHEMA_VERSION
        ):
            raise EvidenceError("AWS4A_REQUEST")
        return cls(_reference(value["decision_ref"]), _reference(value["nonce"]))

    @classmethod
    def from_bytes(cls, raw: object) -> PostureRequest:
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST_BYTES:
            raise EvidenceError("AWS4A_REQUEST")
        try:
            parsed = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_unsupported
            )
            return cls.from_metadata(parsed)
        except (ValueError, UnicodeError, RecursionError):
            raise EvidenceError("AWS4A_REQUEST") from None
