"""Bounded offline import. Hashes establish consistency, never AWS authenticity."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zlib
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import NoReturn, cast

from cloudsecops_live.contracts import (
    EventIdentity,
    Limits,
    NormalizedEvent,
    ParsedLog,
    RawEvidence,
    RecordReference,
    SessionIdentity,
)
from cloudsecops_live.errors import EvidenceError

type JSONValue = None | bool | int | Decimal | str | list[JSONValue] | dict[str, JSONValue]
_DEFAULT_LIMITS = Limits()
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")
_ACCOUNT = re.compile(r"LABACCOUNT_[A-Z0-9_]{1,40}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_LABEL = re.compile(r"[A-Za-z0-9_+=,.@-]{1,128}\Z")


def _reject(code: str) -> NoReturn:
    raise EvidenceError(code)


def _expand(data: bytes, limits: Limits) -> bytes:
    if len(data) > limits.max_compressed_bytes:
        _reject("COMPRESSED_LIMIT")
    decoder = zlib.decompressobj(wbits=31)
    expanded = bytearray()
    try:
        for start in range(0, len(data), 16_384):
            piece = decoder.decompress(
                data[start : start + 16_384], limits.max_expanded_bytes - len(expanded) + 1
            )
            expanded.extend(piece)
            if len(expanded) > limits.max_expanded_bytes:
                _reject("EXPANDED_LIMIT")
            if decoder.unused_data or decoder.unconsumed_tail:
                _reject("INVALID_GZIP")
        if not decoder.eof:
            _reject("INVALID_GZIP")
    except zlib.error:
        _reject("INVALID_GZIP")
    return bytes(expanded)


def _string_end(text: str, start: int, limits: Limits) -> int:
    """Count decoded code points without allocating a decoded string."""
    i, count = start + 1, 0
    while i < len(text):
        char = text[i]
        if char == '"':
            return i + 1
        if ord(char) < 32:
            _reject("INVALID_JSON")
        if char == "\\":
            i += 1
            if i >= len(text):
                _reject("INVALID_JSON")
            if text[i] == "u":
                digits = text[i + 1 : i + 5]
                if len(digits) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                    _reject("INVALID_JSON")
                unit = int(digits, 16)
                i += 5
                if 0xD800 <= unit <= 0xDBFF:
                    low = text[i + 2 : i + 6]
                    if (
                        text[i : i + 2] != "\\u"
                        or len(low) != 4
                        or not re.fullmatch(r"[0-9a-fA-F]{4}", low)
                        or not 0xDC00 <= int(low, 16) <= 0xDFFF
                    ):
                        _reject("INVALID_UNICODE")
                    i += 6
                elif 0xDC00 <= unit <= 0xDFFF:
                    _reject("INVALID_UNICODE")
            else:
                if text[i] not in '"\\/bfnrt':
                    _reject("INVALID_JSON")
                i += 1
        else:
            i += 1
        count += 1
        if count > limits.max_string_length:
            _reject("STRING_LIMIT")
    _reject("INVALID_JSON")


def _preflight(text: str, limits: Limits) -> None:
    """Bound keys, decoded strings and root Records cardinality before tree allocation."""
    stack: list[str] = []
    nodes = i = records = 0
    records_depth: int | None = None
    root_key: str | None = None
    root_keys: set[str] = set()
    while i < len(text):
        char = text[i]
        if char in " \t\r\n,:]}":
            if char in "]}":
                if not stack or (stack[-1], char) not in (("[", "]"), ("{", "}")):
                    _reject("INVALID_JSON")
                if records_depth == len(stack):
                    records_depth = None
                stack.pop()
            elif char == "," and len(stack) == 1:
                root_key = None
            i += 1
            continue
        nodes += 1
        if nodes > limits.max_nodes:
            _reject("NODE_LIMIT")
        if records_depth is not None and len(stack) == records_depth:
            records += 1
            if records > limits.max_records:
                _reject("RECORD_LIMIT")
        if char in "[{":
            if char == "[" and len(stack) == 1 and root_key == "Records":
                records_depth = 2
            stack.append(char)
            if len(stack) > limits.max_depth:
                _reject("DEPTH_LIMIT")
            i += 1
        elif char == '"':
            end = _string_end(text, i, limits)
            following = end
            while following < len(text) and text[following] in " \t\r\n":
                following += 1
            if len(stack) == 1 and stack[0] == "{" and text[following : following + 1] == ":":
                # This token was already length/escape checked; only a bounded key is decoded.
                root_key = cast("str", json.JSONDecoder().raw_decode(text[i:end])[0])
                if root_key in root_keys:
                    _reject("DUPLICATE_KEY")
                root_keys.add(root_key)
            i = end
        else:
            start = i
            while i < len(text) and text[i] not in ' \t\r\n,:]}[{"':
                i += 1
                if i - start > limits.max_number_length:
                    _reject("NUMBER_LIMIT")


def _pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            _reject("DUPLICATE_KEY")
        result[key] = value
    return result


def _number(token: str, limits: Limits, *, integer: bool) -> int | Decimal:
    if len(token) > limits.max_number_length:
        _reject("NUMBER_LIMIT")
    try:
        if integer:
            return int(token)
        value = Decimal(token)
        exponent = value.as_tuple().exponent
        if not value.is_finite() or not isinstance(exponent, int) or abs(exponent) > 308:
            _reject("NUMBER_LIMIT")
        return value
    except (ValueError, InvalidOperation):
        _reject("INVALID_NUMBER")


def _constant(_: str) -> NoReturn:
    _reject("NONFINITE_NUMBER")


def _check_tree(value: JSONValue, limits: Limits) -> None:
    if isinstance(value, str):
        if len(value) > limits.max_string_length:
            _reject("STRING_LIMIT")
        if "\x00" in value:
            _reject("NUL_CHARACTER")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            _reject("INVALID_UNICODE")
    elif isinstance(value, list):
        for item in value:
            _check_tree(item, limits)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_tree(key, limits)
            _check_tree(item, limits)


def _canonical(value: JSONValue) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        number = format(value, "f")  # exact, no context rounding or binary float
        if "." in number:
            number = number.rstrip("0").rstrip(".")
        if number in ("-0", "0"):
            number = "0"
        return number if "." in number else number + ".0"
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    return (
        "{"
        + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + _canonical(value[key])
            for key in sorted(value)
        )
        + "}"
    )


def _timestamp(value: JSONValue) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        _reject("INVALID_TIMESTAMP")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        _reject("INVALID_TIMESTAMP")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OverflowError):
        _reject("INVALID_TIMESTAMP")


def _utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _text(record: dict[str, JSONValue], key: str, *, required: bool = False) -> str:
    value = record.get(key, "")
    if not isinstance(value, str) or (required and not value):
        _reject("INVALID_RECORD_SCHEMA")
    return value


def _session(
    record: dict[str, JSONValue], identity: EventIdentity, event_time: datetime
) -> tuple[SessionIdentity | None, str | None]:
    user = record.get("userIdentity")
    if not isinstance(user, dict) or user.get("type") != "AssumedRole":
        return None, "missing_assumed_role"
    context = user.get("sessionContext")
    if not isinstance(context, dict):
        return None, "missing_session_context"
    issuer = context.get("sessionIssuer")
    attributes = context.get("attributes")
    if not isinstance(issuer, dict) or not isinstance(attributes, dict):
        return None, "missing_session_identity"
    arn, actor_arn = issuer.get("arn"), user.get("arn")
    role_id, principal, key = (
        issuer.get("principalId"),
        user.get("principalId"),
        user.get("accessKeyId"),
    )
    if not all(isinstance(v, str) and v for v in (arn, actor_arn, role_id, principal, key)):
        return None, "missing_session_identity"
    assert isinstance(arn, str) and isinstance(actor_arn, str) and isinstance(role_id, str)
    assert isinstance(principal, str) and isinstance(key, str)
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::([^:]+):role/(.+)", arn)
    parts = principal.split(":")
    if (
        not match
        or issuer.get("type") != "Role"
        or user.get("accountId") != identity.account
        or issuer.get("accountId") != identity.account
        or match.group(2) != identity.account
        or len(parts) != 2
        or parts[0] != role_id
        or not _LABEL.fullmatch(parts[1])
        or not _LABEL.fullmatch(role_id)
        or not re.fullmatch(r"SYNTHETIC_KEY_[A-Z0-9_]{1,64}", key)
    ):
        return None, "inconsistent_assumed_role"
    role_name = match.group(3).split("/")[-1]
    expected = f"arn:{match.group(1)}:sts::{identity.account}:assumed-role/{role_name}/{parts[1]}"
    if not _LABEL.fullmatch(role_name) or actor_arn != expected:
        return None, "inconsistent_assumed_role"
    try:
        creation = _timestamp(attributes.get("creationDate"))
    except EvidenceError:
        return None, "missing_session_creation"
    if creation > event_time:
        return None, "future_session_creation"
    return SessionIdentity(identity.account, identity.region, arn, key, _utc(creation)), None


def _normalize(record: dict[str, JSONValue], reference: RecordReference) -> NormalizedEvent:
    account = _text(record, "recipientAccountId", required=True)
    region = _text(record, "awsRegion", required=True)
    event_id = _text(record, "eventID", required=True)
    if (
        not _ACCOUNT.fullmatch(account)
        or not _REGION.fullmatch(region)
        or not _LABEL.fullmatch(event_id)
    ):
        _reject("INVALID_RECORD_IDENTITY")
    identity = EventIdentity("synthetic", account, region, event_id)
    event_time = _timestamp(record.get("eventTime"))
    read_only = record.get("readOnly")
    if read_only is not None and type(read_only) is not bool:
        _reject("INVALID_RECORD_SCHEMA")
    for error_field in ("errorCode", "errorMessage"):
        if error_field in record and not isinstance(record[error_field], (str, type(None))):
            _reject("INVALID_RECORD_SCHEMA")
    session, reason = _session(record, identity, event_time)
    canonical = _canonical(record).encode("utf-8")
    return NormalizedEvent(
        identity,
        event_time,
        _text(record, "eventSource"),
        _text(record, "eventName"),
        _text(record, "eventCategory"),
        _text(record, "eventType"),
        read_only,
        "errorCode" in record or "errorMessage" in record,
        session,
        reason,
        canonical,
        hashlib.sha256(canonical).hexdigest(),
        (reference,),
    )


def parse_bytes(
    data: bytes, *, source_ref: str = "fixture.json.gz", limits: Limits = _DEFAULT_LIMITS
) -> ParsedLog:
    """Import one strict fixture envelope. Unknown record fields remain evidence."""
    if not isinstance(data, bytes):
        _reject("INVALID_INPUT_TYPE")
    if (
        not isinstance(source_ref, str)
        or not 1 <= len(source_ref) <= 256
        or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in source_ref)
    ):
        _reject("INVALID_SOURCE_REFERENCE")
    content = _expand(data, limits)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        _reject("INVALID_UTF8")
    _preflight(text, limits)
    try:
        document = cast(
            "JSONValue",
            json.loads(
                text,
                object_pairs_hook=_pairs,
                parse_constant=_constant,
                parse_int=lambda token: _number(token, limits, integer=True),
                parse_float=lambda token: _number(token, limits, integer=False),
            ),
        )
    except (json.JSONDecodeError, RecursionError):
        _reject("INVALID_JSON")
    _check_tree(document, limits)
    if not isinstance(document, dict) or set(document) != {
        "fixture_schema_version",
        "source_kind",
        "Records",
    }:
        _reject("INVALID_FIXTURE_ENVELOPE")
    if document["fixture_schema_version"] != "1.0":
        _reject("UNSUPPORTED_VERSION")
    if document["source_kind"] != "synthetic":
        _reject("INVALID_SOURCE_CLASSIFICATION")
    records = document["Records"]
    if not isinstance(records, list):
        _reject("INVALID_RECORDS")
    if len(records) > limits.max_records:
        _reject("RECORD_LIMIT")
    archive_hash = hashlib.sha256(data).hexdigest()
    content_hash = hashlib.sha256(content).hexdigest()
    raw = RawEvidence(source_ref, data, content, archive_hash, content_hash)
    events: list[NormalizedEvent] = []
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            _reject("INVALID_RECORD_SCHEMA")
        events.append(
            _normalize(record, RecordReference(source_ref, position, archive_hash, content_hash))
        )
    return ParsedLog(raw, tuple(events))


def parse_file(path: Path, *, limits: Limits = _DEFAULT_LIMITS) -> ParsedLog:
    """Read only a regular local .json.gz file, never an unbounded stream."""
    if not path.name.endswith(".json.gz"):
        _reject("INVALID_FILE_TYPE")
    try:
        if path.is_symlink():
            _reject("INVALID_FILE_TYPE")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                _reject("INVALID_FILE_TYPE")
            if info.st_size > limits.max_compressed_bytes:
                _reject("COMPRESSED_LIMIT")
            data = stream.read(limits.max_compressed_bytes + 1)
    except OSError:
        _reject("FILE_READ_ERROR")
    return parse_bytes(data, source_ref=path.name, limits=limits)
