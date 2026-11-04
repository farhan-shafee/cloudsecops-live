"""Bounded offline AWS-shaped parsing, without AWS access or trust promotion.

The syntactic helpers are deliberately pinned to ingestion parser 1.0.0 and
canonicalization 1.0. They share gzip/JSON/resource defenses only; this module
does not call its synthetic envelope, normalization, or provenance functions.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import cast

from cloudsecops_live.contracts import Limits
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import (
    JSONValue,
    _canonical,
    _check_tree,
    _constant,
    _expand,
    _number,
    _pairs,
    _preflight,
    _timestamp,
)
from cloudsecops_live.integrations.aws_cloudtrail.models import (
    AwsEvent,
    AwsLog,
    AwsScope,
    AwsSession,
    _is_account,
    _role_parts,
)

_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_SESSION_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{2,64}\Z")
_ROLE_ID = re.compile(r"AROA[A-Z0-9]{17}\Z")
_SESSION_KEY = re.compile(r"ASIA[A-Z0-9]{16}\Z")
_DEFAULT_LIMITS = Limits()


def _required_text(record: dict[str, JSONValue], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise EvidenceError("INVALID_AWS_RECORD")
    return value


def _session(
    record: dict[str, JSONValue], region: str, event_time: datetime
) -> tuple[AwsSession | None, str | None]:
    user = record.get("userIdentity")
    if not isinstance(user, dict) or user.get("type") != "AssumedRole":
        return None, "unsupported_actor"
    context = user.get("sessionContext")
    if not isinstance(context, dict):
        return None, "missing_session_context"
    issuer, attributes = context.get("sessionIssuer"), context.get("attributes")
    if not isinstance(issuer, dict) or not isinstance(attributes, dict):
        return None, "missing_session_identity"
    arn, actor_arn, account = issuer.get("arn"), user.get("arn"), user.get("accountId")
    role_id, principal, key = (
        issuer.get("principalId"),
        user.get("principalId"),
        user.get("accessKeyId"),
    )
    if not all(
        isinstance(value, str) and value
        for value in (arn, actor_arn, account, role_id, principal, key)
    ):
        return None, "missing_session_identity"
    assert isinstance(arn, str) and isinstance(actor_arn, str) and isinstance(account, str)
    assert isinstance(role_id, str) and isinstance(principal, str) and isinstance(key, str)
    role = _role_parts(arn)
    parts = principal.split(":")
    if (
        role is None
        or not _is_account(account)
        or role[0] != account
        or issuer.get("type") != "Role"
        or issuer.get("accountId") != account
        or _ROLE_ID.fullmatch(role_id) is None
        or len(parts) != 2
        or parts[0] != role_id
        or _SESSION_NAME.fullmatch(parts[1]) is None
        or _SESSION_KEY.fullmatch(key) is None
    ):
        return None, "inconsistent_assumed_role"
    expected_arn = f"arn:aws:sts::{account}:assumed-role/{role[1]}/{parts[1]}"
    if actor_arn != expected_arn:
        return None, "inconsistent_assumed_role"
    try:
        creation = _timestamp(attributes.get("creationDate"))
    except EvidenceError:
        return None, "missing_session_creation"
    if creation > event_time:
        return None, "future_session_creation"
    return AwsSession(account, region, arn, key, creation), None


def _event(record: dict[str, JSONValue], scope: AwsScope, position: int) -> AwsEvent:
    # Bind every field, including unsupported actor details, before deriving any labels.
    canonical = _canonical(record).encode("utf-8")
    record_hash = hashlib.sha256(canonical).hexdigest()
    account = _required_text(record, "recipientAccountId")
    region = _required_text(record, "awsRegion")
    event_id = _required_text(record, "eventID")
    if account != scope.account or region != scope.region or _UUID.fullmatch(event_id) is None:
        raise EvidenceError("INVALID_AWS_RECORD_IDENTITY")
    category = _required_text(record, "eventCategory")
    if category != "Management":
        raise EvidenceError("UNSUPPORTED_AWS_EVENT_CATEGORY")
    event_time = _timestamp(record.get("eventTime"))
    source, name, event_type = (
        _required_text(record, "eventSource"),
        _required_text(record, "eventName"),
        _required_text(record, "eventType"),
    )
    read_only = record.get("readOnly")
    if read_only is not None and type(read_only) is not bool:
        raise EvidenceError("INVALID_AWS_RECORD")
    for field in ("errorCode", "errorMessage"):
        if field in record and not isinstance(record[field], (str, type(None))):
            raise EvidenceError("INVALID_AWS_RECORD")
    session, reason = _session(record, region, event_time)
    return AwsEvent(
        (account, region, event_id.lower()),
        event_time,
        source,
        name,
        category,
        event_type,
        read_only,
        "errorCode" in record or "errorMessage" in record,
        session,
        reason,
        canonical,
        record_hash,
        position,
    )


def parse_aws_shaped(data: bytes, scope: AwsScope, *, limits: Limits = _DEFAULT_LIMITS) -> AwsLog:
    """Parse only an AWS Records envelope; authenticity requires separate evidence."""
    if not isinstance(data, bytes):
        raise EvidenceError("INVALID_INPUT_TYPE")
    if not isinstance(scope, AwsScope):
        raise EvidenceError("INVALID_AWS_SCOPE")
    if type(limits) is not Limits:
        raise EvidenceError("INVALID_LIMITS")
    content = _expand(data, limits)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise EvidenceError("INVALID_UTF8") from None
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
        raise EvidenceError("INVALID_JSON") from None
    _check_tree(document, limits)
    if not isinstance(document, dict) or set(document) != {"Records"}:
        raise EvidenceError("INVALID_AWS_ENVELOPE")
    records = document["Records"]
    if not isinstance(records, list):
        raise EvidenceError("INVALID_RECORDS")
    if len(records) > limits.max_records:
        raise EvidenceError("RECORD_LIMIT")
    events: list[AwsEvent] = []
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            raise EvidenceError("INVALID_AWS_RECORD")
        events.append(_event(record, scope, position))
    return AwsLog(
        data,
        content,
        hashlib.sha256(data).hexdigest(),
        hashlib.sha256(content).hexdigest(),
        tuple(events),
    )
