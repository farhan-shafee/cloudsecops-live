"""Synthetic inputs; expectations belong in tests, never derive from production."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def event(
    event_id: str,
    seconds: int = 0,
    *,
    account: str = "LABACCOUNT_A",
    region: str = "us-east-1",
    role: str = "InventoryLab",
    key: str = "SYNTHETIC_KEY_A",
    session_name: str = "lab-session",
    creation: str = "2025-12-31T23:00:00Z",
) -> dict[str, Any]:
    """Build an explicit fake CloudTrail-style record, without AWS credentials."""
    return {
        "eventVersion": "1.11",
        "eventID": event_id,
        "eventTime": (BASE_TIME + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": region,
        "recipientAccountId": account,
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "readOnly": True,
        "requestParameters": {},
        "responseElements": None,
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"SYNTHETIC_ROLE_A:{session_name}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session_name}",
            "accountId": account,
            "accessKeyId": key,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "SYNTHETIC_ROLE_A",
                    "arn": f"arn:aws:iam::{account}:role/{role}",
                    "accountId": account,
                    "userName": role,
                },
                "attributes": {"creationDate": creation, "mfaAuthenticated": "false"},
            },
        },
    }


def envelope(records: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "fixture_schema_version": "1.0",
        "source_kind": "synthetic",
        "Records": records,
        **extra,
    }


def content(records: list[dict[str, Any]], **extra: Any) -> bytes:
    return json.dumps(envelope(records, **extra), separators=(",", ":")).encode("utf-8")


def archive(records: list[dict[str, Any]], **extra: Any) -> bytes:
    return gzip.compress(content(records, **extra), mtime=0)
