"""AWS-shaped test data generated in memory, never real account or credential material."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def scope(**changes: Any) -> AwsScope:
    account = "1" * 12
    region = "us-east-1"
    root = f"offline-lab/AWSLogs/{account}/"
    values: dict[str, Any] = {
        "account": account,
        "region": region,
        "role_arn": f"arn:aws:iam::{account}:role/OfflineCollector",
        "role_id": "AROA" + "A" * 17,
        "trail_arn": f"arn:aws:cloudtrail:{region}:{account}:trail/offline-lab",
        "bucket": "offline-evidence-lab",
        "log_prefix": f"{root}CloudTrail/{region}/",
        "digest_prefix": f"{root}CloudTrail-Digest/{region}/",
    }
    values.update(changes)
    return AwsScope(**values)


def event(
    event_id: str | None = None,
    seconds: int = 0,
    *,
    account: str | None = None,
    region: str = "us-east-1",
    actor_account: str | None = None,
    role: str = "ObservedRole",
    key: str | None = None,
    session_name: str = "offline-session",
    creation: str = "2025-12-31T23:00:00Z",
) -> dict[str, Any]:
    account = account if account is not None else "1" * 12
    actor_account = actor_account if actor_account is not None else account
    role_id = "AROA" + "B" * 17
    return {
        "eventVersion": "1.11",
        "eventID": event_id or "aaaaaaaa-bbbb-4ccc-8ddd-" + "e" * 12,
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
            "principalId": f"{role_id}:{session_name}",
            "arn": f"arn:aws:sts::{actor_account}:assumed-role/{role}/{session_name}",
            "accountId": actor_account,
            "accessKeyId": key if key is not None else "ASIA" + "A" * 16,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role_id,
                    "arn": f"arn:aws:iam::{actor_account}:role/{role}",
                    "accountId": actor_account,
                    "userName": role.rsplit("/", 1)[-1],
                },
                "attributes": {"creationDate": creation, "mfaAuthenticated": "false"},
            },
        },
    }


def archive(records: list[dict[str, Any]] | None = None, **extra: Any) -> bytes:
    content = json.dumps(
        {"Records": [event()] if records is None else records, **extra},
        separators=(",", ":"),
    ).encode("utf-8")
    return gzip.compress(content, mtime=0)
