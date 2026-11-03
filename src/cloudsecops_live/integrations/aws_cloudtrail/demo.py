"""Deterministic in-memory AWS-shaped exercise; no AWS client exists here."""

import gzip
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CallerIdentity,
    MemoryLedger,
    ObjectBody,
    ObjectVersion,
    VersionPage,
    collect,
    require_authenticated,
)
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_cloudtrail.validation import (
    CheckOutcome,
    ControlledValidation,
    DigestMember,
    assess_digest,
)

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class DemoTransport:
    """Literal fake service, with no credential or network configuration hooks."""

    def __init__(self) -> None:
        account = "1" * 12
        root = f"offline-lab/AWSLogs/{account}/"
        self.scope = AwsScope(
            account,
            "us-east-1",
            f"arn:aws:iam::{account}:role/OfflineCollector",
            "AROA" + "A" * 17,
            f"arn:aws:cloudtrail:us-east-1:{account}:trail/offline-lab",
            "offline-evidence-lab",
            root + "CloudTrail/us-east-1/",
            root + "CloudTrail-Digest/us-east-1/",
        )
        records = []
        for index in range(3):
            records.append(
                {
                    "eventID": f"aaaaaaaa-bbbb-4ccc-8ddd-{index:012x}",
                    "eventVersion": "1.11",
                    "eventTime": (_NOW + timedelta(seconds=30 * index))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "eventSource": "ec2.amazonaws.com",
                    "eventName": "DescribeInstances",
                    "eventCategory": "Management",
                    "eventType": "AwsApiCall",
                    "readOnly": True,
                    "recipientAccountId": account,
                    "awsRegion": "us-east-1",
                    "responseElements": None,
                    "userIdentity": {
                        "type": "AssumedRole",
                        "accountId": account,
                        "principalId": "AROA" + "B" * 17 + ":offline",
                        "arn": f"arn:aws:sts::{account}:assumed-role/ObservedRole/offline",
                        "accessKeyId": "ASIA" + "A" * 16,
                        "sessionContext": {
                            "sessionIssuer": {
                                "type": "Role",
                                "accountId": account,
                                "principalId": "AROA" + "B" * 17,
                                "arn": f"arn:aws:iam::{account}:role/ObservedRole",
                            },
                            "attributes": {"creationDate": "2025-12-31T23:00:00Z"},
                        },
                    },
                }
            )
        self.data = gzip.compress(
            json.dumps({"Records": records}, separators=(",", ":")).encode(), mtime=0
        )
        self.ref = ObjectVersion(
            self.scope.bucket,
            self.scope.log_prefix + "2026/01/01/demo.json.gz",
            "offline-version-one",
            len(self.data),
            _NOW,
        )

    def caller_identity(self) -> CallerIdentity:
        return CallerIdentity(
            self.scope.account,
            self.scope.region,
            f"arn:aws:sts::{self.scope.account}:assumed-role/OfflineCollector/offline",
            self.scope.role_id + ":offline",
            _NOW,
            _NOW + timedelta(minutes=5),
        )

    def list_versions(
        self, expected: AwsScope, prefix: str, marker: tuple[str, str] | None
    ) -> VersionPage:
        return VersionPage(True, (self.ref,), False, None)

    def head_current(self, ref: ObjectVersion) -> str:
        return self.ref.version_id

    def get_object(self, ref: ObjectVersion, max_bytes: int) -> ObjectBody:
        return ObjectBody(self.ref, self.scope.account, BytesIO(self.data))


def main() -> int:
    fake = DemoTransport()
    batch = collect(fake, fake.scope, MemoryLedger(), "offline-demo", clock=lambda: _NOW)
    obj = batch.objects[0]
    controlled = ControlledValidation(
        "controlled-offline-fixture",
        0,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        CheckOutcome.VALID,
        (
            DigestMember(
                obj.reference.bucket,
                obj.reference.key,
                obj.reference.version_id,
                obj.log.content_sha256,
            ),
        ),
        True,
        True,
    )
    assessment = assess_digest(obj, controlled)
    report = batch.to_public_dict()
    report["controlled_digest_consistency"] = assessment.consistency_passed
    try:
        require_authenticated(assessment)
    except EvidenceError as error:
        report["authentication_gate"] = error.code
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0
