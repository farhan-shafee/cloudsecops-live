"""Generated AWS-shaped clients and byte streams; never credential discovery."""

from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from io import BytesIO
from types import SimpleNamespace

from botocore.config import Config
from botocore.credentials import Credentials

from cloudsecops_live.integrations.aws_cloudtrail.collection import ObjectVersion
from tests.aws_helpers import BASE_TIME, archive, scope

KEY_ID = "ASIA" + "Q" * 16
SECRET = (
    "generated-test-secret-never-real" + "Q" * 12
)  # pragma: allowlist secret - generated offline fixture, never an AWS credential
TOKEN = "generated-test-session-token-never-real"


class Events:
    def __init__(self):
        self.registered = []

    def register(self, name, handler, **kwargs):
        self.registered.append((name, handler))


class FakeClient:
    """SDK metadata plus explicit responses, with no network-capable endpoint."""

    def __init__(self, service, credentials, region="us-east-1"):
        self.meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name=service),
            region_name=region,
            endpoint_url=f"https://{service}.{region}.amazonaws.com",
            config=Config(
                connect_timeout=2,
                read_timeout=5,
                signature_version="s3v4" if service == "s3" else "v4",
                retries={"mode": "standard", "total_max_attempts": 1},
                proxies={},
                s3={"addressing_style": "path"} if service == "s3" else None,
            ),
            events=Events(),
        )
        self._request_signer = SimpleNamespace(_credentials=credentials)

        def unused_http_send(request):
            raise AssertionError("fake service operations must not send HTTP requests")

        self._endpoint = SimpleNamespace(
            http_session=SimpleNamespace(_verify=True, send=unused_http_send)
        )
        self.responses = {}
        self.calls = []

    def __getattr__(self, operation):
        if operation.startswith("_"):
            raise AttributeError(operation)

        def execute(**params):
            self.calls.append((operation, deepcopy(params)))
            response = self.responses[operation]
            if isinstance(response, Exception):
                raise response
            return response() if callable(response) else deepcopy(response)

        return execute


class Body(BytesIO):
    def __deepcopy__(self, memo):
        return self


def fixtures(**scope_changes):
    expected = scope(**scope_changes)
    credentials = Credentials(KEY_ID, SECRET, TOKEN, method="explicit")
    clients = {name: FakeClient(name, credentials) for name in ("sts", "s3", "cloudtrail")}
    clients["sts"].responses["get_caller_identity"] = {
        "Account": expected.account,
        "Arn": f"arn:aws:sts::{expected.account}:assumed-role/OfflineCollector/offline",
        "UserId": f"{expected.role_id}:offline",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    data = archive()
    reference = ObjectVersion(
        expected.bucket,
        expected.log_prefix + "2026/01/01/log.json.gz",
        "v-one",
        len(data),
        BASE_TIME,
    )
    clients["s3"].responses.update(
        list_object_versions={
            "Name": expected.bucket,
            "Prefix": expected.log_prefix,
            "IsTruncated": False,
            "Versions": [
                {
                    "Key": reference.key,
                    "VersionId": reference.version_id,
                    "Size": reference.size,
                    "LastModified": BASE_TIME,
                    "IsLatest": True,
                }
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        head_object={
            "VersionId": reference.version_id,
            "ContentLength": reference.size,
            "LastModified": BASE_TIME,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        get_object=lambda: {
            "VersionId": reference.version_id,
            "ContentLength": reference.size,
            "LastModified": BASE_TIME,
            "Body": Body(data),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
    )
    root = expected.log_prefix.removesuffix(
        f"AWSLogs/{expected.account}/CloudTrail/{expected.region}/"
    ).removesuffix("/")
    clients["cloudtrail"].responses.update(
        get_trail={
            "Trail": {
                "TrailARN": expected.trail_arn,
                "HomeRegion": expected.region,
                "S3BucketName": expected.bucket,
                "S3KeyPrefix": root,
                "IncludeGlobalServiceEvents": True,
                "LogFileValidationEnabled": True,
                "IsMultiRegionTrail": False,
                "IsOrganizationTrail": False,
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        get_trail_status={
            "IsLogging": True,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        get_event_selectors={
            "TrailARN": expected.trail_arn,
            "EventSelectors": [
                {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        get_insight_selectors={
            "TrailARN": expected.trail_arn,
            "InsightSelectors": [],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
    )
    lease = {
        "issued_at": BASE_TIME - timedelta(minutes=1),
        "expires_at": BASE_TIME + timedelta(minutes=5),
        "principal_arn": clients["sts"].responses["get_caller_identity"]["Arn"],
        "user_id": clients["sts"].responses["get_caller_identity"]["UserId"],
        "access_key_id": KEY_ID,
    }
    return expected, lease, clients, reference, data
