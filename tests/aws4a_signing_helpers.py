"""Fictional real-SDK signing scenarios with a strict fake HTTP boundary."""

from dataclasses import dataclass, field, replace
from datetime import datetime
from io import BytesIO

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest, AWSResponse
from botocore.credentials import Credentials

from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_posture.clients import (
    build_fixed_clients,
    packaged_ca_sha256,
)
from cloudsecops_live.integrations.aws_posture.wire import BoundedReader
from cloudsecops_live.integrations.aws_readiness.sessions import assemble_session
from tests.aws4a_helpers import NOW, decision, session

SERVICES = ("sts", "iam", "cloudtrail", "s3", "s3control")


def header_text(value):
    return value.decode("ascii") if isinstance(value, bytes) else value


def alternative_credentials(*, same_key=False):
    return Credentials(
        "ASIA" + ("Q" if same_key else "Z") * 16,
        "fictional-signing-alternative-secret-never-valid",
        "fictional-signing-alternative-token-never-valid",
        method="explicit",
    )


def resign(request, credentials, service):
    """Exercise actual pinned SigV4 code without discovery or network access."""
    headers = {name: header_text(value) for name, value in request.headers.items()}
    authorization = headers["Authorization"]
    original_signed = authorization.split("SignedHeaders=", 1)[1].split(",", 1)[0]
    # Preparation adds unsigned Content-Length/User-Agent. Excluding those
    # preserves the original SDK auth shape so secret-only attacks exercise
    # signature verification instead of failing earlier membership validation.
    selected = {
        name: value
        for name, value in headers.items()
        if name.casefold() in original_signed.split(";")
    }
    signed = AWSRequest(method=request.method, url=request.url, data=request.body, headers=selected)
    original = authorization.split("Credential=", 1)[1].split(",", 1)[0]
    scope = original.split("/")
    signing = S3SigV4Auth if service == "s3" else SigV4Auth
    signing(credentials, scope[3], scope[2]).add_auth(signed)
    new_signed = signed.headers["Authorization"].split("SignedHeaders=", 1)[1].split(",", 1)[0]
    assert new_signed == original_signed, (
        "alternate signer must preserve exact SDK header membership"
    )
    request.headers["Authorization"] = signed.headers["Authorization"]
    request.headers["X-Amz-Security-Token"] = signed.headers["X-Amz-Security-Token"]


class Raw:
    def __init__(self, body, budget):
        self.reader = BoundedReader(BytesIO(body), budget)

    def stream(self, amt=8192, decode_content=False):
        while part := self.reader.read(amt):
            yield part


@dataclass(repr=False)
class SigningCase:
    service: str
    now: datetime = field(default=NOW, repr=False)
    fractional_start: bool = field(default=False, repr=False)
    owner: object = field(init=False, repr=False)
    bound: object = field(init=False, repr=False)
    budget: object = field(init=False, repr=False)
    clients: object = field(init=False, repr=False)
    client: object = field(init=False, repr=False)
    operation: str = field(init=False)
    params: dict = field(init=False, repr=False)
    method: object = field(init=False, repr=False)
    body: bytes = field(init=False, repr=False)
    sent: int = 0
    signing_service: str | None = None

    def __post_init__(self):
        overrides = {"window_start": self.now} if self.fractional_start else {}
        self.owner = decision(ca_sha256=packaged_ca_sha256(), **overrides)
        self.bound = session(self.owner, now=self.now)
        if self.fractional_start:
            issuance = replace(
                self.bound._issuance,
                issued_at=self.now,
                mfa=replace(self.bound._issuance.mfa, observed_at=self.now),
            )
            self.bound = assemble_session(
                self.owner.expected,
                issuance,
                self.bound._observed,
                self.bound.credentials,
                now=self.now,
            )
        self.budget = PostureBudget(
            self.owner, self.bound, clock=lambda: self.now, monotonic=lambda: 1.0
        )
        self.clients = build_fixed_clients(self.owner, self.bound, self.budget)
        self.client = getattr(self.clients, self.service)
        if self.service == "sts":
            self.operation, self.params = "GetCallerIdentity", {}
            self.method = self.client.get_caller_identity
            self.body = (
                "<GetCallerIdentityResponse><GetCallerIdentityResult>"
                f"<Account>{self.owner.expected.account}</Account>"
                f"<Arn>{self.bound.lease.principal_arn}</Arn>"
                f"<UserId>{self.bound.lease.user_id}</UserId>"
                "</GetCallerIdentityResult></GetCallerIdentityResponse>"
            ).encode()
        elif self.service == "iam":
            self.operation, self.params = "GetRole", {"RoleName": "OfflineInspector"}
            self.method = self.client.get_role
            self.body = (
                "<GetRoleResponse><GetRoleResult><Role>"
                f"<Arn>{self.owner.expected.role_arn}</Arn>"
                f"<RoleId>{self.owner.expected.role_id}</RoleId>"
                "<RoleName>OfflineInspector</RoleName>"
                "</Role></GetRoleResult></GetRoleResponse>"
            ).encode()
        elif self.service == "cloudtrail":
            self.operation, self.params = "ListTrails", {}
            self.method, self.body = self.client.list_trails, b'{"Trails":[]}'
        elif self.service == "s3":
            self.operation, self.params = "ListBuckets", {"MaxBuckets": 64}
            self.method = self.client.list_buckets
            self.body = b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"
        else:
            self.operation = "GetPublicAccessBlock"
            self.params = {"AccountId": self.owner.expected.account}
            self.method = self.client.get_public_access_block
            self.body = (
                b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>"
                b"<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy>"
                b"<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
            )
        self.client._endpoint.http_session._transport.send = self.fake_send

    def fake_send(self, request):
        self.sent += 1
        auth = header_text(request.headers.get("Authorization", ""))
        if "Credential=" in auth:
            credential = auth.split("Credential=", 1)[1].split(",", 1)[0]
            pieces = credential.split("/")
            self.signing_service = pieces[3] if len(pieces) > 3 else None
        return AWSResponse(request.url, 200, {}, Raw(self.body, self.budget))

    def handler(self, action):
        self.client.meta.events.register("before-send", action)

    def call(self, *, retry=False):
        self.budget.before_call(self.service, self.operation, self.params, retry=retry)
        return self.method(**self.params)

    def close(self):
        for name in SERVICES:
            getattr(self.clients, name).close()
