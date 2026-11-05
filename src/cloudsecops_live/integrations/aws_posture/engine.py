"""Fixed eight-operation posture engine for controlled, unauthenticated tests.

This internal engine accepts trusted-code clients, never a request-selected
factory. The separate public worker remains disabled before it can call this
engine or acquire a credential capability. Matching observations prove neither
effective IAM nor signed-source authenticity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_posture.budget import PostureBudget
from cloudsecops_live.integrations.aws_posture.contracts import OwnerDecision, PostureClients
from cloudsecops_live.integrations.aws_readiness.requests import encode
from cloudsecops_live.integrations.aws_readiness.sessions import BoundSession

_TRANSIENT = frozenset(
    {
        "RequestTimeout",
        "RequestTimeoutException",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "InternalError",
        "InternalFailure",
        "InternalServerError",
    }
)
_NETWORK = (ConnectionClosedError, ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError)
_FIELDS = {
    "GetCallerIdentity": {"Account", "Arn", "UserId", "ResponseMetadata"},
    "GetRole": {"Role", "ResponseMetadata"},
    "ListRolePolicies": {"PolicyNames", "IsTruncated", "Marker", "ResponseMetadata"},
    "GetRolePolicy": {"RoleName", "PolicyName", "PolicyDocument", "ResponseMetadata"},
    "ListAttachedRolePolicies": {"AttachedPolicies", "IsTruncated", "Marker", "ResponseMetadata"},
    "ListTrails": {"Trails", "NextToken", "ResponseMetadata"},
    "ListBuckets": {"Buckets", "Owner", "ContinuationToken", "ResponseMetadata"},
    "GetPublicAccessBlock": {"PublicAccessBlockConfiguration", "ResponseMetadata"},
}


def _retryable(error: Exception) -> bool:
    if isinstance(error, _NETWORK):
        return True
    if not isinstance(error, ClientError):
        return False
    value = error.response
    return (
        type(value) is dict
        and type(value.get("Error")) is dict
        and type(value["Error"].get("Code")) is str
        and value["Error"]["Code"] in _TRANSIENT
        and type(value.get("ResponseMetadata")) is dict
        and type(value["ResponseMetadata"].get("HTTPStatusCode")) is int
        and value["ResponseMetadata"]["HTTPStatusCode"] in (400, 408, 429, 500, 502, 503, 504)
    )


def _json_value(value: object) -> object:
    """Copy bounded SDK trees without serialization hooks, then preflight bytes."""
    nodes = 0

    def convert(item: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if depth > 24 or nodes > 30_000:
            raise EvidenceError("AWS4A_RESPONSE")
        if type(item) is dict:
            if len(item) > 30_000 - nodes:
                raise EvidenceError("AWS4A_RESPONSE")
            output: dict[str, object] = {}
            for key, child in item.items():
                if (
                    type(key) is not str
                    or "\x00" in key
                    or any(0xD800 <= ord(char) <= 0xDFFF for char in key)
                ):
                    raise EvidenceError("AWS4A_RESPONSE")
                output[key] = convert(child, depth + 1)
            return output
        if type(item) is list:
            if len(item) > 30_000 - nodes:
                raise EvidenceError("AWS4A_RESPONSE")
            return [convert(child, depth + 1) for child in item]
        if type(item) is datetime:
            return item.isoformat()
        if type(item) is str:
            if "\x00" in item or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise EvidenceError("AWS4A_RESPONSE")
        elif type(item) not in (int, float, bool, type(None)):
            raise EvidenceError("AWS4A_RESPONSE")
        return item

    result = convert(value, 0)
    # Existing encode independently preflights escaped strings, scalar tokens,
    # node count and aggregate bytes before its bounded JSON allocation.
    encode(result)
    return result


class _Inspection:
    def __init__(
        self,
        decision: OwnerDecision,
        session: BoundSession,
        clients: PostureClients,
        budget: PostureBudget,
    ) -> None:
        self.decision, self.session, self.clients, self.budget = decision, session, clients, budget
        self.role_name = decision.expected.role_arn.rsplit("/", 1)[-1]

    def read(
        self, service: str, operation: str, action: Callable[..., Any], params: dict[str, object]
    ) -> dict[str, Any]:
        retry = False
        while True:
            self.budget.before_call(service, operation, params, retry=retry)
            try:
                result = action(**params)
            except Exception as error:
                self.budget.check()
                if _retryable(error):
                    retry = True
                    continue
                raise EvidenceError("AWS4A_SERVICE_REJECTED") from None
            self.budget.check()
            bounded = _json_value(result)
            self.budget.consume_response_bytes(len(encode(bounded)))
            if type(result) is not dict or not set(result) <= _FIELDS[operation]:
                raise EvidenceError("AWS4A_RESPONSE")
            metadata = result.get("ResponseMetadata")
            if (
                type(metadata) is not dict
                or not set(metadata)
                <= {
                    "HTTPStatusCode",
                    "RequestId",
                    "HTTPHeaders",
                    "RetryAttempts",
                    "MaxAttemptsReached",
                }
                or type(metadata.get("HTTPStatusCode")) is not int
                or metadata["HTTPStatusCode"] != 200
                or type(metadata.get("RetryAttempts")) is not int
                or metadata["RetryAttempts"] != 0
                or "MaxAttemptsReached" in metadata
                and type(metadata["MaxAttemptsReached"]) is not bool
            ):
                raise EvidenceError("AWS4A_RESPONSE")
            return dict(result)

    def identity(self) -> None:
        result = self.read("sts", "GetCallerIdentity", self.clients.sts.get_caller_identity, {})
        if (result.get("Account"), result.get("Arn"), result.get("UserId")) != (
            self.decision.expected.account,
            self.session.lease.principal_arn,
            self.session.lease.user_id,
        ):
            raise EvidenceError("AWS4A_STS_IDENTITY")

    def role(self) -> None:
        result = self.read(
            "iam", "GetRole", self.clients.iam.get_role, {"RoleName": self.role_name}
        )
        role = result.get("Role")
        if (
            type(role) is not dict
            or not set(role)
            <= {
                "Arn",
                "RoleId",
                "RoleName",
                "Path",
                "CreateDate",
                "AssumeRolePolicyDocument",
                "Description",
                "MaxSessionDuration",
                "Tags",
                "RoleLastUsed",
            }
            or (role.get("Arn"), role.get("RoleId"), role.get("RoleName"))
            != (self.decision.expected.role_arn, self.decision.expected.role_id, self.role_name)
        ):
            raise EvidenceError("AWS4A_ROLE_IDENTITY")

    def pages(
        self,
        service: str,
        operation: str,
        action: Callable[..., Any],
        params: dict[str, object],
        field: str,
        token: str,
    ) -> list[Any]:
        output: list[Any] = []
        seen: set[str] = set()
        while True:
            result = self.read(service, operation, action, params)
            items = result.get(field)
            if type(items) is not list or len(items) + len(output) > 64:
                raise EvidenceError("AWS4A_PAGINATION")
            output.extend(items)
            following = result.get(token)
            if token in result and following is None:
                raise EvidenceError("AWS4A_PAGINATION")
            if service == "iam":
                truncated = result.get("IsTruncated")
                if type(truncated) is not bool or truncated != (following is not None):
                    raise EvidenceError("AWS4A_PAGINATION")
            if following is None:
                return output
            if (
                type(following) is not str
                or not 1 <= len(following) <= 1024
                or any(not 32 <= ord(char) < 127 for char in following)
                or following in seen
            ):
                raise EvidenceError("AWS4A_PAGINATION")
            seen.add(following)
            params = {**params, token: following}

    def policies(self) -> None:
        params: dict[str, object] = {"RoleName": self.role_name, "MaxItems": 64}
        names = self.pages(
            "iam",
            "ListRolePolicies",
            self.clients.iam.list_role_policies,
            params,
            "PolicyNames",
            "Marker",
        )
        if (
            any(type(name) is not str for name in names)
            or len(names) != len(set(names))
            or set(names) != {item.name for item in self.decision.inline_policies}
        ):
            raise EvidenceError("AWS4A_POLICY_BINDING")
        for policy in self.decision.inline_policies:
            result = self.read(
                "iam",
                "GetRolePolicy",
                self.clients.iam.get_role_policy,
                {"RoleName": self.role_name, "PolicyName": policy.name},
            )
            document = result.get("PolicyDocument")
            if (
                result.get("RoleName") != self.role_name
                or result.get("PolicyName") != policy.name
                or type(document) is not dict
            ):
                raise EvidenceError("AWS4A_POLICY_BINDING")
            encode(document)
            canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != policy.sha256:
                raise EvidenceError("AWS4A_POLICY_BINDING")
        attached = self.pages(
            "iam",
            "ListAttachedRolePolicies",
            self.clients.iam.list_attached_role_policies,
            params,
            "AttachedPolicies",
            "Marker",
        )
        if attached:
            raise EvidenceError("AWS4A_POLICY_BINDING")

    def inventory(self) -> tuple[int, int]:
        trails = self.pages(
            "cloudtrail",
            "ListTrails",
            self.clients.cloudtrail.list_trails,
            {},
            "Trails",
            "NextToken",
        )
        trail_ids: set[str] = set()
        for item in trails:
            if type(item) is not dict or not set(item) <= {"TrailARN", "Name", "HomeRegion"}:
                raise EvidenceError("AWS4A_INVENTORY")
            arn = item.get("TrailARN")
            if (
                type(arn) is not str
                or re.fullmatch(
                    r"arn:aws:cloudtrail:[a-z0-9-]+:"
                    + self.decision.expected.account
                    + r":trail/[A-Za-z0-9._/-]+",
                    arn,
                )
                is None
                or arn in trail_ids
            ):
                raise EvidenceError("AWS4A_INVENTORY")
            trail_ids.add(arn)
        buckets = self.pages(
            "s3",
            "ListBuckets",
            self.clients.s3.list_buckets,
            {"MaxBuckets": 64},
            "Buckets",
            "ContinuationToken",
        )
        bucket_ids: set[str] = set()
        for item in buckets:
            if type(item) is not dict or not set(item) <= {
                "Name",
                "CreationDate",
                "BucketRegion",
                "BucketArn",
            }:
                raise EvidenceError("AWS4A_INVENTORY")
            name = item.get("Name")
            if (
                type(name) is not str
                or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name) is None
                or name in bucket_ids
            ):
                raise EvidenceError("AWS4A_INVENTORY")
            bucket_ids.add(name)
        return len(trails), len(buckets)

    def account(self) -> None:
        result = self.read(
            "s3control",
            "GetPublicAccessBlock",
            self.clients.s3control.get_public_access_block,
            {"AccountId": self.decision.expected.account},
        )
        configuration = result.get("PublicAccessBlockConfiguration")
        if (
            type(configuration) is not dict
            or set(configuration)
            != {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}
            or any(value is not True for value in configuration.values())
        ):
            raise EvidenceError("AWS4A_ACCOUNT_POSTURE")


def inspect_posture(
    decision: OwnerDecision,
    session: BoundSession,
    clients: PostureClients,
    *,
    clock: Callable[[], datetime],
    monotonic: Callable[[], float],
    budget: PostureBudget | None = None,
) -> dict[str, object]:
    if type(clients) is not PostureClients:
        raise EvidenceError("AWS4A_CLIENTS")
    meter = (
        budget
        if budget is not None
        else PostureBudget(decision, session, clock=clock, monotonic=monotonic)
    )
    if (
        type(meter) is not PostureBudget
        or meter.decision is not decision
        or meter.session is not session
    ):
        raise EvidenceError("AWS4A_BUDGET_BINDING")
    try:
        meter.check()
        inspector = _Inspection(decision, session, clients, meter)
        inspector.identity()
        inspector.role()
        inspector.policies()
        trails, buckets = inspector.inventory()
        inspector.account()
        # These observed rereads detect drift; they are not an atomic IAM snapshot.
        inspector.policies()
        inspector.role()
        inspector.identity()
        meter.check()
        return {
            "schema_version": "aws4a-posture-observation/1",
            "state": "offline_posture_observation",
            "execution_state": "disabled",
            "source_kind": "aws_shaped_unverified",
            "trail_count": trails,
            "bucket_count": buckets,
            "inline_policy_count": len(decision.inline_policies),
            "account_public_access_block_all_enabled": True,
            "effective_permissions_verified": False,
            "signed_source_authentication_available": False,
            "authenticated": False,
            "trusted_findings_available": False,
            "closure_available": False,
            "budget": meter.public_dict(),
        }
    except Exception:
        meter.invalidate()
        raise
