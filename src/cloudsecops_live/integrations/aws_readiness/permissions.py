"""Fixed offline operation profiles and a non-deploying inspection-policy contract.

These literal source contracts do not evaluate effective IAM or authenticate AWS
observations. No SDK client, credential source, policy application or network path
is available here. The existing named worker dispatch remains the execution boundary.
"""

import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Literal

from cloudsecops_live.errors import EvidenceError

PurposeName = Literal["posture", "collector", "verifier"]
Operation = tuple[str, str]

POSTURE_OPERATIONS = frozenset(
    {
        ("sts", "GetCallerIdentity"),
        ("cloudtrail", "ListTrails"),
        ("s3", "ListBuckets"),
        ("s3control", "GetPublicAccessBlock"),
        ("iam", "GetRole"),
        ("iam", "ListRolePolicies"),
        ("iam", "GetRolePolicy"),
        ("iam", "ListAttachedRolePolicies"),
    }
)
COLLECTOR_OPERATIONS = frozenset(
    {
        ("sts", "GetCallerIdentity"),
        ("cloudtrail", "GetTrail"),
        ("cloudtrail", "GetTrailStatus"),
        ("cloudtrail", "GetEventSelectors"),
        ("cloudtrail", "GetInsightSelectors"),
        ("cloudtrail", "ListPublicKeys"),
        ("s3", "ListObjectsV2"),
        ("s3", "ListObjectVersions"),
        ("s3", "GetBucketLocation"),
        ("s3", "HeadObject"),
        ("s3", "GetObject"),
    }
)
VERIFIER_OPERATIONS = COLLECTOR_OPERATIONS | frozenset(
    {
        ("iam", "GetRole"),
        ("iam", "ListRolePolicies"),
        ("iam", "GetRolePolicy"),
        ("iam", "ListAttachedRolePolicies"),
        ("s3", "GetBucketAcl"),
        ("s3", "GetBucketPolicy"),
        ("s3", "GetPublicAccessBlock"),
        ("s3", "GetBucketOwnershipControls"),
        ("s3", "GetBucketEncryption"),
        ("s3", "GetBucketVersioning"),
        ("s3", "GetBucketLifecycleConfiguration"),
        ("cloudtrail", "LookupEvents"),
    }
)
OPERATION_PROFILES: Mapping[str, frozenset[Operation]] = MappingProxyType(
    {
        "posture": POSTURE_OPERATIONS,
        "collector": COLLECTOR_OPERATIONS,
        "verifier": VERIFIER_OPERATIONS,
    }
)

POSTURE_ACTIONS = frozenset(
    {
        "sts:GetCallerIdentity",
        "cloudtrail:ListTrails",
        "s3:ListAllMyBuckets",
        "s3:GetAccountPublicAccessBlock",
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
    }
)
COLLECTOR_ACTIONS = frozenset(
    {
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetInsightSelectors",
        "cloudtrail:ListPublicKeys",
        "sts:GetCallerIdentity",
    }
)
VERIFIER_ACTIONS = COLLECTOR_ACTIONS | frozenset(
    {
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketOwnershipControls",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "cloudtrail:LookupEvents",
    }
)
ACTION_PROFILES: Mapping[str, frozenset[str]] = MappingProxyType(
    {"posture": POSTURE_ACTIONS, "collector": COLLECTOR_ACTIONS, "verifier": VERIFIER_ACTIONS}
)

INSPECTION_ROLE_PLACEHOLDER = (
    "arn:aws:iam::${INSPECTION_ACCOUNT_ID}:role/${INSPECTION_ROLE_PATH_AND_NAME}"
)
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+", re.ASCII)
_POLICY_LIMIT = 64 * 1024


def require_operation(purpose: str, service: str, operation: str) -> None:
    """Reject cross-purpose operations before any data-only tape is consumed."""
    if not isinstance(purpose, str) or purpose not in OPERATION_PROFILES:
        raise EvidenceError("AWS3_PERMISSION_PURPOSE")
    if (
        not isinstance(service, str)
        or not isinstance(operation, str)
        or (service, operation) not in OPERATION_PROFILES[purpose]
    ):
        raise EvidenceError("AWS3_PERMISSION_OPERATION")


def _role_account(inspection_role_arn: str) -> str:
    if inspection_role_arn == INSPECTION_ROLE_PLACEHOLDER:
        return "${INSPECTION_ACCOUNT_ID}"
    if not isinstance(inspection_role_arn, str) or len(inspection_role_arn) > 512:
        raise EvidenceError("AWS3_PERMISSION_ROLE")
    match = _ROLE.fullmatch(inspection_role_arn)
    if match is None or inspection_role_arn.endswith("/"):
        raise EvidenceError("AWS3_PERMISSION_ROLE")
    return match.group(1)


def posture_policy(
    inspection_role_arn: str = INSPECTION_ROLE_PLACEHOLDER,
) -> dict[str, Any]:
    """Return a fresh template/private binding; never apply or authorize it."""
    account = _role_account(inspection_role_arn)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ObserveCallerIdentity",
                "Effect": "Allow",
                "Action": ["sts:GetCallerIdentity"],
                "Resource": "*",
            },
            {
                "Sid": "RegionalTrailInventory",
                "Effect": "Allow",
                "Action": ["cloudtrail:ListTrails"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            },
            {
                "Sid": "BucketInventory",
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets"],
                "Resource": "*",
            },
            {
                "Sid": "AccountPublicAccessPosture",
                "Effect": "Allow",
                "Action": ["s3:GetAccountPublicAccessBlock"],
                "Resource": "*",
                "Condition": {"StringEquals": {"s3:ResourceAccount": account}},
            },
            {
                "Sid": "InspectExactRoleMetadata",
                "Effect": "Allow",
                "Action": [
                    "iam:GetRole",
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy",
                    "iam:ListAttachedRolePolicies",
                ],
                "Resource": inspection_role_arn,
            },
            {
                "Sid": "DenyOtherActions",
                "Effect": "Deny",
                "NotAction": sorted(POSTURE_ACTIONS),
                "Resource": "*",
            },
        ],
    }


def validate_posture_policy(
    document: object, inspection_role_arn: str = INSPECTION_ROLE_PLACEHOLDER
) -> None:
    """Require the complete literal source contract, not a partial action subset."""
    expected = posture_policy(inspection_role_arn)
    if type(document) is not dict:
        raise EvidenceError("AWS3_PERMISSION_POLICY")
    try:
        options: dict[str, Any] = {
            "sort_keys": True,
            "separators": (",", ":"),
            "allow_nan": False,
        }
        actual = json.dumps(document, **options)
        wanted = json.dumps(expected, **options)
        if len(actual.encode("utf-8")) > _POLICY_LIMIT or actual != wanted:
            raise EvidenceError("AWS3_PERMISSION_POLICY")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise EvidenceError("AWS3_PERMISSION_POLICY") from exc
