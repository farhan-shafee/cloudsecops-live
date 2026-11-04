"""Generated, fictional AWS3 wire tapes; no credentials or network clients."""

import base64
import gzip
from dataclasses import asdict
from datetime import timedelta
from hashlib import sha256

from cloudsecops_live.integrations.aws_readiness.sessions import (
    CredentialSource,
    ExpectedIdentity,
    MfaObservation,
    PeerIdentity,
    Purpose,
    SessionIssuance,
    StsObservation,
)
from cloudsecops_live.integrations.aws_runner.contracts import BudgetPolicy
from tests.aws_helpers import BASE_TIME, archive, scope


def record(operation, parameters, response, *, fault="none"):
    return {"operation": operation, "parameters": parameters, "response": response, "fault": fault}


def response(**fields):
    return {**fields, "ResponseMetadata": {"HTTPStatusCode": 200}}


def metadata(purpose="posture"):
    name = {
        "posture": "OfflineInspector",
        "collector": "OfflineCollector",
        "verifier": "OfflineVerifier",
    }[purpose]
    role_id = "AROA" + {"posture": "P", "collector": "A", "verifier": "V"}[purpose] * 17
    account = "1" * 12
    roles = {
        "posture": ("OfflineInspector", "P"),
        "collector": ("OfflineCollector", "A"),
        "verifier": ("OfflineVerifier", "V"),
    }
    peers = (
        ()
        if purpose == "posture"
        else tuple(
            PeerIdentity(
                f"arn:aws:iam::{account}:role/{peer_name}",
                "AROA" + letter * 17,
                Purpose(peer_purpose),
            )
            for peer_purpose, (peer_name, letter) in roles.items()
            if peer_purpose != purpose
        )
    )
    expected = ExpectedIdentity(
        account,
        "us-east-1",
        f"arn:aws:iam::{account}:role/{name}",
        role_id,
        f"arn:aws:sts::{account}:assumed-role/{name}/offline",
        Purpose(purpose),
        peers,
    )
    issuance = SessionIssuance(
        BASE_TIME - timedelta(minutes=1),
        BASE_TIME + timedelta(minutes=5),
        CredentialSource.OWNER_SUPPLIED_TEMPORARY_SESSION,
        "controlled_offline_fixture",
        True,
        MfaObservation(True, "controlled_offline_fixture", BASE_TIME - timedelta(seconds=1)),
        access_key_id="ASIA" + "Q" * 16,
    )
    observed = StsObservation(account, expected.assumed_role_arn, role_id + ":offline", BASE_TIME)
    return {
        "expected": expected.to_metadata(),
        "issuance": issuance.to_metadata(),
        "observed": observed.to_metadata(),
        "as_of": BASE_TIME.isoformat(),
        "budget": asdict(BudgetPolicy()),
        "tape": [],
    }


def posture_metadata():
    data = metadata()
    expected = data["expected"]
    name = "OfflineInspector"
    data["inline_policy_names"] = ["OfflineReviewedPolicy"]
    data["tape"] = [
        record(
            "sts:GetCallerIdentity",
            {},
            response(
                Account=expected["account"],
                Arn=expected["assumed_role_arn"],
                UserId=expected["role_id"] + ":offline",
            ),
        ),
        record(
            "iam:GetRole",
            {"RoleName": name},
            response(Role={"Arn": expected["role_arn"], "RoleId": expected["role_id"]}),
        ),
        record(
            "iam:ListRolePolicies",
            {"RoleName": name},
            response(PolicyNames=["OfflineReviewedPolicy"], IsTruncated=False),
        ),
        record(
            "iam:GetRolePolicy",
            {"RoleName": name, "PolicyName": "OfflineReviewedPolicy"},
            response(
                RoleName=name,
                PolicyName="OfflineReviewedPolicy",
                PolicyDocument={"Version": "2012-10-17", "Statement": []},
            ),
        ),
        record(
            "iam:ListAttachedRolePolicies",
            {"RoleName": name},
            response(AttachedPolicies=[], IsTruncated=False),
        ),
        record("cloudtrail:ListTrails", {}, response(Trails=[])),
        record("s3:ListBuckets", {}, response(Buckets=[])),
        record(
            "s3control:GetPublicAccessBlock",
            {"AccountId": expected["account"]},
            response(
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            ),
        ),
    ]
    return data


def archive_metadata(purpose="collector"):
    data = metadata(purpose)
    expected = data["expected"]
    archive_scope = scope(role_arn=expected["role_arn"], role_id=expected["role_id"])
    data["scope"] = asdict(archive_scope)
    data["checkpoint"] = "offline-readiness"
    raw = archive()
    key = archive_scope.log_prefix + "2026/01/01/log.json.gz"
    ref = {
        "bucket": archive_scope.bucket,
        "key": key,
        "version_id": "offline-v1",
        "size": len(raw),
        "last_modified": BASE_TIME.isoformat(),
        "is_delete_marker": False,
        "is_latest": True,
    }
    base = {"Bucket": archive_scope.bucket, "ExpectedBucketOwner": archive_scope.account}
    head = {**base, "Key": key}
    data["tape"] = [
        record(
            "sts:GetCallerIdentity",
            {},
            response(
                Account=expected["account"],
                Arn=expected["assumed_role_arn"],
                UserId=expected["role_id"] + ":offline",
            ),
        ),
        record(
            "s3:ListObjectVersions",
            {**base, "Prefix": archive_scope.log_prefix, "MaxKeys": 64},
            response(versions=[ref], truncated=False, next_marker=None),
        ),
        record("s3:HeadObject", head, response(version_id="offline-v1")),
        record(
            "s3:GetObject",
            {**head, "VersionId": "offline-v1"},
            response(
                reference=ref,
                owner_account=archive_scope.account,
                body_base64=base64.b64encode(raw).decode(),
            ),
        ),
        record("s3:HeadObject", head, response(version_id="offline-v1")),
        record("s3:HeadObject", head, response(version_id="offline-v1")),
    ]
    if purpose == "verifier":
        data["expected_content_hashes"] = [sha256(gzip.decompress(raw)).hexdigest()]
    return data
