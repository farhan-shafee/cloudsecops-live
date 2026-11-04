"""Independent source security contracts, not effective IAM or live AWS proof.

Read the emitted JSON directly rather than importing the structural allowlist.
Expression-clause checks below do not evaluate HCL or replace Terraform validate.
"""

import gzip
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest

from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CallerIdentity,
    MemoryLedger,
    ObjectBody,
    ObjectVersion,
    VersionPage,
    collect,
)
from cloudsecops_live.integrations.aws_cloudtrail.models import AwsScope
from cloudsecops_live.integrations.aws_cloudtrail.parsing import parse_aws_shaped

SOURCE = Path(__file__).resolve().parents[1] / "infra/aws-offline/main.tf.json"
REGIONAL = {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
BUCKET_OWNER = {"StringEquals": {"s3:ResourceAccount": "${var.account_id}"}}
EVIDENCE_OBJECTS = [
    "${local.bucket_arn}/${local.log_prefix}*",
    "${local.bucket_arn}/${local.digest_prefix}*",
]


@pytest.fixture
def source() -> dict:
    return json.loads(SOURCE.read_text(encoding="utf-8"))


def statements(source: dict, name: str) -> dict[str, dict]:
    items = source["locals"][name]["Statement"]
    by_sid = {item["Sid"]: item for item in items}
    assert len(by_sid) == len(items), "Security statements require distinct SIDs"
    return by_sid


def test_toolchain_requires_the_exact_reviewed_terraform_release(source: dict) -> None:
    assert source["terraform"]["required_version"] == "= 1.17.1"


def test_tls_denial_preserves_direct_aws_service_delivery(source: dict) -> None:
    tls = statements(source, "archive_policy")["RequireTls"]
    assert tls["Effect"] == "Deny"
    assert tls["Principal"] == "*"
    assert tls["Action"] == ["s3:*"]
    assert tls["Resource"] == ["${local.bucket_arn}", "${local.bucket_arn}/*"]
    assert tls["Condition"] == {
        "Bool": {"aws:SecureTransport": "false", "aws:PrincipalIsAWSService": "false"}
    }


@pytest.mark.parametrize(
    ("function", "reserved"),
    [
        ("startswith", "xn--"),
        ("startswith", "sthree-"),
        ("startswith", "amzn-s3-demo-"),
        ("endswith", "-s3alias"),
        ("endswith", "--ol-s3"),
        ("endswith", ".mrap"),
        ("endswith", "--x-s3"),
        ("endswith", "--table-s3"),
        ("endswith", "-an"),
    ],
)
def test_shared_namespace_bucket_input_declares_reserved_name_exclusions(
    source: dict, function: str, reserved: str
) -> None:
    # Deliberately check reviewed clauses, without inventing an HCL evaluator.
    conditions = [
        validation["condition"]
        for validation in source["variable"]["archive_bucket_name"]["validation"]
    ]
    clause = f'!{function}(var.archive_bucket_name, "{reserved}")'
    assert any(clause in condition for condition in conditions), clause


def test_provider_uses_one_explicit_account_region_and_provisioning_role(source: dict) -> None:
    provider = source["provider"]["aws"]
    assert provider["region"] == "us-east-1"
    assert provider["allowed_account_ids"] == ["${var.account_id}"]
    assert provider["assume_role"] == [
        {
            "role_arn": "${var.provisioner_role_arn}",
            "session_name": "cloudsecops-reviewed-provisioning",
        }
    ]
    assert source["terraform"]["required_providers"] == {
        "aws": {"source": "hashicorp/aws", "version": "= 6.71.0"}
    }
    assert not {"backend", "cloud"} & source["terraform"].keys()
    assert not {"data", "module", "provisioner"} & source.keys()


@pytest.mark.parametrize("role", ["collector", "verifier"])
def test_readers_bind_listing_to_bucket_owner_and_exact_evidence_prefixes(
    source: dict, role: str
) -> None:
    policy = statements(source, role + "_policy")
    listing = policy["ListEvidencePrefixes"]
    assert set(listing["Action"]) == {"s3:ListBucket", "s3:ListBucketVersions"}
    assert listing["Resource"] == "${local.bucket_arn}"
    assert listing["Condition"] == {
        "StringEquals": {"s3:ResourceAccount": "${var.account_id}"},
        "StringLike": {"s3:prefix": ["${local.log_prefix}*", "${local.digest_prefix}*"]},
    }
    location = policy["ReadBucketLocation"]
    assert location["Action"] == ["s3:GetBucketLocation"]
    assert location["Resource"] == "${local.bucket_arn}"
    assert location["Condition"] == BUCKET_OWNER


@pytest.mark.parametrize("role", ["collector", "verifier"])
def test_readers_can_get_current_and_pinned_versions_only_under_evidence_roots(
    source: dict, role: str
) -> None:
    read = statements(source, role + "_policy")["ReadEvidenceVersions"]
    assert set(read["Action"]) == {"s3:GetObject", "s3:GetObjectVersion"}
    assert read["Resource"] == EVIDENCE_OBJECTS
    assert read["Condition"] == BUCKET_OWNER


@pytest.mark.parametrize("role", ["collector", "verifier"])
def test_trail_reads_use_exact_trail_and_public_key_reads_use_regional_wildcard(
    source: dict, role: str
) -> None:
    policy = statements(source, role + "_policy")
    trail = policy["ReadTrail"]
    assert set(trail["Action"]) == {
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
    }
    assert trail["Resource"] == "${local.trail_arn}"
    assert trail["Condition"] == REGIONAL
    keys = policy["ReadDigestPublicKeys"]
    assert keys["Action"] == ["cloudtrail:ListPublicKeys"]
    assert keys["Resource"] == "*"
    assert keys["Condition"] == REGIONAL


@pytest.mark.parametrize("role", ["collector", "verifier"])
def test_identity_observation_is_separate_from_regional_trail_authorization(
    source: dict, role: str
) -> None:
    identity = statements(source, role + "_policy")["ReadOwnIdentity"]
    assert identity["Action"] == ["sts:GetCallerIdentity"]
    assert identity["Resource"] == "*"
    # AWS authorizes this call even when its identity-policy action is denied.
    # A Region condition here would not enforce the acquisition client's Region.
    assert "Condition" not in identity


def test_verifier_inspection_is_scoped_to_exact_roles_bucket_and_trail(source: dict) -> None:
    policy = statements(source, "verifier_policy")
    roles = policy["InspectExactRuntimeRoles"]
    assert set(roles["Action"]) == {
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
    }
    assert roles["Resource"] == "${local.managed_role_arns}"
    assert "Condition" not in roles  # IAM is global; do not apply a regional read condition.
    archive = policy["InspectArchiveConfiguration"]
    assert set(archive["Action"]) == {
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketOwnershipControls",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
    }
    assert archive["Resource"] == "${local.bucket_arn}"
    assert archive["Condition"] == BUCKET_OWNER
    insights = policy["InspectTrailInsights"]
    assert insights["Action"] == ["cloudtrail:GetInsightSelectors"]
    assert insights["Resource"] == "${local.trail_arn}"
    assert insights["Condition"] == REGIONAL
    history = policy["RegionalHistoryRead"]
    assert history["Action"] == ["cloudtrail:LookupEvents"]
    assert history["Resource"] == "*"
    assert history["Condition"] == REGIONAL


def test_test_actor_can_only_describe_regional_instances(source: dict) -> None:
    actor = statements(source, "test_actor_policy")
    assert set(actor) == {"OnlyRegionalInstanceInventory"}
    inventory = actor["OnlyRegionalInstanceInventory"]
    assert inventory["Action"] == ["ec2:DescribeInstances"]
    assert inventory["Resource"] == "*"
    assert inventory["Condition"] == REGIONAL


@pytest.mark.parametrize("role", ["collector", "verifier", "test_actor"])
def test_runtime_policies_have_no_added_write_or_role_assumption_authority(
    source: dict, role: str
) -> None:
    expected_sids = {
        "ListEvidencePrefixes",
        "ReadBucketLocation",
        "ReadEvidenceVersions",
        "ReadTrail",
        "ReadDigestPublicKeys",
        "ReadOwnIdentity",
    }
    expected = {
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:ListPublicKeys",
        "sts:GetCallerIdentity",
    }
    if role == "verifier":
        expected_sids |= {
            "InspectExactRuntimeRoles",
            "InspectArchiveConfiguration",
            "InspectTrailInsights",
            "RegionalHistoryRead",
        }
        expected |= {
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListRolePolicies",
            "iam:ListAttachedRolePolicies",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketOwnershipControls",
            "s3:GetEncryptionConfiguration",
            "s3:GetBucketVersioning",
            "s3:GetLifecycleConfiguration",
            "cloudtrail:GetInsightSelectors",
            "cloudtrail:LookupEvents",
        }
    elif role == "test_actor":
        expected_sids = {"OnlyRegionalInstanceInventory"}
        expected = {"ec2:DescribeInstances"}
    policy = statements(source, role + "_policy")
    # An added statement reusing an allowed action could otherwise widen resources.
    assert set(policy) == expected_sids
    actual = set()
    for statement in policy.values():
        assert statement["Effect"] == "Allow"
        assert not {"NotAction", "NotResource", "Principal"} & statement.keys()
        actual.update(statement["Action"])
    assert actual == expected


@pytest.mark.parametrize("role", ["collector", "verifier", "test_actor"])
def test_each_runtime_role_trusts_only_its_exact_distinct_external_role(
    source: dict, role: str
) -> None:
    trust = statements(source, role + "_trust")
    assert set(trust) == {"ExactExistingTrustedRole"}
    assert trust["ExactExistingTrustedRole"] == {
        "Sid": "ExactExistingTrustedRole",
        "Effect": "Allow",
        "Action": ["sts:AssumeRole"],
        "Principal": {"AWS": "${var." + role + "_trusted_role_arn}"},
    }
    managed = source["resource"]["aws_iam_role"][role]
    assert managed["name"] == "cloudsecops-" + role.replace("_", "-")
    assert managed["assume_role_policy"] == "${jsonencode(local." + role + "_trust)}"
    assert managed["max_session_duration"] == 3600
    assert managed["path"] == "/cloudsecops-sandbox/"
    assert managed["force_detach_policies"] is False
    external = source["variable"][role + "_trusted_role_arn"]
    assert external["nullable"] is False
    assert external["sensitive"] is True
    assert "default" not in external


def test_external_authorities_must_be_distinct_and_exclude_runtime_roles(source: dict) -> None:
    roles = (
        "[var.provisioner_role_arn, var.cleanup_role_arn, var.collector_trusted_role_arn, "
        "var.verifier_trusted_role_arn, var.test_actor_trusted_role_arn]"
    )
    conditions = {
        validation["condition"]
        for validation in source["variable"]["cleanup_role_arn"]["validation"]
    }
    assert "${length(distinct(" + roles + ")) == 5}" in conditions
    assert (
        "${alltrue([for arn in " + roles + " : !contains(local.managed_role_arns, arn)])}"
        in conditions
    )
    assert source["locals"]["managed_role_arns"] == [
        "arn:aws:iam::${var.account_id}:role/cloudsecops-sandbox/cloudsecops-collector",
        "arn:aws:iam::${var.account_id}:role/cloudsecops-sandbox/cloudsecops-verifier",
        "arn:aws:iam::${var.account_id}:role/cloudsecops-sandbox/cloudsecops-test-actor",
    ]


def test_boe_ownership_and_cloudtrail_acl_requirement_are_kept_together(source: dict) -> None:
    ownership = source["resource"]["aws_s3_bucket_ownership_controls"]["archive"]
    assert ownership["rule"] == {"object_ownership": "BucketOwnerEnforced"}
    assert "aws_s3_bucket_acl" not in source["resource"]
    delivery = statements(source, "archive_policy")["ExactTrailLogAndDigestDelivery"]
    assert delivery["Condition"]["StringEquals"]["s3:x-amz-acl"] == "bucket-owner-full-control"
    blocks = source["resource"]["aws_s3_bucket_public_access_block"]["archive"]
    for key in (
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    ):
        assert blocks[key] is True
    encryption = source["resource"]["aws_s3_bucket_server_side_encryption_configuration"]["archive"]
    assert encryption["rule"] == [
        {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}
    ]


def test_cloudtrail_delivery_binds_exact_service_trail_account_and_both_prefixes(
    source: dict,
) -> None:
    policy = statements(source, "archive_policy")
    acl, delivery = policy["ExactTrailAclCheck"], policy["ExactTrailLogAndDigestDelivery"]
    for statement in (acl, delivery):
        assert statement["Effect"] == "Allow"
        assert statement["Principal"] == {"Service": "cloudtrail.amazonaws.com"}
        condition = statement["Condition"]["StringEquals"]
        assert condition["aws:SourceArn"] == "${local.trail_arn}"
        assert condition["aws:SourceAccount"] == "${var.account_id}"
    assert acl["Action"] == ["s3:GetBucketAcl"]
    assert acl["Resource"] == "${local.bucket_arn}"
    assert delivery["Action"] == ["s3:PutObject"]
    assert delivery["Resource"] == EVIDENCE_OBJECTS
    assert set(acl["Condition"]["StringEquals"]) == {"aws:SourceArn", "aws:SourceAccount"}
    assert set(delivery["Condition"]["StringEquals"]) == {
        "aws:SourceArn",
        "aws:SourceAccount",
        "s3:x-amz-acl",
    }
    allows = {sid for sid, statement in policy.items() if statement["Effect"] == "Allow"}
    assert allows == {"ExactTrailAclCheck", "ExactTrailLogAndDigestDelivery"}


@pytest.mark.parametrize(
    ("sid", "condition"),
    [
        (
            "OnlyCloudTrailMayWrite",
            {"StringNotEqualsIfExists": {"aws:PrincipalServiceName": "cloudtrail.amazonaws.com"}},
        ),
        (
            "OnlyExactTrailMayWrite",
            {"ArnNotEqualsIfExists": {"aws:SourceArn": "${local.trail_arn}"}},
        ),
    ],
)
def test_direct_principals_and_other_trails_cannot_use_writer_exceptions(
    source: dict, sid: str, condition: dict
) -> None:
    deny = statements(source, "archive_policy")[sid]
    assert deny["Effect"] == "Deny"
    assert deny["Principal"] == "*"
    assert deny["Action"] == ["s3:PutObject"]
    assert deny["Resource"] == "${local.bucket_arn}/*"
    assert deny["Condition"] == condition


@pytest.mark.parametrize(
    ("sid", "actions", "resource"),
    [
        (
            "DeleteEvidenceRequiresSeparateCleanup",
            {"s3:DeleteObject", "s3:DeleteObjectVersion"},
            "${local.bucket_arn}/*",
        ),
        ("DeleteBucketRequiresSeparateCleanup", {"s3:DeleteBucket"}, "${local.bucket_arn}"),
    ],
)
def test_cleanup_exception_only_exempts_exact_role_from_scoped_deletion_denials(
    source: dict, sid: str, actions: set[str], resource: str
) -> None:
    deny = statements(source, "archive_policy")[sid]
    assert deny["Effect"] == "Deny"
    assert deny["Principal"] == "*"
    assert set(deny["Action"]) == actions
    assert deny["Resource"] == resource
    assert deny["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": "${var.cleanup_role_arn}"}}
    # Exemption is no Allow, and provisioner/runtime principals receive no exemption.
    assert "NotPrincipal" not in deny


def test_evidence_retention_has_no_automatic_expiration_or_force_destroy(source: dict) -> None:
    resources = source["resource"]
    assert "aws_s3_bucket_lifecycle_configuration" not in resources
    assert "lifecycle_rule" not in resources["aws_s3_bucket"]["archive"]
    assert resources["aws_s3_bucket"]["archive"]["force_destroy"] is False
    assert resources["aws_s3_bucket_versioning"]["archive"]["versioning_configuration"] == {
        "status": "Enabled"
    }
    expiration = statements(source, "archive_policy")["NoAutomaticExpiration"]
    assert expiration == {
        "Sid": "NoAutomaticExpiration",
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["s3:PutLifecycleConfiguration"],
        "Resource": "${local.bucket_arn}",
    }
    for instances in resources.values():
        for resource in instances.values():
            assert resource["lifecycle"]["prevent_destroy"] is True
            assert "provisioner" not in resource


def test_trail_selectors_match_regional_management_parser_scope(source: dict) -> None:
    trail = source["resource"]["aws_cloudtrail"]["management"]
    assert trail["event_selector"] == [
        {"include_management_events": True, "read_write_type": "All"}
    ]
    assert trail["enable_logging"] is True
    assert trail["enable_log_file_validation"] is True
    assert trail["include_global_service_events"] is True
    assert trail["is_multi_region_trail"] is False
    assert trail["is_organization_trail"] is False
    assert "advanced_event_selector" not in trail
    assert "insight_selector" not in trail
    assert trail["s3_key_prefix"] == "evidence"
    assert source["locals"]["log_prefix"] == (
        "evidence/AWSLogs/${var.account_id}/CloudTrail/us-east-1/"
    )
    assert source["locals"]["digest_prefix"] == (
        "evidence/AWSLogs/${var.account_id}/CloudTrail-Digest/us-east-1/"
    )


def test_fixed_infrastructure_scope_supports_offline_parsing_and_collection(
    source: dict,
) -> None:
    # Substitute one known account placeholder; this is not an HCL interpreter.
    account = "1" * 12
    local = source["locals"]
    scope = AwsScope(
        account=account,
        region=source["provider"]["aws"]["region"],
        role_arn=local["managed_role_arns"][0].replace("${var.account_id}", account),
        role_id="AROA" + "A" * 17,
        trail_arn=local["trail_arn"].replace("${var.account_id}", account),
        bucket="cloudsecops-offline-review-" + "a" * 16,
        log_prefix=local["log_prefix"].replace("${var.account_id}", account),
        digest_prefix=local["digest_prefix"].replace("${var.account_id}", account),
    )
    record = {
        "recipientAccountId": account,
        "awsRegion": "us-east-1",
        "eventID": "aaaaaaaa-bbbb-4ccc-8ddd-" + "0" * 12,
        "eventTime": "2026-11-03T00:00:00Z",
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "readOnly": True,
    }
    archive = gzip.compress(json.dumps({"Records": [record]}).encode(), mtime=0)
    log = parse_aws_shaped(archive, scope)
    assert log.archive_bytes == archive
    assert len(log.events) == 1
    assert log.events[0].identity == (account, "us-east-1", record["eventID"])
    assert log.events[0].event_name == "DescribeInstances"
    assert log.source_kind == "aws_shaped_unverified"
    assert log.authenticated is False

    now = datetime(2026, 11, 3, tzinfo=UTC)
    reference = ObjectVersion(
        bucket=scope.bucket,
        key=scope.log_prefix + "2026/11/03/offline.json.gz",
        version_id="offline-version",
        size=len(archive),
        last_modified=now,
    )

    class OfflineTransport:
        def caller_identity(self) -> CallerIdentity:
            return CallerIdentity(
                scope.account,
                scope.region,
                f"arn:aws:sts::{scope.account}:assumed-role/cloudsecops-collector/offline",
                scope.role_id + ":offline",
                now,
                now + timedelta(hours=1),
            )

        def list_versions(self, expected: AwsScope, prefix: str, marker: object) -> VersionPage:
            assert expected == scope
            assert prefix == scope.log_prefix
            assert marker is None
            return VersionPage(True, (reference,), False, None)

        def head_current(self, ref: ObjectVersion) -> str:
            assert ref == reference
            return reference.version_id

        def get_object(self, ref: ObjectVersion, max_bytes: int) -> ObjectBody:
            assert ref == reference
            assert max_bytes == len(archive) + 1
            return ObjectBody(reference, scope.account, BytesIO(archive))

    batch = collect(OfflineTransport(), scope, MemoryLedger(), "fixture", clock=lambda: now)
    assert len(batch.objects) == 1
    assert batch.objects[0].reference == reference
    assert batch.objects[0].log == log
    assert batch.unique_event_count == 1
    assert batch.source_kind == "aws_shaped_unverified"
    assert batch.authenticated is False
