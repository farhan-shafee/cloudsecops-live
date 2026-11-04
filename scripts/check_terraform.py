"""Check the closed Phase1B-AWS-0 source policy using bounded local JSON only.

This is deliberately not a Terraform parser, expression evaluator, provider
schema validator, effective-IAM evaluator or live AWS acceptance check. The
reviewed literal expressions are part of the allowlist. New infrastructure or
different expressions require reviewing this policy as well as the source.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infra/aws-offline"
AWS_VERSION = "6.71.0"
TERRAFORM_VERSION = "1.17.1"
INPUTS = (
    "account_id",
    "archive_bucket_name",
    "provisioner_role_arn",
    "cleanup_role_arn",
    "collector_trusted_role_arn",
    "verifier_trusted_role_arn",
    "test_actor_trusted_role_arn",
)
EXAMPLE = "# Placeholder-only example; never replace values in this tracked file.\n" + "".join(
    f'{name} = "REPLACE_PRIVATELY"\n' for name in INPUTS
)
_ACCOUNT = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")
_LIMIT = 128 * 1024


def _statement(sid: str, actions: list[str], resources: object, **extra: object) -> dict:
    return {"Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resources, **extra}


def _policy(statements: list[dict]) -> dict:
    return {"Version": "2012-10-17", "Statement": statements}


def _reader_statements() -> list[dict]:
    account = {"StringEquals": {"s3:ResourceAccount": "${var.account_id}"}}
    return [
        _statement(
            "ListEvidencePrefixes",
            ["s3:ListBucket", "s3:ListBucketVersions"],
            "${local.bucket_arn}",
            Condition={
                **account,
                "StringLike": {"s3:prefix": ["${local.log_prefix}*", "${local.digest_prefix}*"]},
            },
        ),
        _statement(
            "ReadBucketLocation", ["s3:GetBucketLocation"], "${local.bucket_arn}", Condition=account
        ),
        _statement(
            "ReadEvidenceVersions",
            ["s3:GetObject", "s3:GetObjectVersion"],
            [
                "${local.bucket_arn}/${local.log_prefix}*",
                "${local.bucket_arn}/${local.digest_prefix}*",
            ],
            Condition=account,
        ),
        _statement(
            "ReadTrail",
            ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors"],
            "${local.trail_arn}",
            Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        ),
        _statement(
            "ReadDigestPublicKeys",
            ["cloudtrail:ListPublicKeys"],
            "*",
            Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        ),
        _statement("ReadOwnIdentity", ["sts:GetCallerIdentity"], "*"),
    ]


def _trust(role: str) -> dict:
    return _policy(
        [
            {
                "Sid": "ExactExistingTrustedRole",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Principal": {"AWS": "${var." + role + "_trusted_role_arn}"},
            }
        ]
    )


def _role_variable() -> dict:
    # Cross-input validation requires Terraform 1.9 or newer. The private
    # account itself has no default and is never read from ambient credentials.
    return {"type": "string", "sensitive": True, "nullable": False}


def reviewed_configuration() -> dict:
    """Return the exact reviewed source contract, independent of input files."""
    variables = {
        name: {**_role_variable(), "description": "Supply privately; no tracked real identifiers."}
        for name in INPUTS
    }
    variables["account_id"]["validation"] = [
        {
            "condition": '${can(regex("^[0-9]{12}$", var.account_id))}',
            "error_message": "Supply the expected sandbox account privately.",
        }
    ]
    variables["archive_bucket_name"]["validation"] = [
        {
            "condition": '${can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", '
            "var.archive_bucket_name))}",
            "error_message": "Use a private globally unique lowercase bucket name without dots.",
        }
    ]
    variables["archive_bucket_name"]["validation"].append(
        {
            "condition": "${"
            + " && ".join(
                [
                    f'!startswith(var.archive_bucket_name, "{prefix}")'
                    for prefix in ("xn--", "sthree-", "amzn-s3-demo-")
                ]
                + [
                    f'!endswith(var.archive_bucket_name, "{suffix}")'
                    for suffix in ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3", "-an")
                ]
            )
            + "}",
            "error_message": "Use an ordinary bucket name outside AWS reserved namespaces.",
        }
    )
    role_inputs = INPUTS[2:]
    for name in role_inputs:
        variables[name]["validation"] = [
            {
                "condition": '${can(regex("^arn:aws:iam::[0-9]{12}:role/'
                '[A-Za-z0-9+=,.@_/-]+$", var.'
                + name
                + ")) && startswith(var."
                + name
                + ', "arn:aws:iam::${var.account_id}:role/")}',
                "error_message": "Use one exact existing role in the private expected "
                "sandbox account.",
            }
        ]
    roles_expression = "[" + ", ".join("var." + name for name in role_inputs) + "]"
    variables["cleanup_role_arn"]["validation"].extend(
        [
            {
                "condition": "${length(distinct(" + roles_expression + ")) == 5}",
                "error_message": "Provisioner, cleanup and the three trusted roles "
                "must all be distinct.",
            },
            {
                "condition": "${alltrue([for arn in "
                + roles_expression
                + " : !contains(local.managed_role_arns, arn)])}",
                "error_message": "Runtime roles cannot be provisioning, cleanup "
                "or trusted operator roles.",
            },
        ]
    )
    locals_ = {
        "bucket_arn": "arn:aws:s3:::${var.archive_bucket_name}",
        "trail_arn": "arn:aws:cloudtrail:us-east-1:${var.account_id}:trail/"
        "cloudsecops-sandbox-management",
        "log_prefix": "evidence/AWSLogs/${var.account_id}/CloudTrail/us-east-1/",
        "digest_prefix": "evidence/AWSLogs/${var.account_id}/CloudTrail-Digest/us-east-1/",
        "managed_role_arns": [
            "arn:aws:iam::${var.account_id}:role/cloudsecops-sandbox/cloudsecops-" + role
            for role in ("collector", "verifier", "test-actor")
        ],
        "collector_trust": _trust("collector"),
        "verifier_trust": _trust("verifier"),
        "test_actor_trust": _trust("test_actor"),
        "collector_policy": _policy(_reader_statements()),
        "verifier_policy": _policy(
            _reader_statements()
            + [
                _statement(
                    "InspectExactRuntimeRoles",
                    [
                        "iam:GetRole",
                        "iam:ListRolePolicies",
                        "iam:GetRolePolicy",
                        "iam:ListAttachedRolePolicies",
                    ],
                    "${local.managed_role_arns}",
                ),
                _statement(
                    "InspectArchiveConfiguration",
                    [
                        "s3:GetBucketAcl",
                        "s3:GetBucketPolicy",
                        "s3:GetBucketPublicAccessBlock",
                        "s3:GetBucketOwnershipControls",
                        "s3:GetEncryptionConfiguration",
                        "s3:GetBucketVersioning",
                        "s3:GetLifecycleConfiguration",
                    ],
                    "${local.bucket_arn}",
                    Condition={"StringEquals": {"s3:ResourceAccount": "${var.account_id}"}},
                ),
                _statement(
                    "InspectTrailInsights",
                    ["cloudtrail:GetInsightSelectors"],
                    "${local.trail_arn}",
                    Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                ),
                _statement(
                    "RegionalHistoryRead",
                    ["cloudtrail:LookupEvents"],
                    "*",
                    Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                ),
            ]
        ),
        "test_actor_policy": _policy(
            [
                _statement(
                    "OnlyRegionalInstanceInventory",
                    ["ec2:DescribeInstances"],
                    "*",
                    Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                )
            ]
        ),
        "archive_policy": _policy(
            [
                _statement(
                    "ExactTrailAclCheck",
                    ["s3:GetBucketAcl"],
                    "${local.bucket_arn}",
                    Principal={"Service": "cloudtrail.amazonaws.com"},
                    Condition={
                        "StringEquals": {
                            "aws:SourceArn": "${local.trail_arn}",
                            "aws:SourceAccount": "${var.account_id}",
                        }
                    },
                ),
                _statement(
                    "ExactTrailLogAndDigestDelivery",
                    ["s3:PutObject"],
                    [
                        "${local.bucket_arn}/${local.log_prefix}*",
                        "${local.bucket_arn}/${local.digest_prefix}*",
                    ],
                    Principal={"Service": "cloudtrail.amazonaws.com"},
                    Condition={
                        "StringEquals": {
                            "aws:SourceArn": "${local.trail_arn}",
                            "aws:SourceAccount": "${var.account_id}",
                            "s3:x-amz-acl": "bucket-owner-full-control",
                        }
                    },
                ),
                {
                    "Sid": "RequireTls",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:*"],
                    "Resource": ["${local.bucket_arn}", "${local.bucket_arn}/*"],
                    "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false",
                            "aws:PrincipalIsAWSService": "false",
                        }
                    },
                },
                {
                    "Sid": "OnlyCloudTrailMayWrite",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:PutObject"],
                    "Resource": "${local.bucket_arn}/*",
                    "Condition": {
                        "StringNotEqualsIfExists": {
                            "aws:PrincipalServiceName": "cloudtrail.amazonaws.com"
                        }
                    },
                },
                {
                    "Sid": "OnlyExactTrailMayWrite",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:PutObject"],
                    "Resource": "${local.bucket_arn}/*",
                    "Condition": {"ArnNotEqualsIfExists": {"aws:SourceArn": "${local.trail_arn}"}},
                },
                {
                    "Sid": "DeleteEvidenceRequiresSeparateCleanup",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                    "Resource": "${local.bucket_arn}/*",
                    "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "${var.cleanup_role_arn}"}},
                },
                {
                    "Sid": "NoAutomaticExpiration",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:PutLifecycleConfiguration"],
                    "Resource": "${local.bucket_arn}",
                },
                {
                    "Sid": "DeleteBucketRequiresSeparateCleanup",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": ["s3:DeleteBucket"],
                    "Resource": "${local.bucket_arn}",
                    "Condition": {"ArnNotEquals": {"aws:PrincipalArn": "${var.cleanup_role_arn}"}},
                },
            ]
        ),
    }
    guard = {"prevent_destroy": True}
    resources = {
        "aws_s3_bucket": {
            "archive": {
                "bucket": "${var.archive_bucket_name}",
                "force_destroy": False,
                "lifecycle": guard,
            }
        },
        "aws_s3_bucket_public_access_block": {
            "archive": {
                "bucket": "${aws_s3_bucket.archive.id}",
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
                "lifecycle": guard,
            }
        },
        "aws_s3_bucket_ownership_controls": {
            "archive": {
                "bucket": "${aws_s3_bucket.archive.id}",
                "rule": {"object_ownership": "BucketOwnerEnforced"},
                "lifecycle": guard,
            }
        },
        "aws_s3_bucket_versioning": {
            "archive": {
                "bucket": "${aws_s3_bucket.archive.id}",
                "versioning_configuration": {"status": "Enabled"},
                "lifecycle": guard,
            }
        },
        "aws_s3_bucket_server_side_encryption_configuration": {
            "archive": {
                "bucket": "${aws_s3_bucket.archive.id}",
                "rule": [{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
                "lifecycle": guard,
            }
        },
        "aws_s3_bucket_policy": {
            "archive": {
                "bucket": "${aws_s3_bucket.archive.id}",
                "policy": "${jsonencode(local.archive_policy)}",
                "lifecycle": guard,
                "depends_on": [
                    "aws_s3_bucket_public_access_block.archive",
                    "aws_s3_bucket_ownership_controls.archive",
                ],
            }
        },
        "aws_cloudtrail": {
            "management": {
                "name": "cloudsecops-sandbox-management",
                "s3_bucket_name": "${aws_s3_bucket.archive.id}",
                "s3_key_prefix": "evidence",
                "enable_logging": True,
                "enable_log_file_validation": True,
                "include_global_service_events": True,
                "is_multi_region_trail": False,
                "is_organization_trail": False,
                "event_selector": [{"include_management_events": True, "read_write_type": "All"}],
                "lifecycle": guard,
                "depends_on": [
                    "aws_s3_bucket_policy.archive",
                    "aws_s3_bucket_versioning.archive",
                    "aws_s3_bucket_server_side_encryption_configuration.archive",
                ],
            }
        },
        "aws_iam_role": {},
        "aws_iam_role_policy": {},
    }
    for role in ("collector", "verifier", "test_actor"):
        resources["aws_iam_role"][role] = {
            "name": "cloudsecops-" + role.replace("_", "-"),
            "path": "/cloudsecops-sandbox/",
            "max_session_duration": 3600,
            "assume_role_policy": "${jsonencode(local." + role + "_trust)}",
            "force_detach_policies": False,
            "lifecycle": guard,
        }
        resources["aws_iam_role_policy"][role] = {
            "name": "cloudsecops-" + role.replace("_", "-") + "-scope",
            "role": "${aws_iam_role." + role + ".id}",
            "policy": "${jsonencode(local." + role + "_policy)}",
            "lifecycle": guard,
        }
    return {
        "terraform": {
            "required_version": "= " + TERRAFORM_VERSION,
            "required_providers": {
                "aws": {"source": "hashicorp/aws", "version": "= " + AWS_VERSION}
            },
        },
        "provider": {
            "aws": {
                "region": "us-east-1",
                "allowed_account_ids": ["${var.account_id}"],
                "assume_role": [
                    {
                        "role_arn": "${var.provisioner_role_arn}",
                        "session_name": "cloudsecops-reviewed-provisioning",
                    }
                ],
                "default_tags": {
                    "tags": {
                        "Project": "cloudsecops-live",
                        "Environment": "sandbox",
                        "ManagedBy": "terraform",
                    }
                },
            }
        },
        "variable": variables,
        "locals": locals_,
        "resource": resources,
        "output": {
            "archive_bucket": {"value": "${aws_s3_bucket.archive.id}", "sensitive": True},
            "trail_arn": {"value": "${aws_cloudtrail.management.arn}", "sensitive": True},
            "runtime_role_arns": {
                "value": {
                    role: "${aws_iam_role." + role + ".arn}"
                    for role in ("collector", "verifier", "test_actor")
                },
                "sensitive": True,
            },
        },
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _finite_only(value: str) -> None:
    raise ValueError("nonfinite JSON number")


def check_directory(directory: Path) -> list[str]:
    """Return sanitized findings; never invoke Terraform, subprocesses or AWS."""
    try:
        if directory.is_symlink() or not directory.is_dir():
            return ["source directory missing or unsupported"]
        expected = {"main.tf.json", "terraform.tfvars.example", "README.md"}
        entries = list(directory.iterdir())
        if {path.name for path in entries} != expected:
            return ["missing file or unexpected entry in source directory"]
        texts = {}
        for path in entries:
            if path.is_symlink() or not path.is_file():
                return ["unsupported source entry"]
            with path.open("rb") as source:
                data = source.read(_LIMIT + 1)
            if len(data) > _LIMIT:
                return ["source file exceeds bounded size"]
            content = data.decode("utf-8").replace("\r\n", "\n")
            if _ACCOUNT.search(content):
                return ["account-shaped private identifier present"]
            texts[path.name] = content
        if texts["terraform.tfvars.example"] != EXAMPLE:
            return ["tracked example must remain placeholder-only"]
        document = json.loads(
            texts["main.tf.json"], object_pairs_hook=_unique_object, parse_constant=_finite_only
        )
        # Canonical JSON comparison retains bool/number distinctions that Python
        # equality would erase (True == 1). All expressions are fixed strings.
        options = {"sort_keys": True, "separators": (",", ":"), "allow_nan": False}
        if json.dumps(document, **options) != json.dumps(reviewed_configuration(), **options):
            return ["configuration differs from reviewed offline source policy"]
        return []
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return ["source check incomplete: invalid or unreadable local input"]


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) > 1:
        print("Usage: check_terraform.py [source-directory]", file=sys.stderr)
        return 2
    findings = check_directory(Path(arguments[0]) if arguments else SOURCE)
    for finding in findings:
        print("Terraform source policy: " + finding)
    if findings:
        return 1
    print("Terraform source policy passed (local structural allowlist only).")
    print("Terraform validate was not run by this structural check; the native gate is separate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
