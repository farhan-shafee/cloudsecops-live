"""Verify the offline Terraform guard through its credential-free CLI."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infra/aws-offline"


def run_check(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_terraform.py"), str(directory)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def candidate(tmp_path: Path) -> Path:
    directory = tmp_path / "source"
    shutil.copytree(SOURCE, directory)
    return directory


def rewrite(directory: Path, path: tuple[str | int, ...], value: object) -> None:
    source = directory / "main.tf.json"
    document = json.loads(source.read_text(encoding="utf-8"))
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    source.write_text(json.dumps(document), encoding="utf-8")


def test_checked_in_terraform_has_no_static_policy_findings() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_terraform.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "source policy passed" in result.stdout
    assert "Terraform validate was not run" in result.stdout


@pytest.mark.parametrize("role", ["collector", "verifier"])
def test_archive_readers_can_enumerate_versions_and_head_current_and_exact_versions(
    role: str,
) -> None:
    document = json.loads((SOURCE / "main.tf.json").read_text(encoding="utf-8"))
    statements = document["locals"][role + "_policy"]["Statement"]
    listing = next(
        statement for statement in statements if statement["Sid"] == "ListEvidencePrefixes"
    )
    assert set(listing["Action"]) == {"s3:ListBucket", "s3:ListBucketVersions"}
    assert listing["Resource"] == "${local.bucket_arn}"
    assert listing["Condition"]["StringLike"]["s3:prefix"] == [
        "${local.log_prefix}*",
        "${local.digest_prefix}*",
    ]
    reads = next(
        statement for statement in statements if statement["Sid"] == "ReadEvidenceVersions"
    )
    assert set(reads["Action"]) == {"s3:GetObject", "s3:GetObjectVersion"}


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("provider", "aws", "region"), "us-west-2"),
        (("provider", "aws", "allowed_account_ids"), []),
        (("provider", "aws", "skip_credentials_validation"), True),
        (("terraform", "required_providers", "aws", "version"), ">= 6.0"),
        (("terraform", "backend"), {"s3": {"bucket": "unreviewed"}}),
        (("data",), {"aws_caller_identity": {"current": {}}}),
        (("module",), {"remote": {"source": "https://example.invalid/module"}}),
        (("resource", "aws_instance"), {"surprise": {"instance_type": "t3.micro"}}),
        (("resource", "aws_s3_bucket", "archive", "force_destroy"), True),
        (("resource", "aws_s3_bucket", "archive", "lifecycle", "prevent_destroy"), False),
        (("resource", "aws_cloudtrail", "management", "lifecycle", "prevent_destroy"), False),
        (("resource", "aws_cloudtrail", "management", "enable_log_file_validation"), False),
        (("resource", "aws_cloudtrail", "management", "enable_logging"), 1),
        (("resource", "aws_cloudtrail", "management", "is_multi_region_trail"), True),
        (("resource", "aws_cloudtrail", "management", "insight_selector"), [{}]),
        (
            ("resource", "aws_cloudtrail", "management", "event_selector", 0, "read_write_type"),
            "WriteOnly",
        ),
        (("resource", "aws_cloudtrail", "management", "event_selector", 0, "data_resource"), [{}]),
        (
            ("resource", "aws_s3_bucket_public_access_block", "archive", "block_public_policy"),
            False,
        ),
        (
            (
                "resource",
                "aws_s3_bucket_versioning",
                "archive",
                "versioning_configuration",
                "status",
            ),
            "Suspended",
        ),
        (
            ("resource", "aws_s3_bucket_lifecycle_configuration"),
            {"expiry": {"rule": [{"expiration": {"days": 30}}]}},
        ),
        (
            ("locals", "test_actor_policy", "Statement", 0, "Action"),
            ["ec2:DescribeInstances", "ec2:RunInstances"],
        ),
        (("locals", "test_actor_policy", "Statement", 0, "Condition"), {}),
        (("locals", "collector_policy", "Statement", 0, "Condition"), {}),
        (("locals", "collector_policy", "Statement", 0, "Action"), ["s3:ListBucket"]),
        (("locals", "verifier_policy", "Statement", 0, "Action"), ["s3:ListBucket"]),
        (("locals", "collector_policy", "Statement", 2, "Resource"), ["*"]),
        (
            ("locals", "collector_policy", "Statement", 2, "Action"),
            ["s3:GetObject", "s3:PutObject"],
        ),
        (("locals", "verifier_policy", "Statement", 6, "Resource"), "*"),
        (
            ("locals", "verifier_trust", "Statement", 0, "Principal", "AWS"),
            "${var.collector_trusted_role_arn}",
        ),
        (("locals", "collector_trust", "Statement", 0, "Principal"), "*"),
        (
            (
                "locals",
                "archive_policy",
                "Statement",
                1,
                "Condition",
                "StringEquals",
                "aws:SourceArn",
            ),
            "*",
        ),
        (("locals", "archive_policy", "Statement", 2, "Condition"), {}),
        (("locals", "archive_policy", "Statement", 5, "Condition"), {}),
        (("variable", "account_id", "default"), "REPLACE_PRIVATELY"),
        (("variable", "cleanup_role_arn", "validation"), []),
        (("output", "archive_bucket", "sensitive"), False),
    ],
)
def test_weakened_or_expanded_source_fails_closed(
    candidate: Path, path: tuple[str | int, ...], value: object
) -> None:
    rewrite(candidate, path, value)
    result = run_check(candidate)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "source policy passed" not in result.stdout


@pytest.mark.parametrize(
    "name",
    [
        "override.tf",
        "extra.tf.json",
        "terraform.tfvars",
        "secrets.auto.tfvars",
        "terraform.tfstate",
        "plan.out",
    ],
)
def test_extra_configuration_or_private_artifact_is_rejected(candidate: Path, name: str) -> None:
    (candidate / name).write_text("{}", encoding="utf-8")
    result = run_check(candidate)
    assert result.returncode == 1
    assert "unexpected entry" in result.stdout


@pytest.mark.parametrize(
    "payload", ['{"resource": {}, "resource": {}}', '{"x": NaN}', "[]", "{}", "{"]
)
def test_duplicate_invalid_or_incomplete_source_is_rejected(candidate: Path, payload: str) -> None:
    (candidate / "main.tf.json").write_text(payload, encoding="utf-8")
    result = run_check(candidate)
    assert result.returncode == 1


def test_missing_file_or_directory_is_an_incomplete_check(candidate: Path, tmp_path: Path) -> None:
    (candidate / "main.tf.json").unlink()
    assert run_check(candidate).returncode == 1
    assert run_check(tmp_path / "absent").returncode == 1


def test_private_identifier_is_rejected_without_echo(candidate: Path) -> None:
    account = "123456" + "789012"
    source = candidate / "terraform.tfvars.example"
    source.write_text(f'account_id = "{account}"\n', encoding="utf-8")
    result = run_check(candidate)
    assert result.returncode == 1
    assert account not in result.stdout + result.stderr


def test_example_values_cannot_be_silently_changed_to_deployable_inputs(candidate: Path) -> None:
    example = candidate / "terraform.tfvars.example"
    example.write_text('archive_bucket_name = "a-real-looking-bucket"\n', encoding="utf-8")
    assert run_check(candidate).returncode == 1


def test_checker_does_not_invoke_processes_or_network(candidate: Path) -> None:
    from scripts.check_terraform import check_directory

    # A direct check is only bounded local file parsing; no Terraform, AWS SDK,
    # subprocess runner, HTTP library or environment/credential access is needed.
    assert check_directory(candidate) == []
    source = (ROOT / "scripts/check_terraform.py").read_text(encoding="utf-8")
    import ast

    tree = ast.parse(source)
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {"json", "pathlib", "re", "sys"}
