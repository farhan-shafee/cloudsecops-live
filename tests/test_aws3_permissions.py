"""Independent offline permission contracts and negative source mutations."""

import copy
import hashlib
import importlib
import importlib.util
import json
import shutil
import subprocess
import sys
from enum import StrEnum
from pathlib import Path

import pytest

from cloudsecops_live.errors import EvidenceError

ROOT = Path(__file__).resolve().parents[1]
TF_SOURCE = ROOT / "infra/aws-offline/main.tf.json"
POLICY = ROOT / "infra/iam-readiness/posture-inspection.policy.json"
BASELINE_SHA256 = (
    "e4353e42bee0e9b05b4d9a9703ec676d87"  # pragma: allowlist secret - public source SHA256
    "a4796d53091ccd37ad424610718f19"  # pragma: allowlist secret - public source SHA256
)
REGIONAL_INSIGHT = {
    "Sid": "InspectTrailInsights",
    "Effect": "Allow",
    "Action": ["cloudtrail:GetInsightSelectors"],
    "Resource": "${local.trail_arn}",
    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
}
POSTURE_OPERATIONS = {
    ("sts", "GetCallerIdentity"),
    ("cloudtrail", "ListTrails"),
    ("s3", "ListBuckets"),
    ("s3control", "GetPublicAccessBlock"),
    ("iam", "GetRole"),
    ("iam", "ListRolePolicies"),
    ("iam", "GetRolePolicy"),
    ("iam", "ListAttachedRolePolicies"),
}
ROLE = "arn:aws:iam::" + "1" * 12 + ":role/offline-inspection"


@pytest.fixture
def permissions():
    name = "cloudsecops_live.integrations.aws_readiness.permissions"
    assert importlib.util.find_spec(name) is not None, "AWS3 permission boundary is missing"
    return importlib.import_module(name)


def load_tf() -> dict:
    return json.loads(TF_SOURCE.read_text(encoding="utf-8"))


def test_permission_boundary_is_available_to_fixed_workers() -> None:
    assert (
        importlib.util.find_spec("cloudsecops_live.integrations.aws_readiness.permissions")
        is not None
    ), "Fixed workers need the shared AWS3 permission boundary"


def run_policy_check(policy: Path, source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_aws3_permissions.py"),
            "--policy-file",
            str(policy),
            "--terraform-source",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_only_terraform_delta_is_one_regional_collector_insight_read() -> None:
    candidate = load_tf()
    statements = candidate["locals"]["collector_policy"]["Statement"]
    assert statements[-1] == REGIONAL_INSIGHT, "Collector lacks the exact SDK insight read"
    assert len(statements) == 7
    statements.pop()
    canonical = json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert hashlib.sha256(canonical.encode()).hexdigest() == BASELINE_SHA256


def test_checked_in_permission_cli_accepts_only_reviewed_source() -> None:
    result = run_policy_check(POLICY, TF_SOURCE)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline source contracts passed" in result.stdout


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Action", ["cloudtrail:GetInsightSelectors", "cloudtrail:PutInsightSelectors"]),
        ("Resource", "*"),
        ("Condition", {}),
        ("Condition", {"StringEquals": {"aws:RequestedRegion": "us-west-2"}}),
        ("Effect", "Deny"),
        ("Principal", "*"),
    ],
)
def test_existing_canonical_checker_rejects_changed_collector_insight_scope(
    tmp_path: Path, field: str, value: object
) -> None:
    directory = tmp_path / "source"
    shutil.copytree(TF_SOURCE.parent, directory)
    candidate = load_tf()
    assert candidate["locals"]["collector_policy"]["Statement"][-1] == REGIONAL_INSIGHT
    candidate["locals"]["collector_policy"]["Statement"][-1][field] = value
    (directory / "main.tf.json").write_text(json.dumps(candidate), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_terraform.py"), str(directory)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "configuration differs" in result.stdout


def test_profiles_reject_object_access_in_posture_and_keep_exact_operations(permissions) -> None:
    assert set(permissions.OPERATION_PROFILES["posture"]) == POSTURE_OPERATIONS
    assert len(permissions.ACTION_PROFILES["posture"]) == 8
    assert len(permissions.ACTION_PROFILES["collector"]) == 11
    assert len(permissions.ACTION_PROFILES["verifier"]) == 23
    for service, operation in POSTURE_OPERATIONS:
        permissions.require_operation("posture", service, operation)
    with pytest.raises((AttributeError, TypeError)):
        permissions.OPERATION_PROFILES["posture"].add(("s3", "GetObject"))
    with pytest.raises(TypeError):
        permissions.OPERATION_PROFILES["posture"] = frozenset()


@pytest.mark.parametrize("purpose", ["collector", "verifier"])
@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("sts", "GetCallerIdentity"),
        ("s3", "ListObjectVersions"),
        ("s3", "HeadObject"),
        ("s3", "GetObject"),
        ("cloudtrail", "GetInsightSelectors"),
    ],
)
def test_archive_profiles_preserve_required_reads(permissions, purpose, service, operation) -> None:
    permissions.require_operation(purpose, service, operation)


@pytest.mark.parametrize(
    ("purpose", "service", "operation"),
    [
        ("posture", "s3", "HeadObject"),
        ("posture", "s3", "GetObject"),
        ("posture", "s3", "GetObjectVersion"),
        ("posture", "sts", "AssumeRole"),
        ("posture", "iam", "PassRole"),
        ("posture", "iam", "PutRolePolicy"),
        ("posture", "iam", "GetPolicyVersion"),
        ("posture", "s3", "GetPublicAccessBlock"),
        ("posture", "s3control", "GetAccountPublicAccessBlock"),
        ("posture", "cloudtrail", "list_trails"),
        ("posture", "cloudtrail", "LookupEvents"),
        ("collector", "iam", "GetRole"),
        ("collector", "s3", "PutObject"),
        ("verifier", "iam", "AttachRolePolicy"),
        ("verifier", "sts", "AssumeRole"),
        ("unknown", "sts", "GetCallerIdentity"),
        (None, "sts", "GetCallerIdentity"),
        ([], "sts", "GetCallerIdentity"),
        ("posture", None, "GetRole"),
        ("posture", "iam", []),
    ],
)
def test_unknown_or_cross_purpose_calls_fail_with_fixed_public_code(
    permissions, purpose, service, operation
) -> None:
    with pytest.raises(EvidenceError) as rejected:
        permissions.require_operation(purpose, service, operation)
    assert str(rejected.value) in {"AWS3_PERMISSION_PURPOSE", "AWS3_PERMISSION_OPERATION"}


def test_purpose_str_enum_is_accepted_without_a_second_enum(permissions) -> None:
    class Purpose(StrEnum):
        POSTURE = "posture"

    permissions.require_operation(Purpose.POSTURE, "sts", "GetCallerIdentity")


def test_template_and_private_binding_preserve_one_exact_inspection_role(permissions) -> None:
    template = json.loads(POLICY.read_text(encoding="utf-8"))
    permissions.validate_posture_policy(template)
    private = permissions.posture_policy(ROLE)
    permissions.validate_posture_policy(private, ROLE)
    iam = next(s for s in private["Statement"] if s["Sid"] == "InspectExactRoleMetadata")
    assert iam["Resource"] == ROLE
    assert set(iam["Action"]) == {
        "iam:GetRole",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
    }
    private["Statement"].clear()
    permissions.validate_posture_policy(permissions.posture_policy(ROLE), ROLE)


@pytest.mark.parametrize(
    "role",
    [
        "*",
        "",
        "arn:aws:iam::" + "1" * 12 + ":root",
        ROLE + "*",
        ROLE + "?",
        ROLE + "/",
        ROLE.replace(":aws:", ":aws-us-gov:"),
        ROLE.replace("1" * 12, "1" * 11),
        None,
        1,
    ],
)
def test_nonexact_inspection_role_binding_is_rejected(permissions, role) -> None:
    with pytest.raises(EvidenceError, match="^AWS3_PERMISSION_ROLE$"):
        permissions.posture_policy(role)


@pytest.mark.parametrize(
    "mutation",
    [
        "allow-object",
        "allow-assume",
        "allow-pass",
        "iam-wildcard",
        "iam-extra-role",
        "regional-widening",
        "account-widening",
        "delete-guardrail",
        "widen-guardrail",
        "extra-principal",
        "numeric-effect",
        "extra-field",
    ],
)
def test_policy_mutations_never_expand_posture_privilege(permissions, mutation) -> None:
    candidate = permissions.posture_policy(ROLE)
    statements = {s["Sid"]: s for s in candidate["Statement"]}
    if mutation.startswith("allow-"):
        action = {
            "allow-object": "s3:GetObject",
            "allow-assume": "sts:AssumeRole",
            "allow-pass": "iam:PassRole",
        }[mutation]
        candidate["Statement"].append({"Effect": "Allow", "Action": [action], "Resource": "*"})
    elif mutation == "iam-wildcard":
        statements["InspectExactRoleMetadata"]["Resource"] = "*"
    elif mutation == "iam-extra-role":
        statements["InspectExactRoleMetadata"]["Resource"] = [ROLE, ROLE + "-other"]
    elif mutation == "regional-widening":
        statements["RegionalTrailInventory"].pop("Condition")
    elif mutation == "account-widening":
        statements["AccountPublicAccessPosture"].pop("Condition")
    elif mutation == "delete-guardrail":
        candidate["Statement"].remove(statements["DenyOtherActions"])
    elif mutation == "widen-guardrail":
        statements["DenyOtherActions"]["NotAction"].append("s3:GetObject")
    elif mutation == "extra-principal":
        statements["InspectExactRoleMetadata"]["Principal"] = "*"
    elif mutation == "numeric-effect":
        statements["InspectExactRoleMetadata"]["Effect"] = 1
    else:
        candidate["Authenticated"] = True
    with pytest.raises(EvidenceError, match="^AWS3_PERMISSION_POLICY$"):
        permissions.validate_posture_policy(candidate, ROLE)


@pytest.mark.parametrize(
    "document",
    [
        None,
        [],
        "{}",
        {"Statement": []},
        {"bad": float("nan")},
        {"bad": object()},
        {"bad": "x" * 66000},
    ],
)
def test_malformed_policy_objects_fail_closed(permissions, document) -> None:
    with pytest.raises(EvidenceError, match="^AWS3_PERMISSION_POLICY$"):
        permissions.validate_posture_policy(document, ROLE)


@pytest.mark.parametrize(
    "mutation", ["missing-insight", "duplicate-insight", "verifier-change", "trust-change"]
)
def test_independent_cli_rejects_any_extra_or_missing_terraform_delta(tmp_path, mutation) -> None:
    candidate = load_tf()
    if mutation == "missing-insight":
        candidate["locals"]["collector_policy"]["Statement"] = [
            s
            for s in candidate["locals"]["collector_policy"]["Statement"]
            if s["Sid"] != "InspectTrailInsights"
        ]
    elif mutation == "duplicate-insight":
        candidate["locals"]["collector_policy"]["Statement"].append(copy.deepcopy(REGIONAL_INSIGHT))
    elif mutation == "verifier-change":
        candidate["locals"]["verifier_policy"]["Statement"][0]["Action"].append("s3:GetObject")
    else:
        candidate["locals"]["collector_trust"]["Statement"][0]["Principal"]["AWS"] = "*"
    source = tmp_path / "candidate.json"
    source.write_text(json.dumps(candidate), encoding="utf-8")
    result = run_policy_check(POLICY, source)
    assert result.returncode == 1
    assert "offline permission source rejected" in result.stdout
    assert "candidate.json" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "content",
    [
        b'{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}',
        b'{"Statement":NaN}',
        b"\xff\xfe",
        b"{" + b"x" * 66000,
        b"[]",
        b"null",
    ],
)
def test_cli_rejects_duplicate_nonfinite_invalid_or_oversized_policy_bytes(
    tmp_path: Path, content: bytes
) -> None:
    policy = tmp_path / "private-policy-marker.json"
    policy.write_bytes(content)
    result = run_policy_check(policy, TF_SOURCE)
    assert result.returncode == 1
    assert result.stdout.strip() == "AWS3 offline permission source rejected"
    assert "private-policy-marker" not in result.stdout + result.stderr


def test_cli_missing_policy_fails_without_echoing_private_path(tmp_path: Path) -> None:
    result = run_policy_check(tmp_path / "private-missing-marker.json", TF_SOURCE)
    assert result.returncode == 1
    assert result.stdout.strip() == "AWS3 offline permission source rejected"
    assert "private-missing-marker" not in result.stdout + result.stderr


@pytest.mark.parametrize("content", ["null", "[]", "{}", '{"locals": {}}'])
def test_cli_malformed_terraform_structure_is_not_an_empty_success(
    tmp_path: Path, content: str
) -> None:
    source = tmp_path / "malformed-source.json"
    source.write_text(content, encoding="utf-8")
    result = run_policy_check(POLICY, source)
    assert result.returncode == 1
    assert result.stdout.strip() == "AWS3 offline permission source rejected"


def test_cyclic_policy_and_oversized_role_are_sanitized(permissions) -> None:
    cycle: dict = {}
    cycle["cycle"] = cycle
    with pytest.raises(EvidenceError, match="^AWS3_PERMISSION_POLICY$"):
        permissions.validate_posture_policy(cycle, ROLE)
    with pytest.raises(EvidenceError, match="^AWS3_PERMISSION_ROLE$"):
        permissions.posture_policy(ROLE + "a" * 512)
