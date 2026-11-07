"""Offline AWS4C owner decision contract: fail-closed without touching AWS."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_aws4c_pilot import (
    BASE_COMMIT,
    MAX_INPUT_BYTES,
    ROLE_NAMES,
    check_manifest,
    main,
    read_private_manifest,
)


@pytest.fixture
def valid_manifest() -> dict:
    account = "1" * 12
    roles = {
        name: {
            "arn": f"arn:aws:iam::{account}:role/cloudsecops-operators/{name}",
            "role_id": "AROA" + str(index + 1).zfill(17),
            "mfa_trust_verified": True,
            "role_id_verified": True,
            "effective_permissions_reviewed": True,
            "owner_session_custody_reviewed": True,
        }
        for index, name in enumerate(ROLE_NAMES)
    }
    return {
        "schema": "cloudsecops.aws4c.pilot-gates/1",
        "account_id": account,
        "region": "us-east-1",
        "reviewed_base_sha": BASE_COMMIT,
        "archive_bucket_name": "cloudsecops-archive-fixture-us-east-1",
        "external_operator_roles": roles,
        "state_custody": {
            "backend": "s3",
            "bucket_name": "cloudsecops-state-fixture-us-east-1",
            "key": "cloudsecops-live/aws4c/terraform.tfstate",
            "region": "us-east-1",
            "encrypt": True,
            "bucket_versioning": True,
            "bucket_public_access_block": True,
            "use_lockfile": True,
            "exclusive_writer_reviewed": True,
            "backup_restoration_tested": True,
            "backend_iam_reviewed": True,
        },
        "cost_and_retention": {
            "manual_hold_review_days": 90,
            "no_automatic_expiration": True,
            "funding_owner_approved": True,
            "incremental_usd_limit_approved": True,
            "budget_not_a_hard_cap": True,
            "independent_cleanup_owner": True,
        },
        "independent_controls": {
            "tls_and_egress_control_reviewed": True,
            "source_key_provenance_reviewed": True,
            "real_cli_budget_reviewed": True,
            "exact_bucket_trail_role_plan_reviewed": True,
        },
        "human_approvals": {
            "identity_and_state": "APPROVED_SEPARATELY",
            "resource_scope_and_cost": "APPROVED_SEPARATELY",
            "retention_hold_and_cleanup": "APPROVED_SEPARATELY",
        },
    }


def test_complete_fixture_is_static_only(valid_manifest: dict, tmp_path: Path, capsys) -> None:
    assert check_manifest(valid_manifest) == []
    path = tmp_path / "private-manifest.json"
    path.write_text(json.dumps(valid_manifest), encoding="utf-8")
    assert main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "live resource execution NOT authorized" in output


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("region", "us-west-2", "region differs"),
        ("reviewed_base_sha", "0" * 40, "baseline differs"),
        ("archive_bucket_name", "amzn-s3-demo-illegal", "bucket name missing"),
        ("archive_bucket_name", "xn--invalid-bucket", "bucket name missing"),
        ("schema", "other", "schema unsupported"),
        ("account_id", "wrong", "identifier missing"),
    ],
)
def test_fixed_identity_scope_rejections(
    valid_manifest: dict, field: str, replacement: str, message: str
) -> None:
    modified = deepcopy(valid_manifest)
    modified[field] = replacement
    assert any(message in issue for issue in check_manifest(modified, verify_source=False))


def test_absent_roles_fail_closed(valid_manifest: dict) -> None:
    modified = deepcopy(valid_manifest)
    for role in modified["external_operator_roles"].values():
        role["arn"] = ""
        role["role_id"] = ""
        for key in (
            "mfa_trust_verified",
            "role_id_verified",
            "effective_permissions_reviewed",
            "owner_session_custody_reviewed",
        ):
            role[key] = False
    issues = check_manifest(modified, verify_source=False)
    assert len(issues) >= 10
    assert all(any(name in issue for issue in issues) for name in ROLE_NAMES)


def test_role_separation_prevents_collisions(valid_manifest: dict) -> None:
    modified = deepcopy(valid_manifest)
    modified["external_operator_roles"]["cleanup"]["arn"] = modified["external_operator_roles"][
        "provisioner"
    ]["arn"]
    modified["external_operator_roles"]["cleanup"]["role_id"] = modified["external_operator_roles"][
        "provisioner"
    ]["role_id"]
    findings = check_manifest(modified, verify_source=False)
    assert any("duplicate role ARN" in issue for issue in findings)
    assert any("duplicate immutable RoleId" in issue for issue in findings)


def test_existing_security_audit_role_cannot_be_operator(valid_manifest: dict) -> None:
    modified = deepcopy(valid_manifest)
    modified["external_operator_roles"]["provisioner"]["arn"] = (
        "arn:aws:iam::" + modified["account_id"] + ":role/cloudsecops/CloudSecOps-AuditReadOnly"
    )
    assert any("provisioner" in issue for issue in check_manifest(modified, verify_source=False))


def test_state_must_be_encrypted_locked_and_distinct(valid_manifest: dict) -> None:
    modified = deepcopy(valid_manifest)
    state = modified["state_custody"]
    state["bucket_name"] = modified["archive_bucket_name"]
    state["use_lockfile"] = False
    state["bucket_versioning"] = 1  # int 1 must not equal boolean True
    state["backup_restoration_tested"] = False
    state["backend_iam_reviewed"] = False
    results = check_manifest(modified, verify_source=False)
    assert any("distinct reviewed bucket" in r for r in results)
    assert any("use_lockfile" in r for r in results)
    assert any("bucket_versioning" in r for r in results)
    assert any("backup_restoration_tested" in r for r in results)
    assert any("backend_iam_reviewed" in r for r in results)


@pytest.mark.parametrize(
    "field",
    (
        "no_automatic_expiration",
        "funding_owner_approved",
        "incremental_usd_limit_approved",
        "budget_not_a_hard_cap",
        "independent_cleanup_owner",
    ),
)
def test_retention_and_cost_must_be_explicit(valid_manifest: dict, field: str) -> None:
    modified = deepcopy(valid_manifest)
    modified["cost_and_retention"][field] = False
    assert any(field in reason for reason in check_manifest(modified, verify_source=False))


@pytest.mark.parametrize(
    "field",
    ("identity_and_state", "resource_scope_and_cost", "retention_hold_and_cleanup"),
)
def test_separate_owner_approvals_are_mandatory(valid_manifest: dict, field: str) -> None:
    modified = deepcopy(valid_manifest)
    modified["human_approvals"][field] = "PENDING"
    assert any(field in reason for reason in check_manifest(modified, verify_source=False))


@pytest.mark.parametrize(
    "field",
    (
        "tls_and_egress_control_reviewed",
        "source_key_provenance_reviewed",
        "real_cli_budget_reviewed",
        "exact_bucket_trail_role_plan_reviewed",
    ),
)
def test_independent_controls_required(valid_manifest: dict, field: str) -> None:
    modified = deepcopy(valid_manifest)
    modified["independent_controls"][field] = False
    assert any(field in reason for reason in check_manifest(modified, verify_source=False))


def test_cannot_accept_injected_unknown_attributes(valid_manifest: dict) -> None:
    modified = deepcopy(valid_manifest)
    modified["unknown_extra_input"] = "never"
    assert any(
        "unexpected keys" in reason for reason in check_manifest(modified, verify_source=False)
    )
    modified = deepcopy(valid_manifest)
    modified["state_custody"]["credentials"] = "never"
    assert any(
        "unexpected keys" in reason for reason in check_manifest(modified, verify_source=False)
    )


def test_json_duplicate_object_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicated.json"
    path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid bounded JSON"):
        read_private_manifest(path)


def test_json_nonfinite_rejected(tmp_path: Path) -> None:
    path = tmp_path / "nan.json"
    path.write_text('{"value": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid bounded JSON"):
        read_private_manifest(path)


def test_symlink_refused(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation disabled on this platform")
    with pytest.raises(ValueError, match="regular local file"):
        read_private_manifest(link)


def test_input_byte_limit_enforced(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b"x" * (MAX_INPUT_BYTES + 1))
    with pytest.raises(ValueError, match="maximum size"):
        read_private_manifest(path)


def test_bad_manifest_fails_cli_without_echoing_content(tmp_path: Path, capsys) -> None:
    private = tmp_path / "personal.json"
    private.write_text('{"something_private":"DO_NOT_ECHO_THIS"}', encoding="utf-8")
    assert main([str(private)]) == 1
    output = capsys.readouterr().out
    assert "AWS4C offline gate BLOCKED" in output
    assert "DO_NOT_ECHO_THIS" not in output


def test_usage_needs_one_explicit_manifest() -> None:
    assert main([]) == 2
    assert main(["one", "two"]) == 2
