"""Three reviewed offline workers; no client discovery or source authentication."""

from __future__ import annotations

from botocore.credentials import Credentials  # type: ignore[import-untyped]

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.collection import (
    CollectionLimits,
    MemoryLedger,
    collect,
)
from cloudsecops_live.integrations.aws_readiness.requests import ParsedRequest, parse_request
from cloudsecops_live.integrations.aws_readiness.sessions import Purpose, assemble_session
from cloudsecops_live.integrations.aws_readiness.transport import ArchiveTransport, TapeTransport


def _start(value: object, purpose: Purpose) -> tuple[ParsedRequest, TapeTransport]:
    request = parse_request(value, purpose)
    # Literal fictional reference only. No credential enters IPC, environment or
    # files, and no SDK Session/client is created from this deliberately fake key.
    credentials = Credentials(
        "ASIA" + "Q" * 16,
        "fictional-offline-secret-never-valid" + "Q" * 12,
        "fictional-offline-token-never-valid",
        method="explicit",
    )
    session = assemble_session(
        request.expected, request.issuance, request.observed, credentials, now=request.as_of
    )
    return request, TapeTransport(request, session)


def _pages(
    tape: TapeTransport, operation: str, parameters: dict[str, object], field: str, token: str
) -> list[object]:
    output: list[object] = []
    seen: set[str] = set()
    while True:
        response = tape.read(operation, parameters)
        items = response.get(field)
        if type(items) is not list or len(output) + len(items) > 64:
            raise EvidenceError("AWS3_PAGINATION")
        output.extend(items)
        following = response.get(token)
        if operation.startswith("iam:"):
            truncated = response.get("IsTruncated")
            if type(truncated) is not bool or truncated != (following is not None):
                raise EvidenceError("AWS3_PAGINATION")
        if following is None:
            return output
        if type(following) is not str or not 1 <= len(following) <= 1024 or following in seen:
            raise EvidenceError("AWS3_PAGINATION")
        seen.add(following)
        parameters = {**parameters, token: following}


def _public(purpose: Purpose, tape: TapeTransport) -> dict[str, object]:
    tape.finish()
    return {
        "schema_version": "aws-offline-readiness/1",
        "purpose": purpose.value,
        "state": "offline_readiness_observation",
        "source_kind": "aws_shaped_unverified",
        "authenticated": False,
        "trusted_findings_available": False,
        "closure_available": False,
        "budget": tape.public_dict(),
    }


def inspect_posture(value: object) -> dict[str, object]:
    request, tape = _start(value, Purpose.POSTURE)
    tape.identity()
    name = request.expected.role_arn.rsplit("/", 1)[-1]
    parameters: dict[str, object] = {"RoleName": name}
    role = tape.read("iam:GetRole", parameters).get("Role")
    if type(role) is not dict or (role.get("Arn"), role.get("RoleId")) != (
        request.expected.role_arn,
        request.expected.role_id,
    ):
        raise EvidenceError("AWS3_ROLE_IDENTITY")
    policies = _pages(tape, "iam:ListRolePolicies", parameters, "PolicyNames", "Marker")
    if (
        any(type(item) is not str for item in policies)
        or len(set(policies)) != len(policies)
        or not set(request.inline_policy_names) <= set(policies)
    ):
        raise EvidenceError("AWS3_POLICY_OBSERVATION")
    for policy in request.inline_policy_names:
        result = tape.read("iam:GetRolePolicy", {**parameters, "PolicyName": policy})
        if (
            result.get("RoleName") != name
            or result.get("PolicyName") != policy
            or type(result.get("PolicyDocument")) is not dict
        ):
            raise EvidenceError("AWS3_POLICY_OBSERVATION")
    attached = _pages(
        tape, "iam:ListAttachedRolePolicies", parameters, "AttachedPolicies", "Marker"
    )
    trails = _pages(tape, "cloudtrail:ListTrails", {}, "Trails", "NextToken")
    buckets = _pages(tape, "s3:ListBuckets", {}, "Buckets", "ContinuationToken")
    if any(type(item) is not dict for item in [*attached, *trails, *buckets]):
        raise EvidenceError("AWS3_INVENTORY_OBSERVATION")
    configuration = tape.read(
        "s3control:GetPublicAccessBlock", {"AccountId": request.expected.account}
    ).get("PublicAccessBlockConfiguration")
    keys = {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}
    if (
        type(configuration) is not dict
        or set(configuration) != keys
        or any(type(item) is not bool for item in configuration.values())
    ):
        raise EvidenceError("AWS3_ACCOUNT_OBSERVATION")
    review_required = (
        len(policies) != len(request.inline_policy_names)
        or bool(attached)
        or "PermissionsBoundary" in role
    )
    return {
        **_public(Purpose.POSTURE, tape),
        "state": "owner_review_required" if review_required else "offline_readiness_observation",
        "identity_policy_review_required": review_required,
        "trail_count": len(trails),
        "bucket_count": len(buckets),
        "requested_inline_policy_count": len(request.inline_policy_names),
        "unrequested_inline_policy_count": len(policies) - len(request.inline_policy_names),
        "attached_policy_count": len(attached),
        "permissions_boundary_observed": "PermissionsBoundary" in role,
        "account_public_access_block_all_enabled": all(configuration.values()),
        "effective_permissions_verified": False,
        "policy_contents_verified": False,
        "discovered_resources_read": False,
    }


def _archive(value: object, purpose: Purpose) -> dict[str, object]:
    request, tape = _start(value, purpose)
    scope = request.scope
    if scope is None:
        raise EvidenceError("AWS3_SCOPE")
    batch = collect(
        ArchiveTransport(tape, scope),
        scope,
        MemoryLedger(),
        request.checkpoint,
        clock=tape.now,
        limits=CollectionLimits(max_pages=request.policy.max_pages, attempts=1),
    )
    if purpose is Purpose.VERIFIER and (
        not batch.objects
        or batch.conflicts
        or tuple(obj.log.content_sha256 for obj in batch.objects) != request.expected_content_hashes
    ):
        raise EvidenceError("AWS3_CONSISTENCY")
    return {
        **_public(purpose, tape),
        **batch.to_public_dict(),
        "worker_schema_version": "aws-offline-readiness/1",
        "controlled_fixture_consistency": purpose is Purpose.VERIFIER,
    }


def collect_archive(value: object) -> dict[str, object]:
    return _archive(value, Purpose.COLLECTOR)


def verify_archive(value: object) -> dict[str, object]:
    return _archive(value, Purpose.VERIFIER)
