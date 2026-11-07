"""Offline-only Phase 1B AWS4C pilot decision gate.

This tool never opens AWS sessions, spawns processes, imports a cloud SDK,
or authorizes Terraform. A positive assessment is *only* schema/structural
readiness for independent owner review, not permission to create resources.
"""

import json
import re
import sys
from pathlib import Path

from scripts.check_terraform import SOURCE, check_directory

SCHEMA = "cloudsecops.aws4c.pilot-gates/1"
BASE_COMMIT = (
    "f545a32dd0a16224356192f9ecde480bcc8cbd7d"  # pragma: allowlist secret - public reviewed Git SHA
)
ROLE_NAMES = (
    "provisioner",
    "cleanup",
    "collector_operator",
    "verifier_operator",
    "test_operator",
)
MUST_BE_TRUE = (
    "mfa_trust_verified",
    "role_id_verified",
    "effective_permissions_reviewed",
    "owner_session_custody_reviewed",
)
MAX_INPUT_BYTES = 16 * 1024
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
ROLE_ID_RE = re.compile(r"^AROA[A-Z0-9]{17}$")
RESTRICTED_BUCKET_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
RESTRICTED_BUCKET_SUFFIXES = (
    "-s3alias",
    "--ol-s3",
    ".mrap",
    "--x-s3",
    "--table-s3",
    "-an",
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("nonfinite JSON number")


def read_private_manifest(path: Path) -> dict[str, object]:
    """Load bounded plaintext without following a symlink or revealing its content."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("manifest must be a regular local file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("manifest exceeds maximum size")
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("manifest exceeds maximum size")
    try:
        decoded = raw.decode("utf-8")
        parsed = json.loads(
            decoded, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("manifest contains invalid bounded JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("manifest root must be an object")
    return parsed


def _keys(value: object, expected: set[str], label: str, problems: list[str]) -> dict:
    if not isinstance(value, dict):
        problems.append(label + " must be an object")
        return {}
    if set(value) != expected:
        problems.append(label + " has missing or unexpected keys")
    return value


def _true(value: object) -> bool:
    return type(value) is bool and value


def _bucket_name(value: object) -> bool:
    if not isinstance(value, str) or BUCKET_RE.fullmatch(value) is None:
        return False
    return not value.startswith(RESTRICTED_BUCKET_PREFIXES) and not value.endswith(
        RESTRICTED_BUCKET_SUFFIXES
    )


def check_manifest(doc: object, *, verify_source: bool = True) -> list[str]:
    """Return generic fail-closed issues, never treating the manifest as live proof."""
    problems: list[str] = []
    if verify_source:
        if check_directory(SOURCE):
            problems.append("frozen infrastructure contract differs from reviewed source")
    top = _keys(
        doc,
        {
            "schema",
            "account_id",
            "region",
            "reviewed_base_sha",
            "archive_bucket_name",
            "external_operator_roles",
            "state_custody",
            "cost_and_retention",
            "independent_controls",
            "human_approvals",
        },
        "manifest",
        problems,
    )
    if top.get("schema") != SCHEMA:
        problems.append("schema unsupported")
    acct = top.get("account_id")
    if not isinstance(acct, str) or ACCOUNT_RE.fullmatch(acct) is None:
        problems.append("private account identifier missing or malformed")
        acct = ""
    if top.get("region") != "us-east-1":
        problems.append("region differs from frozen Terraform target")
    if top.get("reviewed_base_sha") != BASE_COMMIT:
        problems.append("reviewed source baseline differs")
    bucket = top.get("archive_bucket_name")
    if not _bucket_name(bucket):
        problems.append("archive bucket name missing or invalid")

    roles = _keys(top.get("external_operator_roles"), set(ROLE_NAMES), "operator roles", problems)
    observed_arns: set[str] = set()
    observed_ids: set[str] = set()
    for name in ROLE_NAMES:
        entry = _keys(
            roles.get(name),
            {"arn", "role_id", *MUST_BE_TRUE},
            "operator " + name,
            problems,
        )
        arn = entry.get("arn")
        expected_prefix = "arn:aws:iam::" + acct + ":role/cloudsecops-operators/"
        if (
            not isinstance(arn, str)
            or not arn.startswith(expected_prefix)
            or re.fullmatch(r"[A-Za-z0-9+=,.@_/-]+", arn[len(expected_prefix) :]) is None
            or arn.endswith("/")
            or arn in observed_arns
        ):
            problems.append("operator " + name + " has unverified or duplicate role ARN")
        if isinstance(arn, str):
            observed_arns.add(arn)
        role_id = entry.get("role_id")
        if (
            not isinstance(role_id, str)
            or ROLE_ID_RE.fullmatch(role_id) is None
            or role_id in observed_ids
        ):
            problems.append("operator " + name + " has invalid or duplicate immutable RoleId")
        if isinstance(role_id, str):
            observed_ids.add(role_id)
        if not all(_true(entry.get(field)) for field in MUST_BE_TRUE):
            problems.append("operator " + name + " lacks independently checked custody")

    state = _keys(
        top.get("state_custody"),
        {
            "backend",
            "bucket_name",
            "key",
            "region",
            "encrypt",
            "bucket_versioning",
            "bucket_public_access_block",
            "use_lockfile",
            "exclusive_writer_reviewed",
            "backup_restoration_tested",
            "backend_iam_reviewed",
        },
        "state custody",
        problems,
    )
    if state.get("backend") != "s3" or state.get("region") != "us-east-1":
        problems.append("state backend is not approved regional S3")
    if not _bucket_name(state.get("bucket_name")) or state.get("bucket_name") == bucket:
        problems.append("state bucket must be a distinct reviewed bucket")
    if state.get("key") != "cloudsecops-live/aws4c/terraform.tfstate":
        problems.append("state key does not match private pilot contract")
    for required in (
        "encrypt",
        "bucket_versioning",
        "bucket_public_access_block",
        "use_lockfile",
        "exclusive_writer_reviewed",
        "backup_restoration_tested",
        "backend_iam_reviewed",
    ):
        if not _true(state.get(required)):
            problems.append("state control " + required + " not verified")

    retention = _keys(
        top.get("cost_and_retention"),
        {
            "manual_hold_review_days",
            "no_automatic_expiration",
            "funding_owner_approved",
            "incremental_usd_limit_approved",
            "budget_not_a_hard_cap",
            "independent_cleanup_owner",
        },
        "cost and retention",
        problems,
    )
    if (
        type(retention.get("manual_hold_review_days")) is not int
        or retention.get("manual_hold_review_days") != 90
    ):
        problems.append("90-day manual preservation review not accepted")
    for required in (
        "no_automatic_expiration",
        "funding_owner_approved",
        "incremental_usd_limit_approved",
        "budget_not_a_hard_cap",
        "independent_cleanup_owner",
    ):
        if not _true(retention.get(required)):
            problems.append("cost or retention decision " + required + " pending")

    controls = _keys(
        top.get("independent_controls"),
        {
            "tls_and_egress_control_reviewed",
            "source_key_provenance_reviewed",
            "real_cli_budget_reviewed",
            "exact_bucket_trail_role_plan_reviewed",
        },
        "independent controls",
        problems,
    )
    for name in (
        "tls_and_egress_control_reviewed",
        "source_key_provenance_reviewed",
        "real_cli_budget_reviewed",
        "exact_bucket_trail_role_plan_reviewed",
    ):
        if not _true(controls.get(name)):
            problems.append("independent safety control " + name + " pending")

    approvals = _keys(
        top.get("human_approvals"),
        {
            "identity_and_state",
            "resource_scope_and_cost",
            "retention_hold_and_cleanup",
        },
        "human approvals",
        problems,
    )
    for key in (
        "identity_and_state",
        "resource_scope_and_cost",
        "retention_hold_and_cleanup",
    ):
        if approvals.get(key) != "APPROVED_SEPARATELY":
            problems.append("separate owner approval " + key + " pending")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: check_aws4c_pilot.py PRIVATE_MANIFEST.json", file=sys.stderr)
        return 2
    try:
        issues = check_manifest(read_private_manifest(Path(args[0])))
    except (OSError, ValueError, RecursionError) as exc:
        # The exception's message is local and sanitized; it contains no user values.
        print("AWS4C offline gate BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    for issue in issues:
        print("AWS4C offline gate BLOCKED: " + issue)
    if issues:
        print("AWS4C live provisioning not authorized. Missing requirements: " + str(len(issues)))
        return 1
    print("AWS4C static readiness schema accepted; live resource execution NOT authorized.")
    print("Independently verify live IAM, state, pricing, authorization and change window.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
