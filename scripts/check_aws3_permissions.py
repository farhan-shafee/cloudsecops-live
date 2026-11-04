"""Check only bounded offline policy bytes and the single reviewed Terraform delta."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_readiness.permissions import validate_posture_policy

ROOT = Path(__file__).resolve().parents[1]
_LIMIT = 64 * 1024
_BASELINE = (
    "e4353e42bee0e9b05b4d9a9703ec676d87"  # pragma: allowlist secret - public source SHA256
    "a4796d53091ccd37ad424610718f19"  # pragma: allowlist secret - public source SHA256
)
_INSIGHT = {
    "Sid": "InspectTrailInsights",
    "Effect": "Allow",
    "Action": ["cloudtrail:GetInsightSelectors"],
    "Resource": "${local.trail_arn}",
    "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
}


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def _finite(value: str) -> None:
    raise ValueError("nonfinite JSON number")


def _read(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("unsupported source")
    with path.open("rb") as source:
        data = source.read(_LIMIT + 1)
    if len(data) > _LIMIT:
        raise ValueError("oversized source")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_finite)


def _validate_delta(document: Any) -> None:
    statements = document["locals"]["collector_policy"]["Statement"]
    if type(statements) is not list or len(statements) != 7 or statements[-1] != _INSIGHT:
        raise ValueError("wrong collector delta")
    statements.pop()
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if hashlib.sha256(canonical.encode()).hexdigest() != _BASELINE:
        raise ValueError("unexpected Terraform delta")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy-file",
        type=Path,
        default=ROOT / "infra/iam-readiness/posture-inspection.policy.json",
    )
    parser.add_argument(
        "--terraform-source", type=Path, default=ROOT / "infra/aws-offline/main.tf.json"
    )
    args = parser.parse_args()
    try:
        validate_posture_policy(_read(args.policy_file))
        _validate_delta(_read(args.terraform_source))
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RecursionError,
        EvidenceError,
    ):
        print("AWS3 offline permission source rejected")
        return 1
    print("AWS3 offline source contracts passed; effective IAM and live acceptance are unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
