"""Preserve foundation gates; report durable modules separately without exclusions."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

FOUNDATION = ("__init__", "__main__", "cli", "contracts", "errors", "ingestion", "detection")
DURABLE = {
    "persistence": ("database", "storage"),
    "worker/outbox": ("worker", "outbox"),
    "cases": ("cases",),
}
SECURITY = (
    "workspace_auth",
    "workspace_web",
    "workspace_store",
    "workspace_roles",
    "workspace_config",
    "workspace_tls",
    "workspace_cli",
    "workflow_store",
    "workflow_web",
    "independent_verifier",
    "verifier_runtime",
    "verifier_cli",
    "pipeline_roles",
)


def module_summary(files: dict[str, Any], module: str) -> dict[str, int]:
    matches = [
        item["summary"]
        for name, item in files.items()
        if name.replace("\\", "/").endswith(f"cloudsecops_live/{module}.py")
    ]
    if len(matches) != 1:
        raise ValueError("missing or ambiguous module coverage evidence")
    summary: dict[str, int] = {}
    for key in ("num_statements", "covered_lines", "num_branches", "covered_branches"):
        value = matches[0][key]
        if type(value) is not int:
            raise ValueError("invalid coverage counter type")
        summary[key] = value
    for total, covered in (
        ("num_statements", "covered_lines"),
        ("num_branches", "covered_branches"),
    ):
        if not 0 <= summary[covered] <= summary[total]:
            raise ValueError("invalid coverage counters")
    return summary


def percentages(summaries: list[dict[str, int]]) -> tuple[float, float]:
    statements = sum(summary["num_statements"] for summary in summaries)
    branches = sum(summary["num_branches"] for summary in summaries)
    if statements <= 0:
        raise ValueError("missing line measurement")
    lines = 100 * sum(summary["covered_lines"] for summary in summaries) / statements
    branch = (
        100 * sum(summary["covered_branches"] for summary in summaries) / branches
        if branches
        else 100.0
    )
    return lines, branch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="?", type=Path, default=Path("coverage.json"))
    parser.add_argument("--require-durable", action="store_true")
    parser.add_argument("--require-security", action="store_true")
    options = parser.parse_args()
    try:
        report = json.loads(options.report.read_text(encoding="utf-8"))
        if report["meta"]["branch_coverage"] is not True:
            raise ValueError("branch measurement required")
        files = report["files"]
        if any(item.get("excluded_lines") for item in files.values()):
            raise ValueError("source exclusions are forbidden")
        passed = True
        for module in ("ingestion", "detection"):
            summary = module_summary(files, module)
            if summary["num_branches"] <= 0:
                raise ValueError("missing module branch evidence")
            percentage = 100 * summary["covered_branches"] / summary["num_branches"]
            print(f"{module}.py: branch {percentage:.2f}% (required >=90%)")
            passed &= percentage >= 90
        lines, _ = percentages([module_summary(files, module) for module in FOUNDATION])
        print(f"Phase 1A-1 foundation lines: {lines:.2f}% (required >=90%)")
        package_lines, package_branches = percentages([item["summary"] for item in files.values()])
        print(f"all package: lines {package_lines:.2f}%, branches {package_branches:.2f}%")
        if options.require_durable:
            passed &= package_lines >= 90
            print("Required full-database suite: all package lines >=90%")
        for group, modules in DURABLE.items():
            available = [
                module
                for module in modules
                if any(
                    name.replace("\\", "/").endswith(f"cloudsecops_live/{module}.py")
                    for name in files
                )
            ]
            if not available and not options.require_durable:
                continue
            summaries = [module_summary(files, module) for module in modules]
            if options.require_durable and any(
                summary["covered_lines"] <= 0 for summary in summaries
            ):
                raise ValueError("required durable module was not executed")
            group_lines, group_branches = percentages(summaries)
            print(f"{group}: lines {group_lines:.2f}%, branches {group_branches:.2f}% (reported)")
        if options.require_security:
            for module in SECURITY:
                summary = module_summary(files, module)
                if summary["num_branches"] <= 0 or summary["covered_lines"] <= 0:
                    raise ValueError("required security module was not executed")
                _, branches = percentages([summary])
                print(f"{module}.py: branch {branches:.2f}% (required >=85%)")
                passed &= branches >= 85
        return 0 if passed and lines >= 90 else 1
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError):
        print("Coverage gate failed: required coverage evidence unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
