"""Require all-package line coverage and each security module's actual branches."""

import json
import sys
from pathlib import Path


def main() -> int:
    try:
        report = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json").read_text())
        if report["meta"]["branch_coverage"] is not True:
            raise ValueError("branch measurement required")
        files = report["files"]
        if any(item.get("excluded_lines") for item in files.values()):
            raise ValueError("source exclusions are forbidden")
        passed = True
        for module in ("ingestion", "detection"):
            matches = [
                item["summary"]
                for name, item in files.items()
                if name.replace("\\", "/").endswith(f"cloudsecops_live/{module}.py")
            ]
            if len(matches) != 1 or matches[0]["num_branches"] <= 0:
                raise ValueError("missing module branch evidence")
            percentage = 100 * matches[0]["covered_branches"] / matches[0]["num_branches"]
            print(f"{module}.py: branch {percentage:.2f}% (required >=90%)")
            passed &= percentage >= 90
        totals = report["totals"]
        if totals["num_statements"] <= 0:
            raise ValueError("missing package line evidence")
        lines = 100 * totals["covered_lines"] / totals["num_statements"]
        print(f"all package lines: {lines:.2f}% (required >=90%)")
        return 0 if passed and lines >= 90 else 1
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError):
        print("Coverage gate failed: required coverage evidence unavailable.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
