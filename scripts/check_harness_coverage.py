"""Require independently measured safety branches without changing application gates."""

import json
import sys
from pathlib import Path

MODULES = ("test_capacity", "test_service", "test_provision", "test_journal")


def main() -> int:
    try:
        report = json.loads(Path("harness-coverage.json").read_text(encoding="utf-8"))
        if report["meta"]["branch_coverage"] is not True:
            raise ValueError
        passed = True
        for module in MODULES:
            matches = [
                item
                for path, item in report["files"].items()
                if path.replace("\\", "/").endswith("scripts/" + module + ".py")
            ]
            if len(matches) != 1 or matches[0]["excluded_lines"]:
                raise ValueError
            summary = matches[0]["summary"]
            covered, total = summary["covered_branches"], summary["num_branches"]
            if type(total) is not int or type(covered) is not int or not 0 <= covered <= total:
                raise ValueError
            if total == 0:
                raise ValueError
            percentage = 100 * covered / total
            print(f"{module}: {covered}/{total} branches ({percentage:.2f}%; required >=85%)")
            passed &= percentage >= 85
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError):
        print("Harness branch evidence missing or invalid", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
