"""Run required database tests and retain a credential-free JSON execution receipt."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args()
    private = ROOT / ".tools" / "private"
    private.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="integration-", dir=private) as temporary:
        junit = Path(temporary) / "results.xml"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/integration",
                "-o",
                "norecursedirs=",
                "-p",
                "no:cacheprovider",
                f"--basetemp={Path(temporary) / 'pytest-temp'}",
                f"--junitxml={junit}",
                *args.pytest_args,
            ],
            cwd=ROOT,
            check=False,
        )
        counts = {"tests": 0, "passed": 0, "failures": 0, "errors": 0, "skipped": 0}
        properties: dict[str, str] = {}
        if junit.exists():
            tree = ET.parse(junit).getroot()
            properties = {p.attrib["name"]: p.attrib["value"] for p in tree.iter("property")}
            for case in tree.iter("testcase"):
                counts["tests"] += 1
                outcome = next(
                    (key for key in ("failure", "error", "skipped") if case.find(key) is not None),
                    None,
                )
                counts[
                    {"failure": "failures", "error": "errors", "skipped": "skipped"}.get(
                        outcome, "passed"
                    )
                ] += 1
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        )
        receipt = {
            "schema": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "source_revision": revision,
            "source_worktree_dirty": dirty,
            "postgresql": properties.get("postgresql_version", "unavailable"),
            "python": platform.python_version(),
            "psycopg": importlib.metadata.version("psycopg"),
            "pytest": importlib.metadata.version("pytest"),
            "fixture_sha256": {
                str(path.relative_to(ROOT)).replace("\\", "/"): sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted((ROOT / "tests" / "integration").glob("*.py"))
            },
            "source_sha256": {
                str(path.relative_to(ROOT)).replace("\\", "/"): sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted((ROOT / "src").rglob("*"))
                if path.suffix in {".py", ".sql"}
            },
            "counts": counts,
            "pytest_exit_code": result.returncode,
            "required_tests_skipped": counts["skipped"] != 0,
            "fault_methods": {
                "controlled_exception": [
                    "ingestion commit",
                    "worker commit",
                    "sink receipt and ack",
                ],
                "genuine_process_termination": ["worker before commit", "worker after commit"],
                "database_connection_interruption": (
                    "pg_terminate_backend on this test connection only"
                ),
                "backup_restore": (
                    "pg_dump custom archive and pg_restore into retained fresh database"
                ),
            },
            "database_cleanup": (
                "none; csl_test_ databases retained for explicitly scoped operator cleanup"
            ),
        }
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return result.returncode or int(counts["skipped"] != 0 or counts["tests"] == 0)


if __name__ == "__main__":
    raise SystemExit(main())
