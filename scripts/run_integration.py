"""Run required database tests and retain a credential-free JSON execution receipt."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

# Script invocation must resolve project-local safety modules before any service use.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.local_postgres import _restrict_directory  # noqa: E402
from scripts.test_capacity import CapacityError  # noqa: E402
from scripts.test_journal import JournalError  # noqa: E402
from scripts.test_service import (  # noqa: E402
    admin_from_environment,
    catalog_counts,
    enroll,
    observe,
    require_hosted,
)

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PYTEST_ARGS = {
    "--cov=cloudsecops_live",
    "--cov=scripts.test_capacity",
    "--cov=scripts.test_service",
    "--cov=scripts.test_provision",
    "--cov=scripts.test_journal",
    "--cov-append",
    "--cov-branch",
    "--cov-fail-under=0",
    "--cov-report=term-missing",
    "--cov-report=json",
    "--cov-report=xml",
    "--cov-report=json:harness-coverage.json",
}
PUBLIC_REASONS = {
    "DISPOSABLE_HOSTED_SERVICE_REQUIRED",
    "TEST_SERVICE_DSN_MISMATCH",
    "TEST_SERVICE_IDENTITY_MISMATCH",
    "TEST_SERVICE_SCOPE_MISSING",
    "TEST_SERVICE_OBSERVATION_FAILED",
    "TEST_SERVICE_IDENTITY_MISSING",
    "TEST_SERVICE_VOLUME_MISMATCH",
    "TEST_SERVICE_CONTRACT_MISSING",
    "TEST_SERVICE_CONTRACT_INVALID",
    "FRESH_TEST_SERVICE_REQUIRED",
    "INVALID_CAPACITY_OBSERVATION",
    "CAPACITY_DATABASE_LIMIT",
    "CAPACITY_ROLE_LIMIT",
    "CAPACITY_DATA_DISK",
    "CAPACITY_BACKING_DISK",
    "CAPACITY_SHARED_MEMORY",
    "CAPACITY_MEMORY",
    "CAPACITY_OOM",
    "CAPACITY_PIDS",
    "CAPACITY_CPU",
    "CAPACITY_RUN_LIMIT",
    "HARNESS_BUSY",
    "CREATION_OPERATOR_REVIEW_REQUIRED",
    "CREATION_QUARANTINE_FAILED",
    "CREATED_DATABASE_IDENTITY_MISMATCH",
    "INVALID_CREATION_PURPOSE",
    "journal_invalid_record",
    "journal_unsafe_path",
    "journal_corrupt",
    "journal_busy",
    "journal_identity_mismatch",
    "journal_operator_review_required",
    "journal_run_reused",
    "journal_write_failed",
    "journal_full",
    "journal_invalid_transition",
}
PUBLIC_REASONS |= {
    "INVALID_CAPACITY_OBSERVATION_" + stage
    for stage in (
        "DATA_FILESYSTEM",
        "SHARED_FILESYSTEM",
        "MEMORY_COUNTERS",
        "MEMORY_EVENTS",
        "PID_CPU",
        "BACKING_DISK",
        "RESULT_FIELDS",
    )
}


def run_private(command: list[str], diagnostic: Path) -> int:
    """Bound private output without buffering PostgreSQL exceptions in public logs."""
    limit = 8 * 1024**2
    failed = threading.Event()
    with diagnostic.open("xb") as output:
        if sys.platform != "win32":
            diagnostic.chmod(0o600)
        with subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            assert process.stdout is not None

            def copy() -> None:
                size = 0
                try:
                    while block := process.stdout.read(16384):
                        size += len(block)
                        if size > limit:
                            failed.set()
                            process.kill()  # Only this runner's own disposable pytest child.
                            break
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                except OSError:
                    failed.set()
                    process.kill()

            reader = threading.Thread(target=copy, daemon=True)
            reader.start()
            try:
                code = process.wait(timeout=15 * 60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                code = 2
            reader.join(timeout=10)
            if reader.is_alive() or failed.is_set():
                return 2
            return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument(
        "--suite", choices=["integration", "harness_postgres"], default="integration"
    )
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args()
    if set(args.pytest_args) - ALLOWED_PYTEST_ARGS or any(
        os.environ.get(key) for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")
    ):
        print(json.dumps({"error": "UNSUPPORTED_TEST_RUNNER_ARGUMENT", "tests_started": False}))
        return 2
    try:
        require_hosted()
        service = enroll(ROOT)
    except (CapacityError, JournalError, OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, CapacityError) else "TEST_SERVICE_PREFLIGHT_FAILED"
        if reason not in PUBLIC_REASONS:
            reason = "TEST_SERVICE_PREFLIGHT_FAILED"
        print(
            json.dumps(
                {"error": "TEST_SERVICE_PREFLIGHT_FAILED", "reason": reason, "tests_started": False}
            )
        )
        return 2
    private = ROOT / ".tools" / "private"
    private.mkdir(parents=True, exist_ok=True)
    _restrict_directory(private)
    with tempfile.TemporaryDirectory(prefix="integration-", dir=private) as temporary:
        junit = Path(temporary) / "results.xml"
        diagnostic = private / (
            "integration-output-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + ".log"
        )
        code = run_private(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/" + args.suite,
                "-o",
                "norecursedirs=",
                "-p",
                "no:cacheprovider",
                f"--basetemp={Path(temporary) / 'pytest-temp'}",
                f"--junitxml={junit}",
                *args.pytest_args,
            ],
            diagnostic,
        )
        counts = {"tests": 0, "passed": 0, "failures": 0, "errors": 0, "skipped": 0}
        failures: list[dict[str, str]] = []
        properties: dict[str, str] = {}
        if junit.exists() and junit.stat().st_size <= 8 * 1024**2:
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
                if outcome in {"failure", "error", "skipped"}:
                    # Parameter IDs can contain runtime database names or secrets.
                    # Publish only the static source function name.
                    name = case.attrib.get("name", "").split("[", 1)[0]
                    safe_name = (
                        name
                        if re.fullmatch(r"[A-Za-z0-9_.\[\]=-]{1,180}", name)
                        else "redacted_test"
                    )
                    failure = case.find(outcome)
                    text = "" if failure is None else str(failure.text)
                    code_match = re.search(
                        r"\b(?:CAPACITY_|TEST_SERVICE_|CREATION_|INVALID_CAPACITY_)[A-Z_]{1,64}\b"
                        r"|\bjournal_[a-z_]{1,64}\b",
                        text,
                    )
                    failures.append(
                        {
                            "test": safe_name,
                            "outcome": outcome,
                            "reason": code_match.group()
                            if code_match and code_match.group() in PUBLIC_REASONS
                            else "test_failure",
                        }
                    )
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
        # Capture aggregate end counts for the separate fault suite as well. No
        # test database, owner, cluster, container or volume identities go public.
        try:
            with admin_from_environment().connect() as conn:
                final_counts = catalog_counts(conn)
            final_resources = observe(ROOT, service)
        except Exception:
            final_counts, final_resources, code = {}, {}, 2
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
            "failure_summary": failures,
            "pytest_exit_code": code,
            "required_tests_skipped": counts["skipped"] != 0,
            "retained_databases_created": int(properties.get("retained_databases_created", "-1")),
            "capacity": json.loads(properties.get("capacity_summary", "{}")),
            "suite": args.suite,
            "final_catalog_counts": final_counts,
            "final_resources": final_resources,
            "fault_methods": {
                "controlled_exception": [
                    "ingestion commit",
                    "worker commit",
                    "sink receipt and ack",
                ],
                "genuine_process_termination": [
                    "worker before commit",
                    "worker after commit",
                    "independent verifier before commit",
                    "independent verifier after commit",
                ],
                "database_connection_interruption": (
                    "pg_terminate_backend on this test connection only; "
                    "includes review, verification and closure transactions"
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
        print(
            json.dumps(
                {
                    "suite": args.suite,
                    "counts": counts,
                    "failure_summary": failures,
                    "exit_code": code,
                },
                sort_keys=True,
            )
        )
    minimum = {"integration": 174, "harness_postgres": 19}[args.suite]
    return code or int(counts["skipped"] != 0 or counts["tests"] < minimum)


if __name__ == "__main__":
    raise SystemExit(main())
