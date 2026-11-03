"""Reference-only CLI for local synthetic consistency verification."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Never

import psycopg

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.independent_verifier import LIMITATIONS
from cloudsecops_live.verifier_runtime import load_config, run_verification


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise EvidenceError("VERIFIER_USAGE")


def parser() -> argparse.ArgumentParser:
    result = _Parser(description=__doc__)
    result.add_argument("--config", required=True, type=Path)
    result.add_argument("--recommendation-id", required=True)
    result.add_argument("--version", required=True, type=int)
    result.add_argument("--run-id")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        options = parser().parse_args(argv)
        receipt = run_verification(
            load_config(options.config), options.recommendation_id, options.version, options.run_id
        )
        public: dict[str, Any] = {
            key: receipt[key]
            for key in (
                "verification_id",
                "request_id",
                "result",
                "checker_version",
                "checker_digest",
            )
            if key in receipt
        }
        public.update(
            {
                "scope": "offline_synthetic_only",
                "source_kind": "synthetic",
                "authenticated": False,
                "limitations": list(LIMITATIONS),
            }
        )
        print(json.dumps(public, sort_keys=True))
        return 0 if receipt.get("result") == "verified" else 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, psycopg.Error):
        print(
            '{"error":"verifier_operation_failed","source_kind":"synthetic","authenticated":false}',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
