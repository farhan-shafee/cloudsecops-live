"""Explicit offline commands; no source-trust promotion or cloud credentials."""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import NoReturn

from cloudsecops_live.contracts import Limits, ParsedLog
from cloudsecops_live.detection import detect
from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.ingestion import parse_file


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's normal text includes caller-supplied filenames/arguments.
        raise EvidenceError("USAGE")


def _load(paths: Sequence[str]) -> list[ParsedLog]:
    if len(paths) > 16:
        raise EvidenceError("BATCH_LIMIT")
    remaining_archive = 10 * 1024 * 1024
    remaining_content = 100 * 1024 * 1024
    count = 0
    logs: list[ParsedLog] = []
    for path in paths:
        if remaining_archive < 1 or remaining_content < 1:
            raise EvidenceError("BATCH_LIMIT")
        limits = Limits(
            max_compressed_bytes=remaining_archive,
            max_expanded_bytes=remaining_content,
            max_records=max(1, 10_000 - count),
        )
        log = parse_file(Path(path), limits=limits)
        count += len(log.events)
        if count > 10_000:
            raise EvidenceError("BATCH_LIMIT")
        remaining_archive -= len(log.evidence.archive_bytes)
        remaining_content -= len(log.evidence.content_bytes)
        logs.append(log)
    return logs


def _raw_objects(logs: Sequence[ParsedLog]) -> list[dict[str, object]]:
    return [
        {
            "source_ref": log.evidence.source_ref,
            "archive_sha256": log.evidence.archive_sha256,
            "content_sha256": log.evidence.content_sha256,
            "archive_bytes": len(log.evidence.archive_bytes),
            "content_bytes": len(log.evidence.content_bytes),
            "record_count": len(log.events),
            "parser_version": log.evidence.parser_version,
            "schema_version": log.evidence.schema_version,
            "canonicalization_version": log.evidence.canonicalization_version,
            "source_kind": "synthetic",
            "authenticated": False,
        }
        for log in sorted(
            logs, key=lambda log: (log.evidence.source_ref, log.evidence.archive_sha256)
        )
    ]


def _normalized(logs: Sequence[ParsedLog]) -> list[dict[str, object]]:
    events = sorted(
        (event for log in logs for event in log.events),
        key=lambda event: (event.identity, event.event_time, event.record_sha256, event.references),
    )
    return [
        {
            "identity": asdict(event.identity),
            "event_time": event.event_time.isoformat().replace("+00:00", "Z"),
            "event_source": event.event_source,
            "event_name": event.event_name,
            "event_category": event.event_category,
            "event_type": event.event_type,
            "read_only": event.read_only,
            "has_error": event.has_error,
            "session": asdict(event.session) if event.session else None,
            "identity_reason": event.identity_reason,
            "record_sha256": event.record_sha256,
            "references": [asdict(reference) for reference in event.references],
            "schema_version": event.schema_version,
            "parser_version": event.parser_version,
            "canonicalization_version": event.canonicalization_version,
        }
        for event in events
    ]


def _error(code: str, status: int) -> int:
    print(
        json.dumps(
            {
                "error": {
                    "code": code,
                    "message": "Operation rejected; no partial result was emitted.",
                },
                "source_kind": "synthetic",
                "authenticated": False,
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return status


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "workspace":
        from cloudsecops_live.workspace_cli import main as workspace_main

        return workspace_main(arguments[1:])
    if arguments and arguments[0].startswith("db-"):
        from cloudsecops_live.durable_cli import main as durable_main

        return durable_main(arguments)
    parser = _Parser(description="Offline synthetic CloudTrail evidence; no AWS authentication.")
    parser.add_argument("command", choices=("import-synthetic", "detect-synthetic"))
    parser.add_argument("paths", nargs="+", help="Explicitly synthetic .json.gz fixture files")
    try:
        args = parser.parse_args(argv)
        logs = _load(args.paths)
        report = detect(logs)
        output = report.to_dict()
        output["operation"] = args.command
        output["raw_objects"] = _raw_objects(logs)
        output["limitations"] = [
            "Only synthetic fixture evidence was parsed; no AWS source was authenticated.",
            "Hashes establish byte consistency only. Signed-digest validation is not implemented.",
            "No network calls, persistent store, analyst review or response action occurred.",
            "Findings are teaching candidates, not evidence of malicious activity.",
        ]
        if args.command == "import-synthetic":
            # Shared deduplication/qualification remains active, but no findings are emitted.
            del output["findings"]
            output["normalized_events"] = _normalized(logs)
        print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        return 3 if report.has_conflicts else 0
    except EvidenceError as error:
        return _error(error.code, 64 if error.code == "USAGE" else 2)
    except Exception:
        # Fail the CLI with a fixed error; never convert an internal failure into a clean scan.
        return _error("INTERNAL_ERROR", 70)
