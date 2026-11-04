"""Private, bounded, fsynced creation provenance; never a disposal authority.

The hash chain and separately durable head detect accidental corruption and tail
loss. They do not authenticate records against an operator who can edit both.
Uncertain/failed operations require human review; this module cannot repair,
adopt, recreate, delete, or connect to any database.

POSIX directory entries are synchronized before a creation intent may be used.
Windows supports offline journal tests and file flushing, but this module does
not claim Windows directory-entry power-loss durability. Actual database
provisioning is restricted separately to disposable hosted Linux services.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import TracebackType
from typing import Any

from scripts.local_postgres import LocalPostgresError, _restrict_directory

MAX_JOURNAL_BYTES = 10 * 1024**2
MAX_RECORD_BYTES = 8192
ZERO_HASH = "0" * 64
SCHEMA = "test-creation-journal/1"
EVENTS = {
    "run_started",
    "run_finished",
    "run_aborted",
    "intent",
    "created",
    "quarantined",
    "ready",
    "provisioned",
    "rejected",
    "failed",
    "uncertain",
}
METADATA = {
    "source_revision",
    "source_tree",
    "harness_version",
    "harness_sha256",
    "cluster_id",
    "service_id",
    "volume_id",
    "postmaster_started",
    "database_count",
    "role_count",
}
FIELDS = METADATA | {
    "event",
    "creation_id",
    "database_name",
    "oid",
    "owner",
    "test",
    "purpose",
    "outcome",
    "retention",
    "phase",
}
GENERATED = {"schema", "run_id", "time", "seq", "previous_sha256", "sha256"}
REQUIRED_METADATA = {"source_revision", "harness_version", "cluster_id", "service_id", "volume_id"}


class JournalError(Exception):
    """Fixed, nonsensitive public reason; never includes a record or OS error."""


def _encode(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JournalError("journal_corrupt")
        result[key] = value
    return result


def _check_transition(record: dict[str, Any], records: list[dict[str, Any]], run_id: str) -> None:
    if "creation_id" not in record:
        return
    history = [
        item
        for item in records
        if item.get("creation_id") == record["creation_id"] and item["run_id"] == run_id
    ]
    prior = history[-1] if history else None
    transitions = {
        "intent": None,
        "created": "intent",
        "quarantined": "created",
        "ready": "quarantined",
        "provisioned": "ready",
        "rejected": "intent",
    }
    event = record["event"]
    expected = transitions.get(event)
    if (
        (event in transitions and (prior["event"] if prior else None) != expected)
        or (event in {"failed", "uncertain"} and prior is None)
        or (prior is not None and prior["database_name"] != record["database_name"])
        or (event == "created" and (not {"oid", "owner"} <= record.keys() or record["oid"] == 0))
        or (event == "intent" and not {"purpose", "test", "retention"} <= record.keys())
        or any(
            key in record and key in previous and record[key] != previous[key]
            for previous in history
            for key in ("oid", "owner")
        )
    ):
        raise JournalError("journal_invalid_transition")


def _validate(fields: dict[str, Any], *, generated: bool = False) -> None:
    allowed = FIELDS | GENERATED if generated else FIELDS
    if not isinstance(fields, dict) or set(fields) - allowed or fields.get("event") not in EVENTS:
        raise JournalError("journal_invalid_record")
    for key, value in fields.items():
        numeric = key in {"oid", "seq", "database_count", "role_count"}
        if numeric != (type(value) is int):
            raise JournalError("journal_invalid_record")
        if isinstance(value, str):
            if len(value) > (256 if key == "test" else 160) or any(
                not c.isprintable() for c in value
            ):
                raise JournalError("journal_invalid_record")
            if re.search(
                r"postgres(?:ql)?://|password\s*=|dbname\s*=|host\s*=|token\s*=", value, re.I
            ):
                raise JournalError("journal_invalid_record")
        elif type(value) is not int or value < 0 or value > 2**64 - 1:
            raise JournalError("journal_invalid_record")
    for key, length in (("source_revision", 40), ("source_tree", 40), ("harness_sha256", 64)):
        if key in fields and not re.fullmatch(f"[a-f0-9]{{{length}}}", str(fields[key])):
            raise JournalError("journal_invalid_record")
    for key in ("creation_id", "run_id"):
        if key in fields and not re.fullmatch(r"[a-f0-9]{32}", str(fields[key])):
            raise JournalError("journal_invalid_record")
    if "database_name" in fields and not re.fullmatch(
        r"csl_test_[a-f0-9]{32}", fields["database_name"]
    ):
        raise JournalError("journal_invalid_record")
    if "owner" in fields and not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}", fields["owner"]):
        raise JournalError("journal_invalid_record")
    if "retention" in fields and fields["retention"] != "retain_operator_review":
        raise JournalError("journal_invalid_record")
    if fields["event"] == "run_started" and not REQUIRED_METADATA <= fields.keys():
        raise JournalError("journal_invalid_record")
    if fields["event"] not in {"run_started", "run_finished", "run_aborted"}:
        if not {"creation_id", "database_name"} <= fields.keys():
            raise JournalError("journal_invalid_record")
    if len(_encode(fields)) > MAX_RECORD_BYTES:
        raise JournalError("journal_invalid_record")


def _safe(directory: Path, *, create: bool = False) -> None:
    if not directory.is_absolute() or len(directory.parts) > 64 or ".." in directory.parts:
        raise JournalError("journal_unsafe_path")
    # Reject every existing symlink component, not only the journal filename.
    components = (directory, *directory.parents)
    for component in components:
        if component.is_symlink() or (os.name == "nt" and component.is_junction()):
            raise JournalError("journal_unsafe_path")
    if create:
        # mkdir(parents=True) followed only by fsync(leaf) can lose an entire
        # ledger subtree after power loss. Persist each new directory name in
        # its parent before creating the next child or accepting any intent.
        # Resync existing ancestors too: a prior failed sync may have left an
        # existing but not yet durable entry. There is no automatic adoption of
        # an unflushed path merely because it now exists.
        for component in reversed(components):
            if not component.exists():
                component.mkdir(mode=0o700)
            if not component.is_dir():
                raise JournalError("journal_unsafe_path")
            _sync_directory(component.parent)
            _sync_directory(component)
    if not directory.is_dir():
        raise JournalError("journal_unsafe_path")
    for name in ("journal.jsonl", "journal.lock", "head.json", "head.pending"):
        path = directory / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise JournalError("journal_unsafe_path")


def _open(path: Path, flags: int) -> int:
    descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        raise JournalError("journal_unsafe_path")
    if os.name != "nt" and info.st_mode & 0o077:
        os.close(descriptor)
        raise JournalError("journal_unsafe_path")
    return descriptor


def _sync_directory(directory: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _load(directory: Path) -> list[dict[str, Any]]:
    _safe(directory)
    path, head = directory / "journal.jsonl", directory / "head.json"
    if not path.exists() and not head.exists():
        return []
    if not path.exists() or not head.exists() or path.stat().st_size > MAX_JOURNAL_BYTES:
        raise JournalError("journal_corrupt")
    with os.fdopen(_open(path, os.O_RDONLY), "rb") as stream:
        raw = stream.read(MAX_JOURNAL_BYTES + 1)
    if not raw or not raw.endswith(b"\n"):
        raise JournalError("journal_corrupt")
    records: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for line in raw.splitlines():
        if len(line) > MAX_RECORD_BYTES:
            raise JournalError("journal_corrupt")
        record = json.loads(line, object_pairs_hook=_unique_pairs)
        if not isinstance(record, dict) or not GENERATED <= record.keys():
            raise JournalError("journal_corrupt")
        _validate(record, generated=True)
        digest = record["sha256"]
        payload = {key: value for key, value in record.items() if key != "sha256"}
        if (
            record["schema"] != SCHEMA
            or record["seq"] != len(records) + 1
            or record["previous_sha256"] != previous
            or digest != sha256(_encode(payload)).hexdigest()
        ):
            raise JournalError("journal_corrupt")
        _check_transition(record, records, record["run_id"])
        records.append(record)
        previous = digest
    if head.stat().st_size > 256:
        raise JournalError("journal_corrupt")
    with os.fdopen(_open(head, os.O_RDONLY), "rb") as stream:
        checkpoint = json.loads(stream.read(257), object_pairs_hook=_unique_pairs)
    if checkpoint != {"seq": len(records), "sha256": previous}:
        raise JournalError("journal_corrupt")
    return records


def read_records(directory: Path) -> list[dict[str, Any]]:
    """Read-only receipt recovery; corruption is never automatically repaired."""
    try:
        return _load(directory)
    except JournalError as exc:
        if str(exc) in {"journal_invalid_record", "journal_invalid_transition"}:
            raise JournalError("journal_corrupt") from None
        raise
    except (OSError, ValueError, TypeError, UnicodeError):
        raise JournalError("journal_corrupt") from None


def pending_creations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return unresolved private records; ready is not permission to delete."""
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        if "creation_id" in record:
            latest[(record["run_id"], record["creation_id"])] = record
    return [
        record for record in latest.values() if record["event"] not in {"provisioned", "rejected"}
    ]


class Journal:
    """One nonblocking process lock covers the run and every durable transition."""

    def __init__(self, directory: Path, run_id: str, metadata: dict[str, Any]) -> None:
        self.directory = directory
        self.run_id = run_id
        self.metadata = dict(metadata)
        self.records: list[dict[str, Any]] = []
        self._lock: int | None = None
        self._stream: int | None = None
        self._failed = False
        _validate({"event": "run_started", "run_id": run_id, **metadata}, generated=True)
        if set(metadata) - METADATA:
            raise JournalError("journal_invalid_record")

    def __enter__(self) -> Journal:
        try:
            _safe(self.directory, create=True)
            _restrict_directory(self.directory)
            self._lock = _open(self.directory / "journal.lock", os.O_RDWR | os.O_CREAT)
            if os.fstat(self._lock).st_size == 0:
                os.write(self._lock, b"0")
                os.fsync(self._lock)
            os.lseek(self._lock, 0, os.SEEK_SET)
            try:
                if os.name == "nt":
                    lock_module = importlib.import_module("msvcrt")
                    lock_module.locking(self._lock, lock_module.LK_NBLCK, 1)
                else:
                    lock_module = importlib.import_module("fcntl")
                    lock_module.flock(self._lock, lock_module.LOCK_EX | lock_module.LOCK_NB)
            except OSError:
                raise JournalError("journal_busy") from None
            self.records = read_records(self.directory)
            if any(
                record["event"] == "run_started"
                and any(
                    record[key] != self.metadata[key]
                    for key in ("cluster_id", "service_id", "volume_id")
                )
                for record in self.records
            ):
                raise JournalError("journal_identity_mismatch")
            if pending_creations(self.records):
                raise JournalError("journal_operator_review_required")
            if any(record["run_id"] == self.run_id for record in self.records):
                raise JournalError("journal_run_reused")
            self._stream = _open(
                self.directory / "journal.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT
            )
            self.append({"event": "run_started", **self.metadata})
            return self
        except JournalError:
            self.close()
            raise
        except (OSError, ValueError, TypeError, subprocess.SubprocessError, LocalPostgresError):
            self.close()
            raise JournalError("journal_unsafe_path") from None

    def append(self, record: dict[str, Any]) -> None:
        if self._failed or self._stream is None:
            raise JournalError("journal_write_failed")
        _validate(record)
        _check_transition(record, self.records, self.run_id)
        payload = {
            **record,
            "schema": SCHEMA,
            "run_id": self.run_id,
            "time": datetime.now(UTC).isoformat(),
            "seq": len(self.records) + 1,
            "previous_sha256": self.records[-1]["sha256"] if self.records else ZERO_HASH,
        }
        final = {**payload, "sha256": sha256(_encode(payload)).hexdigest()}
        data = _encode(final) + b"\n"
        if len(data) > MAX_RECORD_BYTES:
            raise JournalError("journal_invalid_record")
        if os.fstat(self._stream).st_size + len(data) > MAX_JOURNAL_BYTES:
            self._failed = True
            raise JournalError("journal_full")
        try:
            view = memoryview(data)
            while view:
                count = os.write(self._stream, view)
                if count <= 0:
                    raise OSError("short write")
                view = view[count:]
            os.fsync(self._stream)
            checkpoint = _encode({"seq": final["seq"], "sha256": final["sha256"]}) + b"\n"
            descriptor = _open(
                self.directory / "head.pending", os.O_WRONLY | os.O_CREAT | os.O_EXCL
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(checkpoint)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(self.directory / "head.pending", self.directory / "head.json")
            _sync_directory(self.directory)
        except (OSError, JournalError):
            self._failed = True
            raise JournalError("journal_write_failed") from None
        self.records.append(final)

    def close(self) -> None:
        if self._stream is not None:
            os.close(self._stream)
            self._stream = None
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if not self._failed:
                self.append({"event": "run_finished" if exc_type is None else "run_aborted"})
        finally:
            self.close()
