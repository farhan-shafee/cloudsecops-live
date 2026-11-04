"""Independent invariants for the private creation ledger; no database access."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from hashlib import sha256

import pytest


def journal_api():
    from scripts import test_journal

    return test_journal


def metadata():
    return {
        "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "harness_version": "test-harness/1",
        "harness_sha256": "c" * 64,
        "cluster_id": "1234567890123456789",
        "service_id": "d" * 64,
        "volume_id": "e" * 64,
    }


def intent():
    return {
        "event": "intent",
        "creation_id": "1" * 32,
        "database_name": "csl_test_" + "2" * 32,
        "test": "tests/integration/test_security.py::test_expected_failure",
        "purpose": "migration",
        "retention": "retain_operator_review",
    }


def test_journal_records_intent_before_creation_and_exact_private_identity(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path / "private", "3" * 32, metadata()) as journal:
        journal.append(intent())
        journal.append({**intent(), "event": "created", "oid": 12345, "owner": "owner"})
        journal.append({**intent(), "event": "quarantined"})
        journal.append({**intent(), "event": "ready"})
        journal.append({**intent(), "event": "provisioned", "outcome": "migration_complete"})
    records = api.read_records(tmp_path / "private")
    assert [record["event"] for record in records] == [
        "run_started",
        "intent",
        "created",
        "quarantined",
        "ready",
        "provisioned",
        "run_finished",
    ]
    assert records[2]["oid"] == 12345
    assert records[0]["cluster_id"] == "1234567890123456789"
    assert all(record["run_id"] == "3" * 32 for record in records)
    assert api.pending_creations(records) == []
    assert [record["seq"] for record in records] == list(range(1, 8))


def test_unresolved_intent_blocks_another_run_without_recreation(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
    before = (tmp_path / "journal.jsonl").read_bytes()
    with pytest.raises(api.JournalError, match="journal_operator_review_required"):
        with api.Journal(tmp_path, "4" * 32, metadata()):
            pytest.fail("must not adopt unresolved creation")
    assert (tmp_path / "journal.jsonl").read_bytes() == before


@pytest.mark.parametrize("event", ["failed", "uncertain"])
def test_failure_never_becomes_success(tmp_path, event):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
        journal.append({**intent(), "event": event, "outcome": "creation_unconfirmed"})
    assert len(api.pending_creations(api.read_records(tmp_path))) == 1


def test_precreation_rejection_is_an_explicit_terminal_state(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
        journal.append({**intent(), "event": "rejected", "outcome": "capacity_limit"})
    with api.Journal(tmp_path, "4" * 32, metadata()):
        pass
    assert api.pending_creations(api.read_records(tmp_path)) == []


@pytest.mark.parametrize("alteration", ["partial", "contents", "truncate_record", "head"])
def test_corruption_and_complete_tail_truncation_require_review(tmp_path, alteration):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    path = tmp_path / "journal.jsonl"
    original = path.read_bytes()
    if alteration == "partial":
        path.write_bytes(original + b'{"event":')
    elif alteration == "contents":
        path.write_bytes(original.replace(b"run_started", b"run_changed"))
    elif alteration == "truncate_record":
        path.write_bytes(original.splitlines(keepends=True)[0])
    else:
        (tmp_path / "head.json").write_text("{}", encoding="utf-8")
    with pytest.raises(api.JournalError, match="journal_corrupt"):
        api.read_records(tmp_path)


def test_concurrent_writer_is_rejected_before_append(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        with pytest.raises(api.JournalError, match="journal_busy"):
            with api.Journal(tmp_path, "4" * 32, metadata()):
                pass


def test_process_death_releases_lock_and_preserves_unresolved_intent(tmp_path):
    api = journal_api()
    script = (
        "import json, os, sys; from pathlib import Path; "
        "from scripts.test_journal import Journal; "
        "j=Journal(Path(sys.argv[1]), '3'*32,json.loads(sys.argv[2])); j.__enter__(); "
        "j.append(json.loads(sys.argv[3])); os._exit(19)"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), json.dumps(metadata()), json.dumps(intent())],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 19, result.stderr.decode()
    assert len(api.pending_creations(api.read_records(tmp_path))) == 1
    with pytest.raises(api.JournalError, match="journal_operator_review_required"):
        with api.Journal(tmp_path, "4" * 32, metadata()):
            pass


@pytest.mark.parametrize(
    "extra",
    [
        {"dsn": "secret"},
        {"password": "secret"},  # pragma: allowlist secret - rejection fixture
        {"payload": {}},
    ],  # pragma: allowlist secret - fixture
)
def test_unapproved_fields_are_rejected_and_not_written(tmp_path, extra):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        with pytest.raises(api.JournalError, match="journal_invalid_record"):
            journal.append({**intent(), **extra})
    assert "secret" not in (tmp_path / "journal.jsonl").read_text()


@pytest.mark.parametrize(
    "value",
    [
        "postgresql://u:s@127.0.0.1/db",
        "password=secret",
        "x\x00y",
    ],  # pragma: allowlist secret - fixture
)
def test_sensitive_or_control_text_cannot_enter_ledger(tmp_path, value):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        with pytest.raises(api.JournalError, match="journal_invalid_record"):
            journal.append({**intent(), "test": value})


def test_fsync_failure_poison_writer_before_success(tmp_path, monkeypatch):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:

        def fail(_fd):
            raise OSError("private database identifier and secret")

        monkeypatch.setattr(api.os, "fsync", fail)
        with pytest.raises(api.JournalError) as exc:
            journal.append(intent())
        assert str(exc.value) == "journal_write_failed"
        with pytest.raises(api.JournalError, match="journal_write_failed"):
            journal.append(intent())


def test_bounded_records_and_ledger(tmp_path, monkeypatch):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        with pytest.raises(api.JournalError, match="journal_invalid_record"):
            journal.append({**intent(), "test": "x" * 257})
        monkeypatch.setattr(api, "MAX_JOURNAL_BYTES", 1)
        with pytest.raises(api.JournalError, match="journal_full"):
            journal.append(intent())


def test_private_directory_and_files(tmp_path):
    api = journal_api()
    private = tmp_path / "private"
    with api.Journal(private, "3" * 32, metadata()):
        pass
    if os.name == "nt":
        result = subprocess.run(
            ["icacls", str(private)], capture_output=True, check=True, text=True
        )
        assert "(I)" not in result.stdout
        assert "Everyone" not in result.stdout and "BUILTIN\\Users" not in result.stdout
    else:
        assert private.stat().st_mode & 0o777 == 0o700
        for name in ("journal.jsonl", "journal.lock", "head.json"):
            assert (private / name).stat().st_mode & 0o777 == 0o600


def test_non_directory_or_missing_metadata_fails_closed(tmp_path):
    api = journal_api()
    path = tmp_path / "file"
    path.write_text("untouched")
    with pytest.raises(api.JournalError, match="journal_unsafe_path"):
        with api.Journal(path, "3" * 32, metadata()):
            pass
    with pytest.raises(api.JournalError, match="journal_invalid_record"):
        with api.Journal(tmp_path / "private", "3" * 32, {}):
            pass
    assert path.read_text() == "untouched"


def test_reused_run_and_cross_cluster_receipts_are_not_adopted(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    with pytest.raises(api.JournalError, match="journal_run_reused"):
        with api.Journal(tmp_path, "3" * 32, metadata()):
            pass
    with pytest.raises(api.JournalError, match="journal_identity_mismatch"):
        with api.Journal(tmp_path, "4" * 32, {**metadata(), "cluster_id": "987654321"}):
            pass


@pytest.mark.parametrize(
    "patch",
    [
        {"database_name": "cloudsecops_lab"},
        {"creation_id": "not-a-creation-id"},
        {"oid": -1},
        {"oid": True},
        {"oid": "123"},
        {"owner": "owner; DROP DATABASE protected"},
        {"retention": "delete_after_run"},
        {"outcome": ["private"]},
    ],
)
def test_invalid_identity_and_retention_values_are_rejected(tmp_path, patch):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        with pytest.raises(api.JournalError, match="journal_invalid_record"):
            journal.append({**intent(), **patch})


@pytest.mark.parametrize("event", ["ready", "provisioned", "quarantined", "created", "rejected"])
def test_terminal_or_postcreation_state_requires_its_own_predecessor(tmp_path, event):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        with pytest.raises(api.JournalError, match="journal_invalid_transition"):
            journal.append({**intent(), "event": event})


def test_private_state_cannot_relabel_an_existing_creation(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
        with pytest.raises(api.JournalError, match="journal_invalid_transition"):
            journal.append(
                {
                    **intent(),
                    "event": "created",
                    "database_name": "csl_test_" + "f" * 32,
                    "oid": 12,
                    "owner": "owner",
                }
            )


def test_provisioning_failure_reopens_operator_review_requirement(tmp_path):
    api = journal_api()
    with pytest.raises(RuntimeError):
        with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
            journal.append(intent())
            journal.append({**intent(), "event": "created", "oid": 12, "owner": "owner"})
            journal.append({**intent(), "event": "quarantined"})
            journal.append({**intent(), "event": "ready"})
            journal.append({**intent(), "event": "failed", "phase": "provision"})
            raise RuntimeError("controlled test failure")
    records = api.read_records(tmp_path)
    assert records[-1]["event"] == "run_aborted"
    assert api.pending_creations(records)[0]["event"] == "failed"


def test_failed_write_head_or_empty_ledger_cannot_be_silently_initialized(tmp_path):
    api = journal_api()
    (tmp_path / "journal.jsonl").write_bytes(b"")
    with pytest.raises(api.JournalError, match="journal_corrupt"):
        with api.Journal(tmp_path, "3" * 32, metadata()):
            pass
    assert (tmp_path / "journal.jsonl").read_bytes() == b""


def test_large_or_invalid_head_is_rejected_without_payload_leak(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    (tmp_path / "head.json").write_bytes(b"private" * 100)
    with pytest.raises(api.JournalError) as exc:
        api.read_records(tmp_path)
    assert str(exc.value) == "journal_corrupt"


@pytest.mark.parametrize("contents", [b"[]\n", b"not JSON\n", b"{}\n", b"\xff\n"])
def test_malformed_records_never_reveal_raw_data(tmp_path, contents):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    (tmp_path / "journal.jsonl").write_bytes(contents)
    with pytest.raises(api.JournalError, match="journal_corrupt"):
        api.read_records(tmp_path)


def test_private_acl_failure_prevents_any_intent(tmp_path, monkeypatch):
    api = journal_api()

    def fail(_path):
        raise api.LocalPostgresError("private_acl_failed")

    monkeypatch.setattr(api, "_restrict_directory", fail)
    with pytest.raises(api.JournalError, match="journal_unsafe_path"):
        with api.Journal(tmp_path, "3" * 32, metadata()):
            pass
    assert not (tmp_path / "journal.jsonl").exists()


def test_hardlinked_journal_is_not_opened_for_mutation(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    target = tmp_path / "journal.jsonl"
    other = tmp_path / "other-link"
    os.link(target, other)
    before = other.read_bytes()
    with pytest.raises(api.JournalError, match="journal_unsafe_path"):
        with api.Journal(tmp_path, "4" * 32, metadata()):
            pass
    assert other.read_bytes() == before


def test_existing_link_component_is_rejected_before_directory_creation(tmp_path, monkeypatch):
    api = journal_api()
    from pathlib import Path

    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == tmp_path or original(path))
    with pytest.raises(api.JournalError, match="journal_unsafe_path"):
        with api.Journal(tmp_path / "new", "3" * 32, metadata()):
            pass
    assert not (tmp_path / "new").exists()


def test_short_write_is_detected_and_cannot_report_success(tmp_path, monkeypatch):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        monkeypatch.setattr(api.os, "write", lambda *_args: 0)
        with pytest.raises(api.JournalError, match="journal_write_failed"):
            journal.append(intent())
        assert len(journal.records) == 1


def test_ready_is_not_a_completed_migration_or_restore_target(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
        journal.append({**intent(), "event": "created", "oid": 12, "owner": "owner"})
        journal.append({**intent(), "event": "quarantined"})
        journal.append({**intent(), "event": "ready"})
    assert api.pending_creations(api.read_records(tmp_path))[0]["event"] == "ready"
    with pytest.raises(api.JournalError, match="journal_operator_review_required"):
        with api.Journal(tmp_path, "4" * 32, metadata()):
            pass


@pytest.mark.parametrize("changed", [{"oid": 99}, {"owner": "different_owner"}])
def test_confirmed_oid_and_owner_cannot_change_in_a_later_receipt(tmp_path, changed):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
        journal.append({**intent(), "event": "created", "oid": 12, "owner": "owner"})
        with pytest.raises(api.JournalError, match="journal_invalid_transition"):
            journal.append({**intent(), "event": "quarantined", **changed})


def test_recovery_checks_semantics_even_with_self_consistent_hashes(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()) as journal:
        journal.append(intent())
    path = tmp_path / "journal.jsonl"
    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    records[1]["event"] = "ready"
    previous = "0" * 64
    for record in records:
        record["previous_sha256"] = previous
        payload = {key: value for key, value in record.items() if key != "sha256"}
        record["sha256"] = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        previous = record["sha256"]
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    (tmp_path / "head.json").write_text(json.dumps({"seq": len(records), "sha256": previous}))
    with pytest.raises(api.JournalError, match="journal_corrupt"):
        api.read_records(tmp_path)


def test_duplicate_json_keys_in_private_receipts_are_rejected(tmp_path):
    api = journal_api()
    with api.Journal(tmp_path, "3" * 32, metadata()):
        pass
    path = tmp_path / "journal.jsonl"
    path.write_bytes(
        path.read_bytes().replace(b'{"cluster_id":', b'{"cluster_id":"forged","cluster_id":', 1)
    )
    with pytest.raises(api.JournalError, match="journal_corrupt"):
        api.read_records(tmp_path)


def test_new_directory_entries_are_synced_before_first_journal_record(tmp_path, monkeypatch):
    api = journal_api()
    from pathlib import Path

    private = tmp_path / "new-private" / "cluster" / "ledger"
    events = []
    original_mkdir, original_append = Path.mkdir, api.Journal.append

    def mkdir(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        events.append(("mkdir", path))
        return result

    def append(journal, record):
        events.append(("record", record["event"]))
        return original_append(journal, record)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    monkeypatch.setattr(api, "_sync_directory", lambda path: events.append(("sync", path)))
    monkeypatch.setattr(api.Journal, "append", append)
    with api.Journal(private, "3" * 32, metadata()):
        pass
    first_record = events.index(("record", "run_started"))
    for directory in (tmp_path / "new-private", tmp_path / "new-private" / "cluster", private):
        created = events.index(("mkdir", directory))
        assert events[created + 1 : created + 3] == [
            ("sync", directory.parent),
            ("sync", directory),
        ]
        assert created + 3 <= first_record


def test_failed_parent_sync_blocks_before_creating_any_journal_record(tmp_path, monkeypatch):
    api = journal_api()
    private = tmp_path / "new-private" / "cluster" / "ledger"
    syncs = []

    def fail_parent(path):
        syncs.append(path)
        if (tmp_path / "new-private").exists() and path == tmp_path:
            raise OSError("controlled parent directory sync failure")

    monkeypatch.setattr(api, "_sync_directory", fail_parent)
    with pytest.raises(api.JournalError, match="journal_unsafe_path"):
        with api.Journal(private, "3" * 32, metadata()):
            pass
    assert tmp_path in syncs
    assert not private.exists()
    assert not list(tmp_path.rglob("journal.jsonl"))
    assert not list(tmp_path.rglob("journal.lock"))


def test_retry_resyncs_existing_ancestor_links_before_a_new_intent(tmp_path, monkeypatch):
    api = journal_api()
    private = tmp_path / "preexisting-private" / "cluster" / "ledger"
    private.mkdir(parents=True)
    syncs = []
    monkeypatch.setattr(api, "_sync_directory", lambda path: syncs.append(path))
    with api.Journal(private, "3" * 32, metadata()) as journal:
        assert tmp_path in syncs
        assert private.parent in syncs
        journal.append(intent())
    assert syncs.index(tmp_path) < syncs.index(private)
