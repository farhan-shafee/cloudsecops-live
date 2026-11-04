"""Private identifiers use a fixed masking channel before PostgreSQL can log them.

All writes and descriptor observations are intercepted. No workflow commands,
database connections, Docker calls, or network operations are emitted.
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from scripts import test_provision as provision
from scripts.test_capacity import CapacityError

NAME = "csl_test_" + "a" * 32


@pytest.fixture
def channel(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("RUNNER_OS", "Linux")
    monkeypatch.setenv("CSL_TEST_MASK_FD", "997")
    state = SimpleNamespace(
        fd=997,
        writes=[],
        descriptors=[],
        mode=stat.S_IFIFO | 0o600,
        stat_error=None,
        write_error=None,
        write_result=None,
    )
    real_fstat, real_write = os.fstat, os.write

    def fstat(descriptor):
        if descriptor != state.fd:
            return real_fstat(descriptor)
        state.descriptors.append(descriptor)
        if state.stat_error is not None:
            raise state.stat_error
        return SimpleNamespace(st_mode=state.mode)

    def write(descriptor, data):
        if descriptor != state.fd:
            return real_write(descriptor, data)
        state.writes.append((descriptor, data))
        if state.write_error is not None:
            raise state.write_error
        return len(data) if state.write_result is None else state.write_result

    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "write", write)
    return state


def mask(channel, name=NAME, *, descriptor=997):
    # Restore interception before pytest resumes capture on its own descriptors.
    channel.fd = descriptor
    try:
        provision.mask_identifier(name)
    finally:
        channel.fd = 997


def test_mask_identifier_writes_one_fixed_command_to_private_fifo(channel):
    mask(channel)
    assert channel.descriptors == [997]
    assert channel.writes == [(997, ("::add-mask::" + NAME + "\n").encode("ascii"))]
    assert len(channel.writes[0][1]) < 512


@pytest.mark.parametrize("descriptor", [3, 1024])
def test_documented_descriptor_boundaries_are_accepted(channel, monkeypatch, descriptor):
    monkeypatch.setenv("CSL_TEST_MASK_FD", str(descriptor))
    mask(channel, descriptor=descriptor)
    assert channel.descriptors == [descriptor]
    assert channel.writes == [(descriptor, ("::add-mask::" + NAME + "\n").encode("ascii"))]


@pytest.mark.parametrize(
    "name",
    [
        None,
        42,
        "cloudsecops_lab",
        "csl_test_" + "a" * 31,
        "csl_test_" + "a" * 33,
        "csl_test_" + "A" * 32,
        NAME + "\n::warning::untrusted command",
        NAME + "\r",
        " " + NAME,
    ],
)
def test_unapproved_names_never_reach_descriptor_or_workflow_command(channel, name):
    with pytest.raises(CapacityError, match="^PRIVATE_MASK_CHANNEL_UNAVAILABLE$"):
        mask(channel, name)
    assert channel.descriptors == [] and channel.writes == []


@pytest.mark.parametrize(
    "value",
    [None, "", "0", "1", "2", "1025", "9" * 12, "-3", "+3", "3.0", " 3", "3\n", "٣"],
)
def test_missing_or_malformed_channel_is_rejected_before_io(channel, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("CSL_TEST_MASK_FD", raising=False)
    else:
        monkeypatch.setenv("CSL_TEST_MASK_FD", value)
    try:
        descriptor = int(value) if value is not None else 997
    except ValueError:
        descriptor = 997
    with pytest.raises(CapacityError, match="^PRIVATE_MASK_CHANNEL_UNAVAILABLE$"):
        mask(channel, descriptor=descriptor)
    assert channel.descriptors == [] and channel.writes == []


@pytest.mark.parametrize(
    "key,value",
    [("GITHUB_ACTIONS", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_OS", "Windows")],
)
def test_masking_cannot_authorize_a_local_or_self_hosted_run(channel, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(CapacityError):
        mask(channel)
    assert channel.descriptors == [] and channel.writes == []


@pytest.mark.parametrize("mode", [stat.S_IFREG, stat.S_IFDIR, stat.S_IFSOCK, stat.S_IFCHR])
def test_non_fifo_descriptors_cannot_receive_mask_commands(channel, mode):
    channel.mode = mode | 0o600
    with pytest.raises(CapacityError, match="^PRIVATE_MASK_CHANNEL_UNAVAILABLE$"):
        mask(channel)
    assert channel.writes == []


@pytest.mark.parametrize("operation", ["stat_error", "write_error"])
def test_descriptor_errors_are_fixed_and_redacted(channel, operation):
    setattr(channel, operation, OSError("private mask descriptor detail " + NAME))
    with pytest.raises(CapacityError, match="^PRIVATE_MASK_CHANNEL_UNAVAILABLE$") as caught:
        mask(channel)
    assert caught.value.__cause__ is None
    assert NAME not in str(caught.value)


@pytest.mark.parametrize("count", [0, 1, len("::add-mask::" + NAME + "\n") - 1])
def test_short_write_blocks_creation_instead_of_retrying_fragments(channel, count):
    channel.write_result = count
    with pytest.raises(CapacityError, match="^PRIVATE_MASK_CHANNEL_UNAVAILABLE$"):
        mask(channel)
    assert len(channel.writes) == 1


def test_provisioner_masks_after_durable_intent_and_before_create(tmp_path):
    from scripts.test_journal import read_records
    from tests.test_test_provision import harness

    owner, conn = harness(tmp_path)
    masked = []

    def register(name):
        records = read_records(tmp_path)
        assert records[-1]["event"] == "intent"
        assert records[-1]["database_name"] == name
        assert conn.created == 0
        masked.append(name)

    owner.mask = register
    with owner:
        db = owner.create(migrate=False)
    assert masked == [db._values["dbname"]]
    assert conn.created == 1


def test_mask_failure_leaves_failed_intent_and_blocks_every_creation(tmp_path):
    from scripts.test_journal import pending_creations, read_records
    from tests.test_test_provision import harness

    owner, conn = harness(tmp_path)

    def fail(_name):
        raise CapacityError("PRIVATE_MASK_CHANNEL_UNAVAILABLE")

    owner.mask = fail
    with owner:
        with pytest.raises(CapacityError, match="^CREATION_OPERATOR_REVIEW_REQUIRED$"):
            owner.create(migrate=False)
        assert owner.blocked is True and conn.created == 0
        with pytest.raises(CapacityError, match="^CREATION_OPERATOR_REVIEW_REQUIRED$"):
            owner.create(migrate=False)
        assert conn.created == 0
    pending = pending_creations(read_records(tmp_path))
    assert len(pending) == 1 and pending[0]["event"] == "failed"
    assert "oid" not in pending[0]
