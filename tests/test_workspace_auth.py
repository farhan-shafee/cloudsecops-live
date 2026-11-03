"""Independent password/token controls; expectations do not come from the authenticator."""

import pytest
from argon2 import PasswordHasher, Type

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.workspace_auth import hash_password, new_session_token, verify_password


def test_argon_password_hash_is_salted_and_verifies_without_disclosure() -> None:
    password = "A laboratory passphrase 2026!"  # pragma: allowlist secret - fixed public fixture
    first = hash_password(password)
    second = hash_password(password)
    assert first != second and password not in first
    assert first.startswith("$argon2id$v=19$m=65536,t=3,p=1$")
    assert verify_password(first, password)
    assert not verify_password(first, "Another laboratory passphrase!")


@pytest.mark.parametrize(
    "password", ["", "short", " " * 16, "x" * 129, "a" * 12 + "\x00", "a" * 12 + "\ud800"]
)
def test_provisioning_rejects_invalid_passwords_with_fixed_error(password) -> None:
    with pytest.raises(EvidenceError, match="WS_PASSWORD_POLICY"):
        hash_password(password)


def test_invalid_or_unreviewed_hash_parameters_cannot_force_expensive_verification() -> None:
    assert not verify_password("not-an-argon-hash", "A laboratory passphrase!")
    assert not verify_password(
        "$argon2id$v=19$m=999999999,t=99,p=1$bad$bad", "A laboratory passphrase!"
    )
    assert not verify_password(hash_password("A laboratory passphrase!"), "bad\x00password")


def test_real_hash_capacity_exhaustion_is_bounded_and_releases_no_unowned_slot() -> None:
    from cloudsecops_live.workspace_auth import _HASH_CAPACITY

    password = "A laboratory passphrase!"  # pragma: allowlist secret - fixed public fixture
    reviewed = hash_password(password)
    held = 0
    try:
        for _ in range(2):
            available = _HASH_CAPACITY.acquire(blocking=False)
            assert available
            held += 1
        with pytest.raises(EvidenceError, match="WS_LIMIT"):
            hash_password(password)
        assert not verify_password(reviewed, password)
        # Failed contenders must not release either slot held by another operation.
        assert not _HASH_CAPACITY.acquire(blocking=False)
    finally:
        for _ in range(held):
            _HASH_CAPACITY.release()
    assert verify_password(reviewed, password)


@pytest.mark.parametrize(
    ("before", "after"),
    [("m=65536", "m=999999999"), ("t=3", "t=99"), ("p=1", "p=8"), ("v=19", "v=16")],
)
def test_valid_reviewed_hash_cannot_request_unreviewed_verification_resources(
    before, after
) -> None:
    password = "A laboratory passphrase!"  # pragma: allowlist secret - fixed public fixture
    reviewed = hash_password(password)
    assert verify_password(reviewed, password)
    changed = reviewed.replace(before, after, 1)
    assert not verify_password(changed, password)


def test_valid_argon2d_hash_is_rejected_by_argon2id_policy() -> None:
    password = "A laboratory passphrase!"  # pragma: allowlist secret - fixed public fixture
    other = PasswordHasher(
        time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16, type=Type.D
    )
    encoded = other.hash(password)
    assert other.verify(encoded, password)
    assert not verify_password(encoded, password)


def test_new_sessions_are_opaque_unique_and_never_use_a_supplied_cookie() -> None:
    user_id = "a" * 32
    first, second = new_session_token(user_id), new_session_token(user_id)
    assert first.startswith(user_id + ".") and len(first) == 76
    assert first != second
    with pytest.raises(EvidenceError, match="WS_CONFIG"):
        new_session_token("analyst:forged-role")
