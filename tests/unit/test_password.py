"""Tests for password hashing helpers."""

from __future__ import annotations

import pytest

import litestar_auth.password as password_module

pytestmark = pytest.mark.unit
EXPECTED_ARGON2_ONLY_HASHER_COUNT = 1


def test_default_initialization_uses_argon2_only() -> None:
    """Default initialization uses the library's Argon2-only policy."""
    helper = password_module.PasswordHelper()

    assert len(helper.password_hash.hashers) == EXPECTED_ARGON2_ONLY_HASHER_COUNT
    assert helper.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"


def test_default_initialization_uses_internal_default_password_hash_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default initialization routes through the module-level default hash builder."""
    sentinel_password_hash = object()
    build_calls = 0

    def build_default_password_hash() -> object:
        nonlocal build_calls
        build_calls += 1
        return sentinel_password_hash

    monkeypatch.setattr(password_module, "_build_default_password_hash", build_default_password_hash)

    helper = password_module.PasswordHelper()

    assert helper.password_hash is sentinel_password_hash
    assert build_calls == 1


def test_from_defaults_uses_internal_default_password_hash_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    """The named default factory routes through the shared module-level hash builder."""
    sentinel_password_hash = object()
    build_calls = 0

    def build_default_password_hash() -> object:
        nonlocal build_calls
        build_calls += 1
        return sentinel_password_hash

    monkeypatch.setattr(password_module, "_build_default_password_hash", build_default_password_hash)

    helper = password_module.PasswordHelper.from_defaults()

    assert helper.password_hash is sentinel_password_hash
    assert build_calls == 1


def test_hash_returns_argon2_hash_and_uses_unique_salt() -> None:
    """Hashes use Argon2 by default and produce unique salted outputs."""
    helper = password_module.PasswordHelper()

    first_hash = helper.hash("correct horse battery staple")
    second_hash = helper.hash("correct horse battery staple")

    assert first_hash != "correct horse battery staple"
    assert second_hash != "correct horse battery staple"
    assert first_hash != second_hash
    assert first_hash.startswith("$argon2")
    assert second_hash.startswith("$argon2")


def test_verify_returns_true_for_matching_password() -> None:
    """Verification succeeds when the plaintext matches the stored hash."""
    helper = password_module.PasswordHelper()
    hashed_password = helper.hash("s3cure-password")

    assert helper.verify("s3cure-password", hashed_password) is True


def test_verify_returns_false_for_wrong_password() -> None:
    """Verification fails when the plaintext does not match the stored hash."""
    helper = password_module.PasswordHelper()
    hashed_password = helper.hash("s3cure-password")

    assert helper.verify("wrong-password", hashed_password) is False


def test_verify_returns_false_for_unsupported_hash_format() -> None:
    """Verification fails closed for unsupported stored hash formats."""
    helper = password_module.PasswordHelper()
    assert helper.verify("s3cure-password", "not-a-password-hash") is False


def test_verify_and_update_returns_true_none_for_current_argon2_hash() -> None:
    """When the stored hash is already Argon2, no upgrade is needed."""
    helper = password_module.PasswordHelper()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("s3cure-password", hashed)
    assert verified is True
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_unsupported_hash() -> None:
    """Unsupported hash formats fail closed without an upgrade."""
    helper = password_module.PasswordHelper()
    verified, new_hash = helper.verify_and_update("legacy-password", "not-a-password-hash")

    assert verified is False
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_wrong_password() -> None:
    """Failed verification returns (False, None) and does not update."""
    helper = password_module.PasswordHelper()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("wrong-password", hashed)
    assert verified is False
    assert new_hash is None
