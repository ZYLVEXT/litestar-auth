"""Tests for password hashing helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest

import litestar_auth.password as password_module

if TYPE_CHECKING:
    from litestar_auth.password import PasswordHelper

pytestmark = pytest.mark.unit
EXPECTED_ARGON2_ONLY_HASHER_COUNT = 1


def _password_helper_cls() -> type[PasswordHelper]:
    """Return the runtime ``PasswordHelper`` class from the imported module.

    Returns:
        The runtime ``PasswordHelper`` class from ``litestar_auth.password``.
    """
    return password_module.PasswordHelper


def test_password_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records class-body execution."""
    reloaded_module = importlib.reload(password_module)

    assert reloaded_module.PasswordHelper is not None
    assert reloaded_module.PasswordHelper.__name__ == _password_helper_cls().__name__


def test_default_initialization_uses_argon2_only() -> None:
    """Default initialization uses the library's Argon2-only policy."""
    helper = _password_helper_cls()()

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

    helper = _password_helper_cls()()

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

    helper = _password_helper_cls().from_defaults()

    assert helper.password_hash is sentinel_password_hash
    assert build_calls == 1


def test_hash_returns_argon2_hash_and_uses_unique_salt() -> None:
    """Hashes use Argon2 by default and produce unique salted outputs."""
    helper = _password_helper_cls()()

    first_hash = helper.hash("correct horse battery staple")
    second_hash = helper.hash("correct horse battery staple")

    assert first_hash != "correct horse battery staple"
    assert second_hash != "correct horse battery staple"
    assert first_hash != second_hash
    assert first_hash.startswith("$argon2")
    assert second_hash.startswith("$argon2")


def test_verify_returns_true_for_matching_password() -> None:
    """Verification succeeds when the plaintext matches the stored hash."""
    helper = _password_helper_cls()()
    hashed_password = helper.hash("s3cure-password")

    assert helper.verify("s3cure-password", hashed_password) is True


def test_verify_returns_false_for_wrong_password() -> None:
    """Verification fails when the plaintext does not match the stored hash."""
    helper = _password_helper_cls()()
    hashed_password = helper.hash("s3cure-password")

    assert helper.verify("wrong-password", hashed_password) is False


def test_verify_returns_false_for_unsupported_hash_format() -> None:
    """Verification fails closed for unsupported stored hash formats."""
    helper = _password_helper_cls()()
    assert helper.verify("s3cure-password", "not-a-password-hash") is False


def test_verify_and_update_returns_true_none_for_current_argon2_hash() -> None:
    """When the stored hash is already Argon2, no upgrade is needed."""
    helper = _password_helper_cls()()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("s3cure-password", hashed)
    assert verified is True
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_unsupported_hash() -> None:
    """Unsupported hash formats fail closed without an upgrade."""
    helper = _password_helper_cls()()
    verified, new_hash = helper.verify_and_update("legacy-password", "not-a-password-hash")

    assert verified is False
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_wrong_password() -> None:
    """Failed verification returns (False, None) and does not update."""
    helper = _password_helper_cls()()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("wrong-password", hashed)
    assert verified is False
    assert new_hash is None
