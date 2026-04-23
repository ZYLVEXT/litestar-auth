"""Tests for password hashing helpers."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

import litestar_auth.password as password_module

if TYPE_CHECKING:
    from litestar_auth.password import PasswordHelper

pytestmark = pytest.mark.unit
DEFAULT_HASHER_COUNT = 1


def _password_helper_cls() -> type[PasswordHelper]:
    """Import the password helper lazily so coverage includes module definitions.

    Returns:
        The runtime ``PasswordHelper`` class from ``litestar_auth.password``.
    """
    module = importlib.import_module("litestar_auth.password")
    return module.PasswordHelper


def _legacy_password_helper() -> PasswordHelper:
    """Return an explicit helper that keeps bcrypt verification during migrations."""
    return _password_helper_cls()(password_hash=PasswordHash((Argon2Hasher(), BcryptHasher())))


def test_password_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records class-body execution."""
    reloaded_module = importlib.reload(password_module)

    assert reloaded_module.PasswordHelper is not None
    assert reloaded_module.PasswordHelper.__name__ == _password_helper_cls().__name__


def test_default_initialization_uses_argon2_only() -> None:
    """Default initialization uses the library's Argon2-only policy."""
    helper = _password_helper_cls()()

    assert len(helper.password_hash.hashers) == DEFAULT_HASHER_COUNT
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


def test_verify_returns_false_for_wrong_or_unknown_hashes() -> None:
    """Verification fails for invalid credentials and unknown hashes."""
    helper = _password_helper_cls()()
    hashed_password = helper.hash("s3cure-password")

    assert helper.verify("wrong-password", hashed_password) is False
    assert helper.verify("s3cure-password", "not-a-password-hash") is False


def test_verify_returns_false_for_bcrypt_hash_with_default_helper() -> None:
    """The library default helper no longer accepts bcrypt hashes."""
    helper = _password_helper_cls()()
    bcrypt_hash = BcryptHasher().hash("legacy-password")

    assert helper.verify("legacy-password", bcrypt_hash) is False


def test_explicit_legacy_helper_verifies_bcrypt_hashes() -> None:
    """Applications can still keep bcrypt support with an explicit helper."""
    helper = _legacy_password_helper()
    bcrypt_hash = BcryptHasher().hash("legacy-password")

    assert helper.verify("legacy-password", bcrypt_hash) is True


def test_explicit_legacy_helper_returns_false_for_overlong_password_against_bcrypt_hash() -> None:
    """Overlong legacy bcrypt inputs still fail closed for explicit migration helpers."""
    helper = _legacy_password_helper()
    bcrypt_hash = BcryptHasher().hash("a" * 72)

    assert helper.verify("a" * 80, bcrypt_hash) is False


def test_verify_and_update_returns_true_none_for_current_argon2_hash() -> None:
    """When the stored hash is already Argon2, no upgrade is needed."""
    helper = _password_helper_cls()()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("s3cure-password", hashed)
    assert verified is True
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_bcrypt_hash_with_default_helper() -> None:
    """The library default helper refuses bcrypt hashes instead of upgrading them."""
    helper = _password_helper_cls()()
    bcrypt_hash = BcryptHasher().hash("legacy-password")

    verified, new_hash = helper.verify_and_update("legacy-password", bcrypt_hash)

    assert verified is False
    assert new_hash is None


def test_explicit_legacy_helper_returns_new_hash_for_deprecated_bcrypt() -> None:
    """Explicit migration helpers can verify bcrypt hashes and upgrade them to Argon2."""
    helper = _legacy_password_helper()
    bcrypt_hash = BcryptHasher().hash("legacy-password")
    verified, new_hash = helper.verify_and_update("legacy-password", bcrypt_hash)
    assert verified is True
    assert new_hash is not None
    assert new_hash.startswith("$argon2")
    assert new_hash != bcrypt_hash


def test_explicit_legacy_helper_returns_false_none_for_overlong_password_against_bcrypt_hash() -> None:
    """Explicit legacy bcrypt verification should not leak errors for overlong passwords."""
    helper = _legacy_password_helper()
    bcrypt_hash = BcryptHasher().hash("a" * 72)

    verified, new_hash = helper.verify_and_update("a" * 80, bcrypt_hash)

    assert verified is False
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_wrong_password() -> None:
    """Failed verification returns (False, None) and does not update."""
    helper = _password_helper_cls()()
    hashed = helper.hash("s3cure-password")
    verified, new_hash = helper.verify_and_update("wrong-password", hashed)
    assert verified is False
    assert new_hash is None


def test_verify_and_update_returns_false_none_for_unknown_hash() -> None:
    """Unknown hash format yields (False, None)."""
    helper = _password_helper_cls()()
    verified, new_hash = helper.verify_and_update("any-password", "not-a-valid-hash")
    assert verified is False
    assert new_hash is None
