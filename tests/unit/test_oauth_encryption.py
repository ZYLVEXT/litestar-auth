"""Unit tests for `litestar_auth.oauth_encryption`."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

import pytest

from litestar_auth import oauth_encryption
from litestar_auth.oauth_encryption import Fernet as _FernetImport
from litestar_auth.oauth_encryption import (
    _RawFernetBackend,
    oauth_token_encryption_scope,
    register_oauth_token_encryption_key,
    require_oauth_token_encryption_key,
)

if TYPE_CHECKING:
    from collections.abc import Generator

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_oauth_token_encryption_key() -> Generator[None, None, None]:
    oauth_encryption._oauth_token_encryption_registry._keys_by_scope.clear()
    try:
        yield
    finally:
        oauth_encryption._oauth_token_encryption_registry._keys_by_scope.clear()


def test_oauth_encryption_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(oauth_encryption)

    assert reloaded_module._RawFernetBackend is not None
    assert reloaded_module.require_oauth_token_encryption_key.__name__ == require_oauth_token_encryption_key.__name__


def test_mount_vault_none_sets_fernet_none() -> None:
    """`mount_vault(None)` disables encryption without error."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)
    assert backend._fernet is None


def test_mount_vault_fernet_missing_raises_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing `cryptography` raises `ImportError` with the install hint."""
    backend = _RawFernetBackend()
    monkeypatch.setattr(oauth_encryption, "Fernet", None)
    with pytest.raises(ImportError, match=r"litestar-auth\[oauth\]"):
        backend.mount_vault("anykey")


def test_mount_vault_str_key_constructs_fernet() -> None:
    """`mount_vault(str)` builds a Fernet instance."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key().decode())
    assert backend._fernet is not None


def test_mount_vault_bytes_key_constructs_fernet() -> None:
    """`mount_vault(bytes)` builds a Fernet instance."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())
    assert backend._fernet is not None


def test_init_engine_is_noop() -> None:
    """`init_engine()` is intentionally a no-op."""
    backend = _RawFernetBackend()
    assert backend.init_engine(b"ignored") is None


def test_encrypt_non_str_with_encryption_disabled_raises_type_error() -> None:
    """Non-str values are rejected when encryption is disabled."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)
    with pytest.raises(TypeError, match=r"must be strings when encryption is disabled"):
        backend.encrypt(42)


def test_encrypt_none_with_encryption_disabled_returns_empty_string() -> None:
    """Disabled encryption normalizes None to an empty string."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)
    result = backend.encrypt(None)

    assert isinstance(result, str)
    assert not result


def test_encrypt_bytes_with_encryption_disabled_decodes_utf8() -> None:
    """Disabled encryption accepts bytes and decodes them as UTF-8."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend.encrypt(b"plain-token") == "plain-token"


def test_encrypt_string_with_encryption_disabled_returns_original_value() -> None:
    """Disabled encryption preserves plaintext string tokens."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend.encrypt("plain-token") == "plain-token"


def test_encrypt_non_str_with_encryption_enabled_raises_type_error() -> None:
    """Non-str values are rejected prior to encryption."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())
    with pytest.raises(TypeError, match=r"must be strings"):
        backend.encrypt(42)


def test_round_trip_with_encryption_enabled() -> None:
    """Encrypted values can be decrypted back to the original string."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())
    token = backend.encrypt("secret")
    assert backend.decrypt(token) == "secret"


def test_decrypt_non_str_with_encryption_enabled_raises_type_error() -> None:
    """Non-str/non-bytes values are rejected when encryption is enabled."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())

    with pytest.raises(TypeError, match=r"must be strings or bytes"):
        backend.decrypt(42)


def test_decrypt_non_str_with_encryption_enabled_raises_before_fernet_decrypt() -> None:
    """Invalid decrypt input must not reach Fernet when encryption is enabled."""
    decrypt_calls: list[bytes] = []

    class _FakeFernet:
        def decrypt(self, token: bytes) -> bytes:
            decrypt_calls.append(token)
            return b"x"

    backend = _RawFernetBackend()
    backend._fernet = _FakeFernet()

    with pytest.raises(TypeError, match=r"must be strings or bytes"):
        backend.decrypt(123)

    assert decrypt_calls == []


def test_decrypt_none_with_encryption_disabled_returns_empty_string() -> None:
    """Disabled encryption normalizes missing persisted values to an empty string."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)
    result = backend.decrypt(None)

    assert isinstance(result, str)
    assert not result


def test_decrypt_bytes_with_encryption_disabled_decodes_utf8() -> None:
    """Disabled encryption accepts bytes from storage and decodes them as UTF-8."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend.decrypt(b"plain-token") == "plain-token"


def test_decrypt_string_with_encryption_disabled_returns_original_value() -> None:
    """Disabled encryption preserves plaintext string values from storage."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend.decrypt("plain-token") == "plain-token"


def test_decrypt_non_string_with_encryption_disabled_raises_type_error() -> None:
    """Disabled encryption still rejects unsupported token value types."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    with pytest.raises(TypeError, match=r"must be strings when encryption is disabled"):
        backend.decrypt(42)


def test_decrypt_decodes_bytes_result_to_str() -> None:
    """If `Fernet.decrypt()` returns bytes, `decrypt()` decodes to str."""

    class _FakeFernet:
        def decrypt(self, token: bytes) -> bytes:
            return b"hello"

    backend = _RawFernetBackend()
    backend._fernet = _FakeFernet()
    assert backend.decrypt("ignored") == "hello"


def test_decrypt_accepts_bytes_with_encryption_enabled() -> None:
    """Encrypted bytes tokens are passed through to Fernet unchanged."""
    encrypted_tokens: list[bytes] = []

    class _FakeFernet:
        def decrypt(self, token: bytes) -> bytes:
            encrypted_tokens.append(token)
            return b"hello"

    backend = _RawFernetBackend()
    backend._fernet = _FakeFernet()

    assert backend.decrypt(b"ciphertext") == "hello"
    assert encrypted_tokens == [b"ciphertext"]


def test_get_oauth_encryption_key_callable_reads_active_scope_key() -> None:
    """The callable returned for `EncryptedString` resolves the current scope key."""
    scope = object()
    register_oauth_token_encryption_key(scope, "scope-key")
    resolve_key = oauth_encryption.get_oauth_encryption_key_callable()

    with oauth_token_encryption_scope(scope):
        assert resolve_key() == "scope-key"


def test_get_oauth_encryption_key_without_scope_returns_none() -> None:
    """No active scope means no encryption key can be resolved."""
    assert oauth_encryption.get_oauth_encryption_key_callable()() is None


def test_require_oauth_token_encryption_key_raises_outside_testing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing oauth_token_encryption_key fails closed when not in testing mode."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    scope = object()
    register_oauth_token_encryption_key(scope, None)
    with oauth_token_encryption_scope(scope), pytest.raises(oauth_encryption.ConfigurationError) as exc_info:
        require_oauth_token_encryption_key()

    assert "oauth_token_encryption_key is required" in str(exc_info.value)
    assert "Fernet.generate_key().decode()" in str(exc_info.value)


def test_require_oauth_token_encryption_key_allows_missing_in_testing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Testing mode bypasses the fail-closed requirement."""
    monkeypatch.setenv("LITESTAR_AUTH_TESTING", "1")
    scope = object()
    register_oauth_token_encryption_key(scope, None)
    with oauth_token_encryption_scope(scope):
        require_oauth_token_encryption_key()


def test_require_oauth_token_encryption_key_with_explicit_scope_succeeds() -> None:
    """An explicit scope with a configured key satisfies the runtime guard."""
    scope = object()
    register_oauth_token_encryption_key(scope, "scope-key")

    require_oauth_token_encryption_key(scope, context="rotating OAuth credentials")


def test_register_oauth_token_encryption_key_first_set_wins_for_scope() -> None:
    """The first non-None assignment is accepted for a scope."""
    scope = object()
    register_oauth_token_encryption_key(scope, "first-key")
    with oauth_token_encryption_scope(scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "first-key"


def test_register_oauth_token_encryption_key_same_key_is_idempotent() -> None:
    """Re-applying the same key to a scope is a safe no-op."""
    scope = object()
    register_oauth_token_encryption_key(scope, "same-key")
    register_oauth_token_encryption_key(scope, "same-key")
    with oauth_token_encryption_scope(scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "same-key"


def test_register_oauth_token_encryption_key_conflict_raises_outside_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Conflicting key replacement fails closed for the same scope outside testing runtime."""
    monkeypatch.setattr(oauth_encryption, "is_testing", lambda: False)
    monkeypatch.setattr(oauth_encryption, "is_pytest_runtime", lambda: False)
    scope = object()
    register_oauth_token_encryption_key(scope, "first-key")

    with pytest.raises(oauth_encryption.ConfigurationError, match="Conflicting oauth_token_encryption_key"):
        register_oauth_token_encryption_key(scope, "second-key")


def test_register_oauth_token_encryption_key_conflict_allowed_in_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Conflicting keys are allowed under test runtime for the same scope."""
    monkeypatch.setattr(oauth_encryption, "is_testing", lambda: True)
    scope = object()
    register_oauth_token_encryption_key(scope, "first-key")
    register_oauth_token_encryption_key(scope, "second-key")
    with oauth_token_encryption_scope(scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "second-key"


def test_register_oauth_token_encryption_key_conflict_allowed_in_pytest_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pytest runtime also permits in-process key rotation for the same scope."""
    monkeypatch.setattr(oauth_encryption, "is_testing", lambda: False)
    monkeypatch.setattr(oauth_encryption, "is_pytest_runtime", lambda: True)
    scope = object()
    register_oauth_token_encryption_key(scope, "first-key")
    register_oauth_token_encryption_key(scope, "second-key")

    with oauth_token_encryption_scope(scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "second-key"


def test_oauth_token_encryption_scopes_do_not_conflict() -> None:
    """Multiple scopes can hold different keys in the same process."""
    first_scope = object()
    second_scope = object()
    register_oauth_token_encryption_key(first_scope, "first-key")
    register_oauth_token_encryption_key(second_scope, "second-key")

    with oauth_token_encryption_scope(first_scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "first-key"

    with oauth_token_encryption_scope(second_scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "second-key"


def test_clear_oauth_token_encryption_key_removes_registered_scope() -> None:
    """Clearing a scope removes its registered key from the registry."""
    scope = object()
    register_oauth_token_encryption_key(scope, "scope-key")

    oauth_encryption.clear_oauth_token_encryption_key(scope)

    assert oauth_encryption._oauth_token_encryption_registry.get(scope) is None


def test_oauth_token_encryption_scope_restores_previous_scope_on_exit() -> None:
    """Nested scopes restore the prior active scope when the inner scope exits."""
    outer_scope = object()
    inner_scope = object()
    register_oauth_token_encryption_key(outer_scope, "outer-key")
    register_oauth_token_encryption_key(inner_scope, "inner-key")

    with oauth_token_encryption_scope(outer_scope):
        assert oauth_encryption._get_oauth_token_encryption_key() == "outer-key"

        with oauth_token_encryption_scope(inner_scope):
            assert oauth_encryption._get_oauth_token_encryption_key() == "inner-key"

        assert oauth_encryption._get_oauth_token_encryption_key() == "outer-key"

    assert oauth_encryption._get_oauth_token_encryption_key() is None
