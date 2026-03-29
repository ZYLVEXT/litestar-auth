"""OAuth token encryption at rest using Advanced Alchemy EncryptedString and a Fernet key.

When ``oauth_token_encryption_key`` is set on the auth plugin config, OAuth
access_token and refresh_token are stored encrypted in the database. The key
must be a URL-safe base64-encoded Fernet key (e.g. from ``Fernet.generate_key().decode()``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator  # noqa: TC003
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, override

from litestar_auth.config import is_pytest_runtime, is_testing
from litestar_auth.exceptions import ConfigurationError

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None  # ty: ignore[invalid-assignment]

from advanced_alchemy.types.encrypted_string import EncryptionBackend

type OAuthEncryptionScope = object

_current_oauth_encryption_scope: ContextVar[OAuthEncryptionScope | None] = ContextVar(
    "current_oauth_encryption_scope",
    default=None,
)


class OAuthTokenEncryptionRegistry:
    """Registry of OAuth token encryption keys keyed by app/plugin scope."""

    def __init__(self) -> None:
        """Initialize an empty scope-to-key mapping."""
        self._keys_by_scope: dict[OAuthEncryptionScope, str | None] = {}

    def register(self, scope: OAuthEncryptionScope, key: str | None) -> None:
        """Register or validate the encryption key for a specific scope.

        Raises:
            ConfigurationError: If the scope already has a different key outside testing runtime.
        """
        current = self._keys_by_scope.get(scope)
        if current is None:
            self._keys_by_scope[scope] = key
            return

        if current == key:
            return

        if is_testing() or is_pytest_runtime():
            self._keys_by_scope[scope] = key
            return

        msg = "Conflicting oauth_token_encryption_key values detected for the same app scope."
        raise ConfigurationError(msg)

    def clear(self, scope: OAuthEncryptionScope) -> None:
        """Remove the registered key for a scope."""
        self._keys_by_scope.pop(scope, None)

    def get(self, scope: OAuthEncryptionScope | None = None) -> str | bytes | None:
        """Return the configured key for a scope or the active scope."""
        resolved_scope = _current_oauth_encryption_scope.get() if scope is None else scope
        if resolved_scope is None:
            return None
        return self._keys_by_scope.get(resolved_scope)

    def require(self, scope: OAuthEncryptionScope | None = None, *, context: str = "OAuth token persistence") -> None:
        """Fail closed when OAuth token encryption is required but not configured.

        Raises:
            ConfigurationError: When not in testing mode and no encryption key is configured.
        """
        if is_testing():
            return
        if self.get(scope) is not None:
            return
        msg = (
            f"oauth_token_encryption_key is required when {context}. "
            'Generate one with `python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"`.'
        )
        raise ConfigurationError(msg)


_oauth_token_encryption_registry = OAuthTokenEncryptionRegistry()


def register_oauth_token_encryption_key(scope: OAuthEncryptionScope, key: str | None) -> None:
    """Configure the OAuth token encryption key for a specific scope.

    Security:
        Each app/plugin scope maintains its own Fernet key. In production,
        conflicting re-registration for the same scope fails closed.
    """
    _oauth_token_encryption_registry.register(scope, key)


def clear_oauth_token_encryption_key(scope: OAuthEncryptionScope) -> None:
    """Remove the registered key for a specific scope."""
    _oauth_token_encryption_registry.clear(scope)


@contextmanager
def oauth_token_encryption_scope(scope: OAuthEncryptionScope) -> Iterator[None]:
    """Activate the given scope while interacting with encrypted OAuth columns."""
    token = _current_oauth_encryption_scope.set(scope)
    try:
        yield
    finally:
        _current_oauth_encryption_scope.reset(token)


def get_oauth_encryption_key_callable() -> Callable[[], str | bytes | None]:
    """Return a callable for EncryptedString that resolves the active scope key."""
    return _get_oauth_token_encryption_key


def _get_oauth_token_encryption_key() -> str | bytes | None:
    """Return the active scope key for use by EncryptedString."""
    return _oauth_token_encryption_registry.get()


def require_oauth_token_encryption_key(
    scope: OAuthEncryptionScope | None = None,
    *,
    context: str = "OAuth token persistence",
) -> None:
    """Fail closed when OAuth token encryption is required but not configured.

    This is intentionally a runtime guard so that applications that do not use
    OAuth token persistence are not forced to configure an encryption key.
    """
    _oauth_token_encryption_registry.require(scope, context=context)


class _RawFernetBackend(EncryptionBackend):
    """Encryption backend that uses the configured key directly as a Fernet key (no hashing).

    When key is None, values are stored and returned as plain text (no encryption).
    """

    def __init__(self) -> None:
        self._fernet: Any = None

    def mount_vault(self, key: str | bytes | None) -> None:
        """Use the given key as the Fernet key, or None to disable encryption.

        Raises:
            ImportError: If cryptography is not installed and a non-None key is passed.
        """
        if key is None:
            self._fernet = None
            return
        if Fernet is None:
            msg = "Install litestar-auth[oauth] to use OAuth token encryption."
            raise ImportError(msg)
        key_bytes = key.encode() if isinstance(key, str) else key
        self._fernet = Fernet(key_bytes)

    @override
    def init_engine(self, key: bytes | str) -> None:
        """No-op; mount_vault does the work."""
        return

    def encrypt(self, value: object) -> str:
        """Encrypt the value, or return as-is if encryption is disabled.

        Security:
            When ``self._fernet`` is ``None`` (no ``oauth_token_encryption_key``
            configured), values are stored in plaintext. Production deployments
            SHOULD supply a Fernet key via ``oauth_token_encryption_key`` so that
            OAuth access and refresh tokens are protected at rest.

        Returns:
            Encrypted or plain string.

        Raises:
            TypeError: If the value cannot be represented as a token string.
        """
        if self._fernet is None:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode("utf-8")
            msg = "OAuth token values must be strings when encryption is disabled."
            raise TypeError(msg)
        if not isinstance(value, str):
            msg = "OAuth token values must be strings."
            raise TypeError(msg)
        return self._fernet.encrypt(value.encode()).decode("utf-8")

    def decrypt(self, value: object) -> str:
        """Decrypt the value, or return as-is if encryption is disabled.

        Returns:
            Decrypted or plain string.

        Raises:
            TypeError: If the value is not a string or bytes (including when encryption is enabled).
        """
        if self._fernet is None or value is None:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode("utf-8")
            msg = "OAuth token values must be strings when encryption is disabled."
            raise TypeError(msg)
        if isinstance(value, str):
            decrypted: str | bytes = self._fernet.decrypt(value.encode("utf-8"))
        elif isinstance(value, bytes):
            decrypted = self._fernet.decrypt(value)
        else:
            msg = "OAuth token values must be strings or bytes."
            raise TypeError(msg)
        return decrypted.decode("utf-8") if isinstance(decrypted, bytes) else decrypted
