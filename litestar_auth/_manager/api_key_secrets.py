"""API-key secret generation and signing-secret rotation helpers."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

import msgspec

from litestar_auth._secrets_at_rest import FernetKeyring, SecretAtRestError
from litestar_auth.exceptions import ApiKeyError

_DEFAULT_KEY_ID_BYTES = 16
_DEFAULT_SECRET_BYTES = 32


@dataclass(frozen=True, slots=True)
class ApiKeySecret:
    """One-time API-key credential whose repr/str never reveal the secret."""

    _value: str

    def get_secret_value(self) -> str:
        """Return the raw API key for the one response that is allowed to expose it."""
        return self._value

    def __repr__(self) -> str:
        """Return a redacted representation."""
        return "ApiKeySecret('**********')"

    def __str__(self) -> str:
        """Return a redacted string representation."""
        return "**********"


class ApiKeyCreateResult[AK](msgspec.Struct, frozen=True):
    """API-key creation result carrying the one-time raw credential."""

    api_key: AK
    secret: ApiKeySecret


def generate_key_id() -> str:
    """Return a parser-compatible public API-key identifier."""
    key_id = secrets.token_urlsafe(_DEFAULT_KEY_ID_BYTES)
    if key_id[0].isalnum():
        return key_id
    return f"k{key_id[1:]}"


def generate_secret() -> str:
    """Return the raw API-key secret component."""
    return secrets.token_urlsafe(_DEFAULT_SECRET_BYTES)


def encrypt_secret_for_signing(secret: str, keyring: FernetKeyring | None) -> bytes:
    """Encrypt a raw signing secret with the active keyring.

    Returns:
        The UTF-8 encoded encrypted secret.

    Raises:
        ApiKeyError: If no encryption keyring is configured.
    """
    if keyring is None:
        msg = "API-key signing requires api_keys.secret_encryption_keyring."
        raise ApiKeyError(msg)
    return keyring.encrypt(secret).encode("utf-8")


def require_secret_encryption_keyring(keyring: FernetKeyring | None) -> FernetKeyring:
    """Return the configured keyring or raise the manager rotation error.

    Raises:
        ApiKeyError: If no encryption keyring is configured.
    """
    if keyring is None:
        msg = "API-key signing-secret rotation requires api_keys.secret_encryption_keyring."
        raise ApiKeyError(msg)
    return keyring


def require_rotation_encrypted_secret(api_key: object) -> bytes:
    """Return encrypted signing material or raise the manager rotation error.

    Raises:
        ApiKeyError: If the row is not an encrypted signing API key.
    """
    signing_required = getattr(api_key, "signing_required", None)
    encrypted_secret = getattr(api_key, "encrypted_secret", None)
    if signing_required is not True or encrypted_secret is None:
        msg = "API-key signing-secret rotation requires an encrypted signing API key."
        raise ApiKeyError(msg)
    return encrypted_secret


def signing_secret_needs_rotation(keyring: FernetKeyring, encrypted_secret: bytes) -> bool:
    """Return whether an encrypted signing secret needs key rotation.

    Raises:
        ApiKeyError: If the encrypted secret cannot be decoded or inspected.
    """
    try:
        return keyring.needs_rotation(encrypted_secret.decode("utf-8"))
    except (SecretAtRestError, UnicodeDecodeError) as exc:
        msg = "API-key signing secret cannot be processed for rotation."
        raise ApiKeyError(msg) from exc


def as_aware_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def decrypt_rotation_secret(keyring: FernetKeyring, encrypted_secret: bytes) -> str:
    """Decrypt a signing secret for re-encryption under the active key.

    Returns:
        The plaintext signing secret.

    Raises:
        ApiKeyError: If the encrypted secret cannot be decoded or decrypted.
    """
    try:
        return keyring.decrypt(encrypted_secret.decode("utf-8"))
    except (SecretAtRestError, UnicodeDecodeError) as exc:
        msg = "API-key signing secret cannot be processed for rotation."
        raise ApiKeyError(msg) from exc
