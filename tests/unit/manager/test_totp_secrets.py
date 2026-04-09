"""Tests for ``TotpSecretsService``."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

import litestar_auth._manager.totp_secrets as totp_secrets_module
from litestar_auth._manager.totp_secrets import TotpSecretsService, TotpSecretStoragePosture
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit

PREFIX = "fernet:"


class _FakeInvalidTokenError(Exception):
    """Deterministic InvalidToken replacement for service tests."""


class _FakeFernet:
    """Minimal Fernet-compatible test double."""

    def __init__(self, key: bytes) -> None:
        """Store the key and reject intentionally invalid values.

        Raises:
            ValueError: If the provided key is intentionally marked invalid.
        """
        if key == b"invalid-key":
            msg = "invalid Fernet key"
            raise ValueError(msg)
        self._prefix = b"enc:" + key + b":"

    def encrypt(self, value: bytes) -> bytes:
        """Encode the key into the token for round-trip tests.

        Returns:
            A deterministic encrypted token.
        """
        return self._prefix + value

    def decrypt(self, value: bytes) -> bytes:
        """Return the plaintext for matching tokens.

        Raises:
            _FakeInvalidTokenError: If the value was not produced for this key.
        """
        if not value.startswith(self._prefix):
            raise _FakeInvalidTokenError
        return value.removeprefix(self._prefix)


@dataclass(slots=True)
class _Manager:
    """Minimal manager double for ``TotpSecretsService`` tests."""

    user_db: AsyncMock
    totp_secret_key: str | None = None


def _build_fake_fernet_module() -> SimpleNamespace:
    """Return a fake cryptography module with deterministic Fernet behavior."""
    return SimpleNamespace(Fernet=_FakeFernet, InvalidToken=_FakeInvalidTokenError)


def test_totp_secrets_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    reloaded_module = importlib.reload(totp_secrets_module)

    assert reloaded_module.TotpSecretsService.__name__ == TotpSecretsService.__name__


def test_totp_secret_storage_posture_reports_plaintext_compatibility_without_key() -> None:
    """Missing keys keep the plaintext compatibility contract explicit."""
    posture = TotpSecretStoragePosture.from_secret_key(None)

    assert posture == TotpSecretStoragePosture.compatibility_plaintext()
    assert posture.key == "compatibility_plaintext"
    assert posture.encrypts_at_rest is False
    assert posture.requires_explicit_production_opt_in is True
    assert posture.production_validation_error is not None


def test_totp_secret_storage_posture_reports_fernet_encrypted_with_key() -> None:
    """Configured keys switch the explicit storage contract to Fernet encryption."""
    posture = TotpSecretStoragePosture.from_secret_key("test-key")

    assert posture == TotpSecretStoragePosture.fernet_encrypted()
    assert posture.key == "fernet_encrypted"
    assert posture.encrypts_at_rest is True
    assert posture.requires_explicit_production_opt_in is False
    assert posture.production_validation_error is None


async def test_set_secret_delegates_to_user_store_with_encrypted_value() -> None:
    """set_secret() should encrypt, prefix, and pass the payload to the user store."""
    user_db = AsyncMock()
    manager = _Manager(user_db=user_db, totp_secret_key="test-key")
    service = TotpSecretsService(manager, prefix=PREFIX)
    user = ExampleUser(id=uuid4())
    updated_user = ExampleUser(id=user.id, totp_secret=f"{PREFIX}enc:test-key:plain-secret")
    user_db.update.return_value = updated_user

    result = await service.set_secret(
        user,
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    assert result is updated_user
    user_db.update.assert_awaited_once_with(
        user,
        {"totp_secret": f"{PREFIX}enc:test-key:plain-secret"},
    )


async def test_set_secret_stores_plaintext_when_encryption_disabled() -> None:
    """set_secret() should pass through plaintext when no key is configured."""
    user_db = AsyncMock()
    manager = _Manager(user_db=user_db)
    service = TotpSecretsService(manager, prefix=PREFIX)
    user = ExampleUser(id=uuid4())
    updated_user = ExampleUser(id=user.id, totp_secret="plain-secret")
    loader = Mock(side_effect=AssertionError("loader should not be used"))
    user_db.update.return_value = updated_user

    result = await service.set_secret(user, "plain-secret", load_cryptography_fernet=loader)

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"totp_secret": "plain-secret"})
    loader.assert_not_called()


@pytest.mark.parametrize("secret", [None, "plain-secret"])
async def test_read_secret_returns_unencrypted_values(secret: str | None) -> None:
    """read_secret() should return plaintext or ``None`` unchanged."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    assert await service.read_secret(secret, load_cryptography_fernet=loader) == secret
    loader.assert_not_called()


async def test_read_secret_decrypts_prefixed_value() -> None:
    """read_secret() should decrypt values that use the encrypted prefix."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)
    encrypted_secret = service.prepare_secret_for_storage(
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    assert encrypted_secret is not None
    assert (
        await service.read_secret(
            encrypted_secret,
            load_cryptography_fernet=_build_fake_fernet_module,
        )
        == "plain-secret"
    )


async def test_read_secret_requires_key_for_encrypted_values() -> None:
    """read_secret() should fail clearly when encrypted data is stored without a key."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)

    with pytest.raises(RuntimeError, match="totp_secret_key"):
        await service.read_secret(f"{PREFIX}encrypted-value", load_cryptography_fernet=_build_fake_fernet_module)


async def test_read_secret_raises_runtime_error_for_corrupted_data() -> None:
    """Invalid encrypted payloads should raise a stable RuntimeError with the original cause."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)

    with pytest.raises(RuntimeError, match="TOTP secret decryption failed") as exc_info:
        await service.read_secret(
            f"{PREFIX}enc:other-key:plain-secret",
            load_cryptography_fernet=_build_fake_fernet_module,
        )

    assert isinstance(exc_info.value.__cause__, _FakeInvalidTokenError)


def test_prepare_secret_for_storage_encrypts_and_prefixes_values() -> None:
    """prepare_secret_for_storage() should prefix deterministic Fernet output."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)

    assert (
        service.prepare_secret_for_storage(
            "plain-secret",
            load_cryptography_fernet=_build_fake_fernet_module,
        )
        == f"{PREFIX}enc:test-key:plain-secret"
    )


@pytest.mark.parametrize("secret", [None, "plain-secret"])
def test_prepare_secret_for_storage_returns_plain_value_when_encryption_disabled(secret: str | None) -> None:
    """prepare_secret_for_storage() should skip the loader when encryption is disabled."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    assert service.prepare_secret_for_storage(secret, load_cryptography_fernet=loader) == secret
    loader.assert_not_called()


def test_prepare_secret_for_storage_propagates_invalid_fernet_key_errors() -> None:
    """Invalid configured Fernet keys should surface the underlying constructor error."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="invalid-key"), prefix=PREFIX)

    with pytest.raises(ValueError, match="invalid Fernet key"):
        service.prepare_secret_for_storage("plain-secret", load_cryptography_fernet=_build_fake_fernet_module)
