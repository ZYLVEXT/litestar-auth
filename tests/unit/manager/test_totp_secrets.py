"""Tests for ``TotpSecretsService``."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from litestar_auth._manager.totp_secrets import TotpSecretsService, TotpSecretStoragePosture
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit

PREFIX = "fernet:"
DEFAULT_KEY_ID = "default"


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


def test_totp_secret_storage_posture_requires_key_without_plaintext_branch() -> None:
    """Missing keys keep the encrypted-at-rest contract but require configuration."""
    posture = TotpSecretStoragePosture.from_secret_key(None)

    assert posture == TotpSecretStoragePosture.fernet_encrypted(key_configured=False)
    assert posture.key == "fernet_encrypted"
    assert posture.encrypts_at_rest is True
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


@pytest.mark.parametrize(
    ("totp_secret_key", "expected_key", "encrypts_at_rest"),
    [
        pytest.param(None, "fernet_encrypted", True, id="missing-key"),
        pytest.param("test-key", "fernet_encrypted", True, id="encrypted"),
    ],
)
def test_service_storage_posture_tracks_manager_key(
    *,
    totp_secret_key: str | None,
    expected_key: str,
    encrypts_at_rest: bool,
) -> None:
    """The service resolves the same posture contract the manager reports publicly."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key=totp_secret_key), prefix=PREFIX)
    posture = service.storage_posture

    assert posture.key == expected_key
    assert posture.encrypts_at_rest is encrypts_at_rest
    assert posture.requires_explicit_production_opt_in is (totp_secret_key is None)


def test_service_storage_posture_tracks_explicit_keyring_inputs() -> None:
    """Explicit keyring inputs satisfy the encrypted-at-rest posture contract."""
    service = TotpSecretsService(
        _Manager(user_db=AsyncMock()),
        prefix=PREFIX,
        active_key_id="current",
        keys={"current": "current-key"},
    )

    posture = service.storage_posture

    assert posture.key == "fernet_encrypted"
    assert posture.encrypts_at_rest is True
    assert posture.requires_explicit_production_opt_in is False


async def test_set_secret_delegates_to_user_store_with_encrypted_value() -> None:
    """set_secret() should encrypt, prefix, and pass the payload to the user store."""
    user_db = AsyncMock()
    manager = _Manager(user_db=user_db, totp_secret_key="test-key")
    service = TotpSecretsService(manager, prefix=PREFIX)
    user = ExampleUser(id=uuid4())
    updated_user = ExampleUser(id=user.id, totp_secret=f"{PREFIX}v1:{DEFAULT_KEY_ID}:enc:test-key:plain-secret")
    user_db.update.return_value = updated_user

    result = await service.set_secret(
        user,
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    assert result is updated_user
    user_db.update.assert_awaited_once_with(
        user,
        {"totp_secret": f"{PREFIX}v1:{DEFAULT_KEY_ID}:enc:test-key:plain-secret"},
    )


async def test_set_secret_requires_key_for_non_null_secret() -> None:
    """set_secret() fails closed instead of storing plaintext when no key is configured."""
    user_db = AsyncMock()
    manager = _Manager(user_db=user_db)
    service = TotpSecretsService(manager, prefix=PREFIX)
    user = ExampleUser(id=uuid4())
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    with pytest.raises(RuntimeError, match="totp_secret_key is required"):
        await service.set_secret(user, "plain-secret", load_cryptography_fernet=loader)

    user_db.update.assert_not_awaited()
    loader.assert_not_called()


async def test_read_secret_returns_none_without_loader() -> None:
    """read_secret() should return ``None`` unchanged."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    assert await service.read_secret(None, load_cryptography_fernet=loader) is None
    loader.assert_not_called()


async def test_read_secret_rejects_unprefixed_plaintext_values() -> None:
    """read_secret() fails closed for legacy plaintext persisted values."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await service.read_secret("plain-secret", load_cryptography_fernet=loader)
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
        await service.read_secret(
            f"{PREFIX}v1:{DEFAULT_KEY_ID}:encrypted-value",
            load_cryptography_fernet=_build_fake_fernet_module,
        )


async def test_read_secret_raises_runtime_error_for_corrupted_data() -> None:
    """Invalid encrypted payloads should raise a stable RuntimeError with the original cause."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)

    with pytest.raises(RuntimeError, match="TOTP secret decryption failed") as exc_info:
        await service.read_secret(
            f"{PREFIX}v1:{DEFAULT_KEY_ID}:enc:other-key:plain-secret",
            load_cryptography_fernet=_build_fake_fernet_module,
        )

    cause = exc_info.value.__cause__
    assert isinstance(cause, RuntimeError)
    assert isinstance(cause.__cause__, _FakeInvalidTokenError)


def test_prepare_secret_for_storage_encrypts_and_prefixes_values() -> None:
    """prepare_secret_for_storage() should prefix deterministic Fernet output."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)

    assert (
        service.prepare_secret_for_storage(
            "plain-secret",
            load_cryptography_fernet=_build_fake_fernet_module,
        )
        == f"{PREFIX}v1:{DEFAULT_KEY_ID}:enc:test-key:plain-secret"
    )


def test_prepare_secret_for_storage_returns_none_without_loader() -> None:
    """prepare_secret_for_storage() should preserve ``None`` without loading cryptography."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    assert service.prepare_secret_for_storage(None, load_cryptography_fernet=loader) is None
    loader.assert_not_called()


def test_prepare_secret_for_storage_requires_key_for_non_null_secret() -> None:
    """prepare_secret_for_storage() fails closed instead of returning plaintext."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    with pytest.raises(RuntimeError, match="totp_secret_key is required"):
        service.prepare_secret_for_storage("plain-secret", load_cryptography_fernet=loader)
    loader.assert_not_called()


def test_prepare_secret_for_storage_propagates_invalid_fernet_key_errors() -> None:
    """Invalid configured Fernet keys should surface a stable runtime error."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="invalid-key"), prefix=PREFIX)

    with pytest.raises(RuntimeError, match="key material is invalid") as exc_info:
        service.prepare_secret_for_storage("plain-secret", load_cryptography_fernet=_build_fake_fernet_module)

    assert "invalid-key" not in str(exc_info.value)


def test_read_secret_decrypts_present_non_active_key_and_detects_rotation() -> None:
    """Configured non-active key ids remain readable and are marked for rotation."""
    keys = {"current": "current-key", "old": "old-key"}
    old_service = TotpSecretsService(
        _Manager(user_db=AsyncMock()),
        prefix=PREFIX,
        active_key_id="old",
        keys=keys,
    )
    current_service = TotpSecretsService(
        _Manager(user_db=AsyncMock()),
        prefix=PREFIX,
        active_key_id="current",
        keys=keys,
    )
    old_stored = old_service.prepare_secret_for_storage(
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )
    current_stored = current_service.prepare_secret_for_storage(
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    assert old_stored is not None
    assert current_stored is not None
    assert old_stored.startswith(f"{PREFIX}v1:old:")
    assert current_stored.startswith(f"{PREFIX}v1:current:")
    assert current_service.requires_reencrypt(old_stored, load_cryptography_fernet=_build_fake_fernet_module) is True
    assert (
        current_service.requires_reencrypt(current_stored, load_cryptography_fernet=_build_fake_fernet_module) is False
    )


def test_reencrypt_secret_for_storage_rewrites_non_active_key_values() -> None:
    """Migration helpers should decrypt old-key values and rewrite with the active key id."""
    keys = {"current": "current-key", "old": "old-key"}
    old_service = TotpSecretsService(
        _Manager(user_db=AsyncMock()),
        prefix=PREFIX,
        active_key_id="old",
        keys=keys,
    )
    current_service = TotpSecretsService(
        _Manager(user_db=AsyncMock()),
        prefix=PREFIX,
        active_key_id="current",
        keys=keys,
    )
    old_stored = old_service.prepare_secret_for_storage(
        "plain-secret",
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    rewritten = current_service.reencrypt_secret_for_storage(
        old_stored,
        load_cryptography_fernet=_build_fake_fernet_module,
    )

    assert rewritten is not None
    assert rewritten.startswith(f"{PREFIX}v1:current:")
    assert current_service.requires_reencrypt(rewritten, load_cryptography_fernet=_build_fake_fernet_module) is False


def test_rotation_helpers_preserve_none_without_loading_crypto() -> None:
    """Disabled TOTP values should not require cryptography for rotation helpers."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock()), prefix=PREFIX)
    loader = Mock(side_effect=AssertionError("loader should not be used"))

    assert service.requires_reencrypt(None, load_cryptography_fernet=loader) is False
    assert service.reencrypt_secret_for_storage(None, load_cryptography_fernet=loader) is None
    loader.assert_not_called()


@pytest.mark.parametrize(
    ("stored", "match"),
    [
        pytest.param(f"{PREFIX}legacy-token", "must use", id="legacy-unversioned"),
        pytest.param(f"{PREFIX}v2:{DEFAULT_KEY_ID}:ciphertext", "unsupported", id="unsupported-version"),
        pytest.param(f"{PREFIX}v1:old:ciphertext", "unknown key id", id="unknown-key"),
    ],
)
def test_versioned_totp_storage_errors_are_stable_and_secret_free(stored: str, match: str) -> None:
    """Malformed and unknown-key values fail closed without echoing stored data."""
    service = TotpSecretsService(_Manager(user_db=AsyncMock(), totp_secret_key="test-key"), prefix=PREFIX)

    with pytest.raises(RuntimeError, match=match) as exc_info:
        service.requires_reencrypt(stored, load_cryptography_fernet=_build_fake_fernet_module)

    assert stored not in str(exc_info.value)
