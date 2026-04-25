"""Internal TOTP-secret service for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self

from litestar_auth._manager._protocols import UserDatabaseManagerProtocol
from litestar_auth._secrets_at_rest import FernetKey, FernetKeyring, SecretAtRestError

if TYPE_CHECKING:
    from collections.abc import Mapping

_TOTP_STORAGE_VALIDATION_ERROR = (
    "totp_secret_keyring or totp_secret_key is required in production when TOTP is enabled. "
    "TOTP secrets must be encrypted at rest. Generate a Fernet key with: "
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)
_DEFAULT_TOTP_FERNET_KEY_ID = "default"

type TotpSecretStoragePostureKey = Literal["fernet_encrypted"]


@dataclass(slots=True, frozen=True)
class TotpSecretStoragePosture:
    """Explicit contract describing how persisted TOTP secrets are stored."""

    key: TotpSecretStoragePostureKey
    encrypts_at_rest: bool
    requires_explicit_production_opt_in: bool

    @classmethod
    def fernet_encrypted(cls, *, key_configured: bool = True) -> Self:
        """Return the Fernet-encrypted storage posture."""
        return cls(
            key="fernet_encrypted",
            encrypts_at_rest=True,
            requires_explicit_production_opt_in=not key_configured,
        )

    @classmethod
    def from_secret_key(cls, totp_secret_key: str | None) -> Self:
        """Build the storage posture for the configured TOTP secret key.

        Returns:
            The explicit TOTP secret storage posture for ``totp_secret_key``.
        """
        return _resolve_totp_secret_storage_posture(cls, totp_secret_key)

    @classmethod
    def from_keyring_inputs(cls, *, totp_secret_key: str | None, keyring_configured: bool) -> Self:
        """Build the storage posture for the configured TOTP key or keyring inputs.

        Returns:
            The explicit TOTP secret storage posture for configured TOTP encryption inputs.
        """
        return cls.fernet_encrypted(key_configured=bool(totp_secret_key) or keyring_configured)

    @property
    def production_validation_error(self) -> str | None:
        """Return the plugin validation error for this posture, if any."""
        if not self.requires_explicit_production_opt_in:
            return None
        return _TOTP_STORAGE_VALIDATION_ERROR


class _TotpSecretsManagerProtocol[UP](UserDatabaseManagerProtocol[UP], Protocol):
    """Manager surface required by the TOTP-secret service."""

    totp_secret_key: str | None


def _resolve_totp_secret_storage_posture[T: TotpSecretStoragePosture](
    posture_cls: type[T],
    totp_secret_key: str | None,
) -> T:
    """Resolve the explicit TOTP secret storage posture for ``totp_secret_key``."""
    return posture_cls.fernet_encrypted(key_configured=bool(totp_secret_key))


class TotpSecretsService[UP]:
    """Handle stored TOTP secret encryption and decryption."""

    def __init__(
        self,
        manager: _TotpSecretsManagerProtocol[UP],
        *,
        prefix: str,
        active_key_id: str = _DEFAULT_TOTP_FERNET_KEY_ID,
        keys: Mapping[str, FernetKey] | None = None,
    ) -> None:
        """Bind the facade manager and encrypted-secret prefix."""
        self._manager = manager
        self._prefix = prefix
        self._active_key_id = active_key_id
        self._keys = None if keys is None else MappingProxyType(dict(keys))

    @property
    def storage_posture(self) -> TotpSecretStoragePosture:
        """Return the explicit storage posture for the manager's current key."""
        return TotpSecretStoragePosture.fernet_encrypted(key_configured=self._has_configured_keyring())

    async def set_secret(
        self,
        user: UP,
        secret: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> UP:
        """Persist a TOTP secret using the manager's configured storage format."""
        return await self._manager.user_db.update(
            user,
            {"totp_secret": self.prepare_secret_for_storage(secret, load_cryptography_fernet=load_cryptography_fernet)},
        )

    async def read_secret(
        self,
        secret: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> str | None:
        """Return a plain-text TOTP secret from storage."""
        if secret is None:
            return None
        return self._read_secret_from_storage(secret, load_cryptography_fernet=load_cryptography_fernet)

    def prepare_secret_for_storage(
        self,
        secret: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> str | None:
        """Return the database representation for a TOTP secret."""
        if secret is None:
            return secret

        return self._build_keyring(load_cryptography_fernet=load_cryptography_fernet).encrypt(secret)

    def requires_reencrypt(
        self,
        stored: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> bool:
        """Return whether a stored TOTP secret should be rewritten with the active key."""
        if stored is None:
            return False
        self._require_encrypted_storage_value(stored)
        try:
            return self._build_keyring(load_cryptography_fernet=load_cryptography_fernet).needs_rotation(stored)
        except SecretAtRestError as exc:
            raise _totp_secret_runtime_error(exc) from exc

    def reencrypt_secret_for_storage(
        self,
        stored: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> str | None:
        """Rewrite a stored TOTP secret with the active Fernet key id."""
        if stored is None:
            return None
        plaintext = self._read_secret_from_storage(stored, load_cryptography_fernet=load_cryptography_fernet)
        return self.prepare_secret_for_storage(plaintext, load_cryptography_fernet=load_cryptography_fernet)

    def _read_secret_from_storage(
        self,
        secret: str,
        *,
        load_cryptography_fernet: Any,
    ) -> str:
        """Return a plain-text TOTP secret from a non-null storage value."""
        self._require_encrypted_storage_value(secret)
        try:
            return self._build_keyring(load_cryptography_fernet=load_cryptography_fernet).decrypt(secret)
        except SecretAtRestError as exc:
            raise _totp_secret_runtime_error(exc) from exc

    def _build_keyring(self, *, load_cryptography_fernet: Any) -> FernetKeyring:
        """Return the Fernet keyring configured for persisted TOTP secrets."""
        if self._keys is not None:
            return FernetKeyring(
                active_key_id=self._active_key_id,
                keys=self._keys,
                _load_cryptography_fernet=load_cryptography_fernet,
            )

        totp_secret_key = self._manager.totp_secret_key
        if not totp_secret_key:
            msg = "totp_secret_key is required to store or read TOTP secrets encrypted at rest."
            raise RuntimeError(msg)
        return FernetKeyring(
            active_key_id=_DEFAULT_TOTP_FERNET_KEY_ID,
            keys={_DEFAULT_TOTP_FERNET_KEY_ID: totp_secret_key},
            _load_cryptography_fernet=load_cryptography_fernet,
        )

    def _has_configured_keyring(self) -> bool:
        """Return whether this service has enough key input for encrypted non-null values."""
        if self._keys is not None:
            return bool(self._keys)
        return bool(self._manager.totp_secret_key)

    def _require_encrypted_storage_value(self, secret: str) -> None:
        """Fail closed for plaintext TOTP secret values."""
        if not secret.startswith(self._prefix):
            msg = "Persisted TOTP secrets must be encrypted at rest."
            raise RuntimeError(msg)


def _totp_secret_runtime_error(exc: SecretAtRestError) -> RuntimeError:
    """Return a stable TOTP runtime error without adding secret material."""
    if "decryption failed" in str(exc):
        msg = "TOTP secret decryption failed; key may be wrong or data corrupted."
        return RuntimeError(msg)
    return RuntimeError(str(exc))
