"""Internal TOTP-secret service for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, Self

from litestar_auth._manager._protocols import UserDatabaseManagerProtocol

_TOTP_STORAGE_VALIDATION_ERROR = (
    "totp_secret_key is required in production when TOTP is enabled. "
    "TOTP secrets must be encrypted at rest. Generate a Fernet key with: "
    'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
)

type TotpSecretStoragePostureKey = Literal["compatibility_plaintext", "fernet_encrypted"]


@dataclass(slots=True, frozen=True)
class TotpSecretStoragePosture:
    """Explicit contract describing how persisted TOTP secrets are stored."""

    key: TotpSecretStoragePostureKey
    encrypts_at_rest: bool
    requires_explicit_production_opt_in: bool

    @classmethod
    def compatibility_plaintext(cls) -> Self:
        """Return the compatibility-grade plaintext storage posture."""
        return cls(
            key="compatibility_plaintext",
            encrypts_at_rest=False,
            requires_explicit_production_opt_in=True,
        )

    @classmethod
    def fernet_encrypted(cls) -> Self:
        """Return the Fernet-encrypted storage posture."""
        return cls(
            key="fernet_encrypted",
            encrypts_at_rest=True,
            requires_explicit_production_opt_in=False,
        )

    @classmethod
    def from_secret_key(cls, totp_secret_key: str | None) -> Self:
        """Build the storage posture for the configured TOTP secret key.

        Returns:
            The explicit TOTP secret storage posture for ``totp_secret_key``.
        """
        return _resolve_totp_secret_storage_posture(cls, totp_secret_key)

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
    if totp_secret_key is None:
        return posture_cls.compatibility_plaintext()
    return posture_cls.fernet_encrypted()


def _load_fernet_for_totp_secret(
    *,
    load_cryptography_fernet: Any,
    totp_secret_key: str,
) -> tuple[Any, Any]:
    """Return the cryptography module and Fernet instance for ``totp_secret_key``."""
    fernet_module = load_cryptography_fernet()
    return fernet_module, fernet_module.Fernet(totp_secret_key.encode())


class TotpSecretsService[UP]:
    """Handle stored TOTP secret encryption and decryption."""

    def __init__(self, manager: _TotpSecretsManagerProtocol[UP], *, prefix: str) -> None:
        """Bind the facade manager and encrypted-secret prefix."""
        self._manager = manager
        self._prefix = prefix

    @property
    def storage_posture(self) -> TotpSecretStoragePosture:
        """Return the explicit storage posture for the manager's current key."""
        return _resolve_totp_secret_storage_posture(TotpSecretStoragePosture, self._manager.totp_secret_key)

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
        if secret is None or not secret.startswith(self._prefix):
            return secret

        totp_secret_key = self._manager.totp_secret_key
        if totp_secret_key is None:
            msg = "Encrypted TOTP secrets require totp_secret_key."
            raise RuntimeError(msg)

        fernet_module, fernet = _load_fernet_for_totp_secret(
            load_cryptography_fernet=load_cryptography_fernet,
            totp_secret_key=totp_secret_key,
        )
        encrypted_value = secret.removeprefix(self._prefix).encode()
        try:
            return fernet.decrypt(encrypted_value).decode()
        except fernet_module.InvalidToken as exc:
            msg = "TOTP secret decryption failed; key may be wrong or data corrupted."
            raise RuntimeError(msg) from exc

    def prepare_secret_for_storage(
        self,
        secret: str | None,
        *,
        load_cryptography_fernet: Any,
    ) -> str | None:
        """Return the database representation for a TOTP secret."""
        if secret is None:
            return secret

        totp_secret_key = self._manager.totp_secret_key
        if not self.storage_posture.encrypts_at_rest:
            return secret
        if totp_secret_key is None:  # pragma: no cover - posture branch above already guards this
            return secret

        _, fernet = _load_fernet_for_totp_secret(
            load_cryptography_fernet=load_cryptography_fernet,
            totp_secret_key=totp_secret_key,
        )
        encrypted_secret = fernet.encrypt(secret.encode()).decode()
        return f"{self._prefix}{encrypted_secret}"
