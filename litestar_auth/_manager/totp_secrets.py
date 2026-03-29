"""Internal TOTP-secret service for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501

from __future__ import annotations

from typing import Any, Protocol

from litestar_auth._manager._protocols import UserDatabaseManagerProtocol


class _TotpSecretsManagerProtocol[UP](UserDatabaseManagerProtocol[UP], Protocol):
    """Manager surface required by the TOTP-secret service."""

    totp_secret_key: str | None


class TotpSecretsService[UP]:
    """Handle stored TOTP secret encryption and decryption."""

    def __init__(self, manager: _TotpSecretsManagerProtocol[UP], *, prefix: str) -> None:
        """Bind the facade manager and encrypted-secret prefix."""
        self._manager = manager
        self._prefix = prefix

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

        if self._manager.totp_secret_key is None:
            msg = "Encrypted TOTP secrets require totp_secret_key."
            raise RuntimeError(msg)

        fernet_module = load_cryptography_fernet()
        fernet = fernet_module.Fernet(self._manager.totp_secret_key.encode())
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
        if secret is None or self._manager.totp_secret_key is None:
            return secret

        fernet_module = load_cryptography_fernet()
        fernet = fernet_module.Fernet(self._manager.totp_secret_key.encode())
        encrypted_secret = fernet.encrypt(secret.encode()).decode()
        return f"{self._prefix}{encrypted_secret}"
