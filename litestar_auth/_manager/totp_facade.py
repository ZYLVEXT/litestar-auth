"""TOTP facade methods for the public user manager."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._optional_deps import require_cryptography_fernet
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._manager.totp_secrets import TotpSecretsService

_TOTP_SECRET_FERNET_INSTALL_HINT = "Install litestar-auth[totp] to use TOTP secret encryption."  # noqa: S105
_load_cryptography_fernet = cast(
    "Any",
    partial(require_cryptography_fernet, install_hint=_TOTP_SECRET_FERNET_INSTALL_HINT),
)


class TotpManagerFacade[UP: UserProtocol[Any]]:
    """Mixin exposing TOTP secret helpers on ``BaseUserManager``."""

    user_db: Any
    _totp_secrets: TotpSecretsService[UP]

    async def set_totp_secret(self, user: UP, secret: str | None) -> UP:
        """Store or clear the TOTP secret directly, bypassing None-filtering.

        Args:
            user: The user whose TOTP secret should be updated.
            secret: New secret string, or ``None`` to disable 2FA.

        Returns:
            The updated user instance.
        """
        return await self._totp_secrets.set_secret(
            user,
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage.

        Returns:
            Plain-text secret, or ``None`` when 2FA is disabled.
        """
        return await self._totp_secrets.read_secret(secret, load_cryptography_fernet=_load_cryptography_fernet)

    def totp_secret_requires_reencrypt(self, secret: str | None) -> bool:
        """Return whether a stored TOTP secret should be rewritten with the active key."""
        return self._totp_secrets.requires_reencrypt(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    def reencrypt_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return a stored TOTP secret rewritten with the active key."""
        return self._totp_secrets.reencrypt_secret_for_storage(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    async def set_recovery_code_hashes(self, user: UP, code_index: dict[str, str]) -> UP:
        """Replace the active TOTP recovery-code lookup index for a user.

        Returns:
            The updated user instance.
        """
        return cast("UP", await self.user_db.set_recovery_code_hashes(user, code_index))

    async def find_recovery_code_hash_by_lookup(self, user: UP, lookup_hex: str) -> str | None:
        """Return the active recovery-code hash matching ``lookup_hex``."""
        return cast("str | None", await self.user_db.find_recovery_code_hash_by_lookup(user, lookup_hex))

    async def consume_recovery_code_by_lookup(self, user: UP, lookup_hex: str) -> bool:
        """Atomically consume an active TOTP recovery-code lookup entry.

        Returns:
            ``True`` when the lookup entry was consumed, otherwise ``False``.
        """
        return cast("bool", await self.user_db.consume_recovery_code_by_lookup(user, lookup_hex))

    def _prepare_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return the database representation for a TOTP secret."""
        return self._totp_secrets.prepare_secret_for_storage(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )
