"""TOTP facade methods for the public user manager."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._optional_deps import require_cryptography_fernet
from litestar_auth.authentication.strategy.base import TotpStepUpStrategy
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Iterable

    from litestar_auth._manager.totp_secrets import TotpSecretsService
    from litestar_auth._secrets_at_rest import FernetModuleLoader

_TOTP_SECRET_FERNET_INSTALL_HINT = "Install litestar-auth[totp] to use TOTP secret encryption."  # noqa: S105
_load_cryptography_fernet: FernetModuleLoader = cast(
    "FernetModuleLoader",
    partial(require_cryptography_fernet, install_hint=_TOTP_SECRET_FERNET_INSTALL_HINT),
)


@dataclass(frozen=True, slots=True)
class TotpStepUpDispatcher:
    """Dispatch TOTP step-up markers to configured backend strategies."""

    strategies: tuple[TotpStepUpStrategy[Any], ...]

    @classmethod
    def from_backends(cls, backends: Iterable[object]) -> TotpStepUpDispatcher:
        """Return a dispatcher containing configured step-up strategies."""
        strategies: list[TotpStepUpStrategy[Any]] = []
        for backend in backends:
            strategy = getattr(backend, "strategy", None)
            if isinstance(strategy, TotpStepUpStrategy):
                strategies.append(strategy)
        return cls(tuple(strategies))

    async def issue(self, user: UserProtocol[Any], session_id: str, *, ttl_seconds: int) -> None:
        """Store a recent TOTP verification marker for all capable strategies."""
        for strategy in self.strategies:
            await strategy.issue_totp_stepup(user, session_id, ttl_seconds=ttl_seconds)

    async def has_recent_verification(self, user: UserProtocol[Any], session_id: str) -> bool:
        """Return whether any capable strategy has a live step-up marker."""
        for strategy in self.strategies:
            if await strategy.has_recent_totp_verification(user, session_id):
                return True
        return False


class TotpManagerFacade[UP: UserProtocol[Any]]:
    """Mixin exposing TOTP secret helpers on ``BaseUserManager``."""

    user_db: Any
    _totp_secrets: TotpSecretsService[UP]
    _totp_stepup: TotpStepUpDispatcher
    backends: tuple[object, ...]
    unsafe_testing: bool

    async def set_totp_secret(self, user: UP, secret: str | None) -> UP:
        """Store or clear the TOTP secret directly, bypassing None-filtering.

        Args:
            user: The user whose TOTP secret should be updated.
            secret: New secret string, or ``None`` to disable 2FA.

        Returns:
            The updated user instance.
        """
        return await self._totp_secrets.set_secret(user, secret)

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage.

        Returns:
            Plain-text secret, or ``None`` when 2FA is disabled.
        """
        return await self._totp_secrets.read_secret(secret)

    def totp_secret_requires_reencrypt(self, secret: str | None) -> bool:
        """Return whether a stored TOTP secret should be rewritten with the active key."""
        return self._totp_secrets.requires_reencrypt(secret)

    def reencrypt_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return a stored TOTP secret rewritten with the active key."""
        return self._totp_secrets.reencrypt_secret_for_storage(secret)

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

    async def issue_totp_stepup_verification(self, user: UP, session_id: str, *, ttl_seconds: int) -> None:
        """Store a recent TOTP verification marker for the current authenticated session."""
        await self._totp_stepup.issue(user, session_id, ttl_seconds=ttl_seconds)

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether the user's current session has a live TOTP step-up marker."""
        return await self._totp_stepup.has_recent_verification(user, session_id)

    def _prepare_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return the database representation for a TOTP secret."""
        return self._totp_secrets.prepare_secret_for_storage(secret)
