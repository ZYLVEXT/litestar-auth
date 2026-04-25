"""Session-bound plugin helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar_auth.db.base import BaseOAuthAccountStore, BaseUserStore
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.manager import BaseUserManager
    from litestar_auth.oauth_encryption import OAuthTokenEncryption


class _UserManagerFactory[UP: UserProtocol[Any], ID](Protocol):  # noqa: PYI046
    """Factory that builds a session-bound user manager."""

    def __call__(self, session: AsyncSession) -> BaseUserManager[UP, ID]: ...  # pragma: no cover


class _AccountStateValidator[UP](Protocol):  # noqa: PYI046
    """Callable validator contract for ``require_account_state`` on the manager class."""

    def __call__(self, user: UP, *, require_verified: bool = False) -> None: ...  # pragma: no cover


class _OAuthTokenEncryptionBindable(Protocol):
    """Store contract that accepts an explicit OAuth token encryption policy."""

    def bind_oauth_token_encryption(
        self,
        oauth_token_encryption: OAuthTokenEncryption,
    ) -> object: ...  # pragma: no cover


class _TotpRecoveryCodeStore[UP](Protocol):
    """Store contract for hashed TOTP recovery-code persistence."""

    async def set_recovery_code_hashes(self, user: UP, hashes: tuple[str, ...]) -> UP: ...  # pragma: no cover

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]: ...  # pragma: no cover

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool: ...  # pragma: no cover


class _ScopedUserDatabaseProxy[UP: UserProtocol[Any], ID](BaseUserStore[UP, ID]):
    """Wrap a store and bind any explicit plugin-owned OAuth token policy once.

    The wrapped store must implement :class:`~litestar_auth.db.base.BaseUserStore`.
    OAuth methods (:meth:`get_by_oauth_account`, :meth:`upsert_oauth_account`)
    additionally require the wrapped store to satisfy
    :class:`~litestar_auth.db.base.BaseOAuthAccountStore`; calling them on a store
    that does not implement those methods raises ``AttributeError`` at runtime.
    """

    def __init__(
        self,
        user_db: BaseUserStore[UP, ID],
        *,
        oauth_token_encryption: OAuthTokenEncryption | None,
    ) -> None:
        """Wrap ``user_db`` and bind any explicit OAuth token policy."""
        if oauth_token_encryption is not None:
            bind = getattr(user_db, "bind_oauth_token_encryption", None)
            if callable(bind):
                user_db = cast(
                    "BaseUserStore[UP, ID]",
                    cast("_OAuthTokenEncryptionBindable", user_db).bind_oauth_token_encryption(
                        oauth_token_encryption,
                    ),
                )
        self._user_db = user_db

    async def get(self, user_id: ID) -> UP | None:
        """Return the user with the given identifier, if present."""
        return await self._user_db.get(user_id)

    async def get_by_email(self, email: str) -> UP | None:
        """Return the user matching the provided email, if present."""
        return await self._user_db.get_by_email(email)

    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> UP | None:
        """Return the user where ``field_name`` equals ``value``, if present."""
        return await self._user_db.get_by_field(field_name, value)

    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Persist and return a newly created user.

        Returns:
            The persisted user instance.
        """
        return await self._user_db.create(user_dict)

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""
        return await self._user_db.list_users(offset=offset, limit=limit)

    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Persist and return updates for an existing user.

        Returns:
            The updated user instance.
        """
        return await self._user_db.update(user, update_dict)

    async def delete(self, user_id: ID) -> None:
        """Delete the user identified by ``user_id`` from storage."""
        await self._user_db.delete(user_id)

    async def set_recovery_code_hashes(self, user: UP, hashes: tuple[str, ...]) -> UP:
        """Replace active TOTP recovery-code hashes through the wrapped store.

        Returns:
            The updated user instance.
        """
        recovery_store = cast("_TotpRecoveryCodeStore[UP]", self._user_db)
        return await recovery_store.set_recovery_code_hashes(user, hashes)

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]:
        """Return active TOTP recovery-code hashes through the wrapped store."""
        recovery_store = cast("_TotpRecoveryCodeStore[UP]", self._user_db)
        return await recovery_store.read_recovery_code_hashes(user)

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool:
        """Consume an active TOTP recovery-code hash through the wrapped store.

        Returns:
            ``True`` when the hash was active and consumed.
        """
        recovery_store = cast("_TotpRecoveryCodeStore[UP]", self._user_db)
        return await recovery_store.consume_recovery_code_hash(user, matched_hash)

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Load a linked OAuth account through the wrapped store.

        Returns:
            The linked user when the provider account exists, otherwise ``None``.
        """
        oauth_store = cast("BaseOAuthAccountStore[UP, ID]", self._user_db)
        return await oauth_store.get_by_oauth_account(oauth_name, account_id)

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: UP,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Persist a linked OAuth account through the wrapped store."""
        oauth_store = cast("BaseOAuthAccountStore[UP, ID]", self._user_db)
        await oauth_store.upsert_oauth_account(
            user,
            oauth_name=oauth_name,
            account_id=account_id,
            account_email=account_email,
            access_token=access_token,
            expires_at=expires_at,
            refresh_token=refresh_token,
        )
