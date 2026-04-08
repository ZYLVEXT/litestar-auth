"""Session-bound plugin helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar_auth.db.base import BaseOAuthAccountStore, BaseUserStore
from litestar_auth.oauth_encryption import oauth_token_encryption_scope
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.manager import BaseUserManager


class _UserManagerFactory[UP: UserProtocol[Any], ID](Protocol):  # noqa: PYI046
    """Factory that builds a session-bound user manager."""

    def __call__(self, session: AsyncSession) -> BaseUserManager[UP, ID]: ...  # pragma: no cover


class _AccountStateValidator[UP](Protocol):  # noqa: PYI046
    """Callable validator contract for ``require_account_state`` on the manager class."""

    def __call__(self, user: UP, *, require_verified: bool = False) -> None: ...  # pragma: no cover


class _ScopedUserDatabaseProxy[UP: UserProtocol[Any], ID](BaseUserStore[UP, ID]):
    """Wrap OAuth-account persistence calls in the plugin's OAuth encryption scope.

    The wrapped store must implement :class:`~litestar_auth.db.base.BaseUserStore`.
    OAuth methods (:meth:`get_by_oauth_account`, :meth:`upsert_oauth_account`)
    additionally require the wrapped store to satisfy
    :class:`~litestar_auth.db.base.BaseOAuthAccountStore`; calling them on a store
    that does not implement those methods raises ``AttributeError`` at runtime.
    """

    def __init__(self, user_db: BaseUserStore[UP, ID], *, oauth_scope: object) -> None:
        """Wrap ``user_db`` and route OAuth calls through the encryption scope."""
        self._user_db = user_db
        self._oauth_scope = oauth_scope

    async def get(self, user_id: ID) -> UP | None:
        """Return the user with the given identifier, if present."""
        return await self._user_db.get(user_id)

    async def get_by_email(self, email: str) -> UP | None:
        """Return the user matching the provided email, if present."""
        return await self._user_db.get_by_email(email)

    async def get_by_field(self, field_name: str, value: str) -> UP | None:
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

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Load a linked OAuth account within the plugin's encryption scope.

        Returns:
            The linked user when the provider account exists, otherwise ``None``.
        """
        oauth_store = cast("BaseOAuthAccountStore[UP, ID]", self._user_db)
        with oauth_token_encryption_scope(self._oauth_scope):
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
        """Persist a linked OAuth account within the plugin's encryption scope."""
        oauth_store = cast("BaseOAuthAccountStore[UP, ID]", self._user_db)
        with oauth_token_encryption_scope(self._oauth_scope):
            await oauth_store.upsert_oauth_account(
                user,
                oauth_name=oauth_name,
                account_id=account_id,
                account_email=account_email,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
            )
