"""SQLAlchemy-backed user database implementation."""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any, Protocol, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.filters import LimitOffset
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy import select

from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import OAuthAccountAlreadyLinkedError
from litestar_auth.oauth_encryption import require_oauth_token_encryption_key
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.sql import Select

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]


class SQLAlchemyUserModelProtocol(ModelProtocol, UserProtocol[UUID], Protocol):
    """Protocol for SQLAlchemy user models handled by this adapter."""


type UserModelT[UP: SQLAlchemyUserModelProtocol] = type[UP]


@cache
def _build_user_repository(
    user_model: type[SQLAlchemyUserModelProtocol],
) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository type bound to the provided SQLAlchemy user model.

    Cached by ``user_model`` identity so repeated adapter construction does not
    allocate new dynamic repository classes.

    Returns:
        Repository class configured for ``user_model``.
    """
    return type(
        f"{user_model.__name__}Repository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": user_model},
    )


@cache
def _build_oauth_repository(oauth_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository type bound to the provided OAuth account model.

    Returns:
        A cached Advanced Alchemy async repository subclass for ``oauth_model``.
    """
    return type(
        f"{oauth_model.__name__}OAuthRepository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": oauth_model},
    )


class SQLAlchemyUserDatabase[UP: SQLAlchemyUserModelProtocol](BaseUserStore[UP, UUID]):
    """Persist users via Advanced Alchemy's async SQLAlchemy repository."""

    def __init__(
        self,
        session: AsyncSessionT,
        *,
        user_model: UserModelT[UP],
        oauth_account_model: type[Any] | None = None,
    ) -> None:
        """Initialize the database adapter.

        Args:
            session: Async SQLAlchemy session used for all repository operations.
            user_model: SQLAlchemy user model used for repository operations.
            oauth_account_model: SQLAlchemy model for OAuth account rows. Required
                when using OAuth methods (``get_by_oauth_account``, ``upsert_oauth_account``).
        """
        self.session = session
        self.user_model = user_model
        self.oauth_account_model = oauth_account_model
        self._user_repository_type = _build_user_repository(self.user_model)

    def _require_oauth_account_model(self) -> type[Any]:
        """Return the OAuth account model or raise if not configured.

        Raises:
            TypeError: When ``oauth_account_model`` was not provided to the constructor.
        """
        if self.oauth_account_model is None:
            msg = (
                "OAuth methods require oauth_account_model. "
                "Pass oauth_account_model=YourOAuthModel to SQLAlchemyUserDatabase()."
            )
            raise TypeError(msg)
        return self.oauth_account_model

    def _repository(
        self,
        *,
        statement: Select[tuple[UP]] | None = None,
    ) -> SQLAlchemyAsyncRepository[UP]:
        """Create a repository bound to the configured session.

        Args:
            statement: Optional custom select statement for specialized lookups.

        Returns:
            User repository instance.
        """
        return self._user_repository_type(session=self.session, statement=statement)

    @override
    async def get(self, user_id: UUID) -> UP | None:
        """Return a user by identifier when present."""
        return await self._repository().get_one_or_none(id=user_id)

    @override
    async def get_by_email(self, email: str) -> UP | None:
        """Return a user by email address when present."""
        return await self._repository().get_one_or_none(email=email)

    _ALLOWED_LOOKUP_FIELDS: frozenset[str] = frozenset({"email", "username"})

    @override
    async def get_by_field(self, field_name: str, value: str) -> UP | None:
        """Return a user by an allowed model field when present.

        Raises:
            ValueError: If ``field_name`` is not in the allow-list.
        """
        if field_name not in self._ALLOWED_LOOKUP_FIELDS:
            msg = f"Lookup by {field_name!r} is not permitted; allowed: {sorted(self._ALLOWED_LOOKUP_FIELDS)}"
            raise ValueError(msg)
        return await cast(
            "Any",
            self._repository().get_one_or_none,
        )(**{field_name: value})

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given OAuth account, if present."""
        oa = self._require_oauth_account_model()
        statement = select(self.user_model).join(oa, oa.user_id == self.user_model.id)
        return await self._repository(statement=statement).get_one_or_none(
            oa.oauth_name == oauth_name,
            oa.account_id == account_id,
        )

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
        """Create or update an OAuth account linked to the provided user.

        Provider identity (oauth_name, account_id) is the global invariant: lookup
        is by provider identity first. Cross-user rebinding is refused.
        Access and refresh tokens are encrypted at rest via EncryptedString when
        ``oauth_token_encryption_key`` is configured for the auth plugin.

        Raises:
            OAuthAccountAlreadyLinkedError: When the provider identity is already
                linked to a different user.
        """
        require_oauth_token_encryption_key()
        oa_model = self._require_oauth_account_model()
        oauth_repo_type = _build_oauth_repository(oa_model)
        repository = oauth_repo_type(session=self.session, statement=select(oa_model))
        oauth_account = await repository.get_one_or_none(
            oa_model.oauth_name == oauth_name,
            oa_model.account_id == account_id,
        )
        if oauth_account is None:
            oauth_account = oa_model(
                user_id=user.id,
                oauth_name=oauth_name,
                account_id=account_id,
                account_email=account_email,
                access_token=access_token,
                expires_at=expires_at,
                refresh_token=refresh_token,
            )
            await repository.add(oauth_account, auto_refresh=True)
            return

        if oauth_account.user_id != user.id:
            raise OAuthAccountAlreadyLinkedError

        oauth_account.account_email = account_email
        oauth_account.access_token = access_token
        oauth_account.expires_at = expires_at
        oauth_account.refresh_token = refresh_token
        await repository.update(oauth_account, auto_refresh=True)

    @override
    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Persist and return a newly created user.

        Returns:
            Newly persisted user instance.
        """
        user = cast("UP", self.user_model(**dict(user_dict)))
        return await self._repository().add(user, auto_refresh=True)

    @override
    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""
        return await self._repository().list_and_count(
            LimitOffset(limit=limit, offset=offset),
            order_by=("email", True),
        )

    @override
    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Persist and return updates for an existing user.

        Returns:
            Updated user instance.
        """
        persistent_user = cast("UP", await self.session.merge(user))
        for field_name, value in update_dict.items():
            setattr(persistent_user, field_name, value)

        return await self._repository().update(persistent_user, auto_refresh=True)

    @override
    async def delete(self, user_id: UUID) -> None:
        """Delete the provided user from storage."""
        await self._repository().delete(user_id)
