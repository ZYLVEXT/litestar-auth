"""SQLAlchemy-backed user database implementation."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Protocol, Self, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.filters import LimitOffset
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy import inspect, select
from sqlalchemy.exc import NoInspectionAvailable

from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError, OAuthAccountAlreadyLinkedError
from litestar_auth.oauth_encryption import (
    OAuthTokenEncryption,
    bind_oauth_token_encryption,
    require_oauth_token_encryption,
)
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.sql import Select

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]


class SQLAlchemyUserModelProtocol(ModelProtocol, UserProtocol[UUID], Protocol):
    """Protocol for SQLAlchemy user models handled by this adapter."""


type UserModelT[UP: SQLAlchemyUserModelProtocol] = type[UP]


@dataclass(frozen=True, slots=True)
class _UserModelContract:
    """Minimal declarative contract used to validate OAuth/user model alignment."""

    model_name: str | None
    table_name: str | None
    registry: object | None


def _describe_user_model_contract(user_model: type[Any]) -> _UserModelContract:
    """Return the user-model identity details that OAuth models point back to."""
    return _UserModelContract(
        model_name=cast("str | None", getattr(user_model, "__name__", None)),
        table_name=cast("str | None", getattr(user_model, "__tablename__", None)),
        registry=getattr(user_model, "registry", None),
    )


def _describe_oauth_user_contract(oauth_model: type[Any]) -> _UserModelContract | None:
    """Return the declared user-side contract for an OAuth model when available."""
    auth_user_model = getattr(oauth_model, "auth_user_model", None)
    auth_user_table = getattr(oauth_model, "auth_user_table", None)
    if not isinstance(auth_user_model, str) and not isinstance(auth_user_table, str):
        return None
    return _UserModelContract(
        model_name=auth_user_model if isinstance(auth_user_model, str) else None,
        table_name=auth_user_table if isinstance(auth_user_table, str) else None,
        registry=getattr(oauth_model, "registry", None),
    )


def _validate_oauth_account_model_contract(
    user_model: UserModelT[SQLAlchemyUserModelProtocol],
    oauth_model: type[Any],
) -> None:
    """Reject OAuth models that point at a different user class, table, or registry.

    The supported paths are:
    - the bundled ``OAuthAccount`` with a same-registry ``User`` mapped to ``user``
    - a custom ``OAuthAccountMixin`` subclass whose hooks target ``user_model``

    Raises:
        TypeError: When ``oauth_model`` points at a different user class, table,
            or registry than ``user_model``.
    """
    expected_contract = _describe_oauth_user_contract(oauth_model)
    if expected_contract is None:
        return

    actual_contract = _describe_user_model_contract(user_model)
    mismatches: list[str] = []
    if expected_contract.model_name is not None and actual_contract.model_name != expected_contract.model_name:
        mismatches.append(
            "auth_user_model="
            f"{expected_contract.model_name!r} does not match user_model.__name__={actual_contract.model_name!r}",
        )
    if expected_contract.table_name is not None and actual_contract.table_name != expected_contract.table_name:
        mismatches.append(
            "auth_user_table="
            f"{expected_contract.table_name!r} does not match user_model.__tablename__={actual_contract.table_name!r}",
        )
    if (
        expected_contract.registry is not None
        and actual_contract.registry is not None
        and expected_contract.registry is not actual_contract.registry
    ):
        mismatches.append("oauth_account_model and user_model use different declarative registries")

    if mismatches:
        msg = (
            "oauth_account_model does not match user_model: "
            + "; ".join(mismatches)
            + ". Use a matching OAuthAccountMixin subclass for custom users, or reuse "
            "litestar_auth.models.oauth.OAuthAccount only with a same-registry User mapped to the 'user' table."
        )
        raise TypeError(msg)


@lru_cache(maxsize=16)
def _build_user_repository[UP: SQLAlchemyUserModelProtocol](
    user_model: UserModelT[UP],
) -> type[SQLAlchemyAsyncRepository[UP]]:
    """Create a repository type bound to the provided SQLAlchemy user model.

    Cached by ``user_model`` identity so repeated adapter construction does not
    allocate new dynamic repository classes.

    Returns:
        Repository class configured for ``user_model``.
    """
    return cast(
        "type[SQLAlchemyAsyncRepository[UP]]",
        type(
            f"{user_model.__name__}Repository",
            (SQLAlchemyAsyncRepository,),
            {"model_type": user_model},
        ),
    )


@lru_cache(maxsize=16)
def _build_oauth_repository(oauth_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository type bound to the provided OAuth account model.

    Returns:
        A cached Advanced Alchemy async repository subclass for ``oauth_model``.
    """
    return cast(
        "type[SQLAlchemyAsyncRepository[Any]]",
        type(
            f"{oauth_model.__name__}OAuthRepository",
            (SQLAlchemyAsyncRepository,),
            {"model_type": oauth_model},
        ),
    )


class SQLAlchemyUserDatabase[UP: SQLAlchemyUserModelProtocol](BaseUserStore[UP, UUID]):
    """Persist users via Advanced Alchemy's async SQLAlchemy repository."""

    def __init__(
        self,
        session: AsyncSessionT,
        *,
        user_model: UserModelT[UP],
        oauth_account_model: type[Any] | None = None,
        oauth_token_encryption: OAuthTokenEncryption | None = None,
    ) -> None:
        """Initialize the database adapter.

        Args:
            session: Async SQLAlchemy session used for all repository operations.
            user_model: SQLAlchemy user model used for repository operations.
            oauth_account_model: SQLAlchemy model for OAuth account rows. Required
                when using OAuth methods (``get_by_oauth_account``, ``upsert_oauth_account``).
                Models built from ``OAuthAccountMixin`` must point back to the
                same user class, table, and registry as ``user_model``.
            oauth_token_encryption: Explicit OAuth token encryption policy for this
                adapter's session path. Use
                ``OAuthTokenEncryption(key=None, unsafe_testing=True)`` for the
                explicit plaintext test policy; omitting the argument leaves OAuth
                token writes unconfigured and they will fail closed.
        """
        self.session = session
        self.user_model = user_model
        if oauth_account_model is not None:
            _validate_oauth_account_model_contract(user_model, oauth_account_model)
        self.oauth_account_model = oauth_account_model
        self._oauth_token_encryption = oauth_token_encryption
        self._user_repository_type = _build_user_repository(self.user_model)
        self._user_load = _build_user_load(self.user_model)
        if oauth_token_encryption is not None:
            self.bind_oauth_token_encryption(oauth_token_encryption)

    def bind_oauth_token_encryption(self, oauth_token_encryption: OAuthTokenEncryption) -> Self:
        """Bind an explicit OAuth token encryption policy to this adapter's session path.

        Returns:
            ``self`` for fluent handoff from plugin/session wiring.
        """
        self._oauth_token_encryption = oauth_token_encryption
        bind_oauth_token_encryption(self.session, oauth_token_encryption)
        return self

    def _require_oauth_token_encryption(self) -> OAuthTokenEncryption:
        """Return the explicit OAuth token encryption policy or fail closed.

        Raises:
            ConfigurationError: When OAuth token writes are attempted without an
                explicit policy, or with a keyless policy while
                ``oauth_token_encryption.unsafe_testing`` is false.
        """
        if self._oauth_token_encryption is None:
            msg = (
                "OAuth token writes require oauth_token_encryption. "
                "Pass oauth_token_encryption=OAuthTokenEncryption(...) to "
                "SQLAlchemyUserDatabase() or call bind_oauth_token_encryption(...)."
            )
            raise ConfigurationError(msg)
        return require_oauth_token_encryption(
            self._oauth_token_encryption,
            context="persisting OAuth access and refresh tokens",
        )

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
        return self._user_repository_type(
            session=self.session,
            statement=statement,
            load=self._user_load or None,
        )

    @override
    async def get(self, user_id: UUID) -> UP | None:
        """Return a user by identifier when present."""
        return await self._repository().get_one_or_none(id=user_id, load=self._user_load or None)

    @override
    async def get_by_email(self, email: str) -> UP | None:
        """Return a user by email address when present."""
        return await self._repository().get_one_or_none(email=email, load=self._user_load or None)

    _ALLOWED_LOOKUP_FIELDS: frozenset[LoginIdentifier] = frozenset({"email", "username"})

    @override
    async def get_by_field(self, field_name: LoginIdentifier, value: str) -> UP | None:
        """Return a user by an allowed model field when present.

        ``field_name`` must be a :data:`~litestar_auth.types.LoginIdentifier`.

        Raises:
            ValueError: If ``field_name`` is not in the allow-list (defense in depth).
        """
        if field_name not in self._ALLOWED_LOOKUP_FIELDS:
            msg = f"Lookup by {field_name!r} is not permitted; allowed: {sorted(self._ALLOWED_LOOKUP_FIELDS)}"
            raise ValueError(msg)
        return await cast(
            "Any",
            self._repository().get_one_or_none,
        )(**{field_name: value}, load=self._user_load or None)

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given OAuth account, if present."""
        oa = self._require_oauth_account_model()
        oauth_model = cast("Any", oa)
        statement = select(self.user_model).join(oa, oauth_model.user_id == self.user_model.id)
        return await self._repository(statement=statement).get_one_or_none(
            oauth_model.oauth_name == oauth_name,
            oauth_model.account_id == account_id,
            load=self._user_load or None,
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
        Access and refresh tokens are encrypted at rest when this adapter has an
        explicit ``oauth_token_encryption`` policy bound to its session path.

        Raises:
            OAuthAccountAlreadyLinkedError: When the provider identity is already
                linked to a different user.
        """
        self._require_oauth_token_encryption()
        oa_model = self._require_oauth_account_model()
        oauth_repo_type = _build_oauth_repository(oa_model)
        oauth_model = cast("Any", oa_model)
        repository = oauth_repo_type(session=self.session, statement=select(oa_model))
        oauth_account = await repository.get_one_or_none(
            oauth_model.oauth_name == oauth_name,
            oauth_model.account_id == account_id,
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
        created_user = await self._repository().add(user, auto_refresh=True)
        return await self._reload_with_relationships(created_user)

    @override
    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""
        return await self._repository().list_and_count(
            LimitOffset(limit=limit, offset=offset),
            order_by=("email", True),
            load=self._user_load or None,
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

        return await self._repository().update(
            persistent_user,
            auto_refresh=True,
            load=self._user_load or None,
        )

    @override
    async def delete(self, user_id: UUID) -> None:
        """Delete the provided user from storage."""
        await self._repository().delete(user_id)

    async def _reload_with_relationships(self, user: UP) -> UP:
        """Return ``user`` with any configured relationship loads hydrated."""
        if not self._user_load:
            return user

        reloaded_user = await self.get(user.id)
        return user if reloaded_user is None else reloaded_user


@lru_cache(maxsize=16)
def _build_user_load[UP: SQLAlchemyUserModelProtocol](
    user_model: UserModelT[UP],
) -> tuple[Any, ...]:
    """Return repository load options required by the configured user model."""
    try:
        relationships = inspect(user_model).relationships
    except NoInspectionAvailable:
        return ()
    if "role_assignments" not in relationships:
        return ()
    return (cast("Any", user_model).role_assignments,)
