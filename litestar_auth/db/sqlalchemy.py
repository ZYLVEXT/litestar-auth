"""SQLAlchemy-backed user database implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Self, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.filters import LimitOffset
from sqlalchemy import inspect, select

from litestar_auth.db._contract import _validate_oauth_account_model_contract
from litestar_auth.db._repositories import (
    SQLAlchemyUserModelProtocol,
    UserModelT,
    _build_oauth_repository,
    _build_user_load,
    _build_user_repository,
)
from litestar_auth.db.base import BaseUserStore, OAuthAccountData
from litestar_auth.exceptions import ConfigurationError, OAuthAccountAlreadyLinkedError
from litestar_auth.oauth_encryption import (
    OAuthTokenEncryption,
    bind_oauth_token_encryption,
    require_oauth_token_encryption,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from advanced_alchemy.repository import SQLAlchemyAsyncRepository
    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.sql import Select

    from litestar_auth.types import LoginIdentifier

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]


class _OAuthAccountRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy OAuth account upsert flow."""

    user_id: UUID
    oauth_name: str
    account_id: str
    account_email: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None


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

    async def upsert_oauth_account(
        self,
        user: UP,
        *,
        account: OAuthAccountData,
    ) -> None:
        """Create or update an OAuth account linked to the provided user.

        Provider identity (oauth_name, account_id) is the global invariant: lookup
        is by provider identity first. Cross-user rebinding is refused.
        Access and refresh tokens are encrypted at rest when this adapter has an
        explicit ``oauth_token_encryption`` policy bound to its session path.

        """
        oa_model, repository = self._require_oauth_repository()
        oauth_account = await self._lookup_oauth_account(
            repository,
            oauth_name=account.oauth_name,
            account_id=account.account_id,
        )
        if oauth_account is None:
            await self._insert_new_oauth_account(oa_model, repository, user, account)
            return

        await self._update_existing_oauth_account(repository, oauth_account, user, account)

    def _require_oauth_repository(self) -> tuple[type[Any], SQLAlchemyAsyncRepository[_OAuthAccountRow]]:
        """Return the configured OAuth account model and session-bound repository."""
        self._require_oauth_token_encryption()
        oa_model = self._require_oauth_account_model()
        oauth_repo_type = _build_oauth_repository(oa_model)
        repository = cast(
            "SQLAlchemyAsyncRepository[_OAuthAccountRow]",
            oauth_repo_type(session=self.session, statement=select(oa_model)),
        )
        return oa_model, repository

    @staticmethod
    async def _lookup_oauth_account(
        repository: SQLAlchemyAsyncRepository[_OAuthAccountRow],
        *,
        oauth_name: str,
        account_id: str,
    ) -> _OAuthAccountRow | None:
        """Return an OAuth account row by provider identity when it exists."""
        oauth_model = cast("Any", repository.model_type)
        return await repository.get_one_or_none(
            oauth_model.oauth_name == oauth_name,
            oauth_model.account_id == account_id,
        )

    @staticmethod
    async def _insert_new_oauth_account(
        oa_model: type[Any],
        repository: SQLAlchemyAsyncRepository[_OAuthAccountRow],
        user: UP,
        account: OAuthAccountData,
    ) -> None:
        """Persist a new OAuth account row linked to ``user``."""
        oauth_account = oa_model(
            user_id=user.id,
            oauth_name=account.oauth_name,
            account_id=account.account_id,
            account_email=account.account_email,
            access_token=account.access_token,
            expires_at=account.expires_at,
            refresh_token=account.refresh_token,
        )
        await repository.add(oauth_account, auto_refresh=True)

    @staticmethod
    async def _update_existing_oauth_account(
        repository: SQLAlchemyAsyncRepository[_OAuthAccountRow],
        oauth_account: _OAuthAccountRow,
        user: UP,
        account: OAuthAccountData,
    ) -> None:
        """Validate ownership and persist OAuth account token updates.

        Raises:
            OAuthAccountAlreadyLinkedError: When the provider identity is already
                linked to a different user.
        """
        if oauth_account.user_id != user.id:
            raise OAuthAccountAlreadyLinkedError(
                provider=oauth_account.oauth_name,
                account_id=oauth_account.account_id,
                existing_user_id=oauth_account.user_id,
            )

        oauth_account.account_email = account.account_email
        oauth_account.access_token = account.access_token
        oauth_account.expires_at = account.expires_at
        oauth_account.refresh_token = account.refresh_token
        await repository.update(oauth_account, auto_refresh=True)

    @override
    async def create(self, user_dict: Mapping[str, Any]) -> UP:
        """Persist and return a newly created user.

        Returns:
            Newly persisted user instance.
        """
        user = self.user_model(**dict(user_dict))
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
        persistent_user = await self.session.merge(user)
        for field_name, value in update_dict.items():
            setattr(persistent_user, field_name, value)

        return await self._repository().update(
            persistent_user,
            auto_refresh=True,
            load=self._user_load or None,
        )

    async def set_recovery_code_hashes(self, user: UP, hashes: tuple[str, ...]) -> UP:
        """Replace the user's active TOTP recovery-code hashes.

        Returns:
            Updated user instance.
        """
        return await self.update(user, {"recovery_codes_hashes": list(hashes) or None})

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]:
        """Return the user's active TOTP recovery-code hashes."""
        if not isinstance(user, self.user_model):
            return ()
        if stored_hashes := getattr(user, "recovery_codes_hashes", None):
            return tuple(stored_hashes)
        return ()

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool:
        """Atomically mark ``matched_hash`` consumed for the user.

        Returns:
            ``True`` when the hash was active and is now consumed; ``False`` when
            it was already consumed or never existed.
        """
        primary_key_column = inspect(self.user_model).primary_key[0]
        result = await self.session.execute(
            select(self.user_model).where(primary_key_column == user.id).with_for_update(),
        )
        persistent_user = cast("Any", result).scalar_one_or_none()
        if persistent_user is None:
            return False

        active_hashes = list(getattr(persistent_user, "recovery_codes_hashes", None) or ())
        if matched_hash not in active_hashes:
            return False

        active_hashes.remove(matched_hash)
        persistent_user.recovery_codes_hashes = active_hashes or None
        await self._repository().update(
            persistent_user,
            auto_refresh=True,
            load=self._user_load or None,
        )
        return True

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
