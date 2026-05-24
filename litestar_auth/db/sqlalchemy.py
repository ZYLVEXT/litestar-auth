"""SQLAlchemy-backed user database implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, Self, TypedDict, Unpack, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.filters import LimitOffset
from sqlalchemy import func, inspect, select, update

from litestar_auth.db._contract import _validate_oauth_account_model_contract
from litestar_auth.db._repositories import (
    SQLAlchemyUserModelProtocol,
    UserModelT,
    _build_oauth_repository,
    _build_user_load,
    _build_user_repository,
)
from litestar_auth.db._sqlalchemy_api_keys import SQLAlchemyApiKeyStore
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
    from sqlalchemy.orm import InstrumentedAttribute
    from sqlalchemy.sql import Select

    from litestar_auth.types import LoginIdentifier

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]

__all__ = (
    "SQLAlchemyApiKeyStore",
    "SQLAlchemyUserDatabase",
    "SQLAlchemyUserModelProtocol",
)


def _collect_writable_user_fields(user_model: type[Any]) -> frozenset[str]:
    """Return the persistence-side write allow-list for a user model.

    Combines SQLAlchemy mapper attributes (columns + relationships) with any
    class-level Python properties whose setters would have a real effect, so
    that custom user models with extra columns or computed setter properties
    (e.g. ``roles`` delegating to a relationship) all stay writable while
    arbitrary unmapped names are rejected up front.
    """
    mapper = inspect(user_model)
    mapped_attrs: set[str] = {attr.key for attr in mapper.attrs}
    property_setters: set[str] = {
        attribute_name
        for klass in user_model.__mro__
        for attribute_name, member in vars(klass).items()
        if isinstance(member, property) and member.fset is not None
    }
    return frozenset(mapped_attrs | property_setters)


class _OAuthAccountRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy OAuth account upsert flow."""

    user_id: UUID
    oauth_name: str
    account_id: str
    account_email: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None


class _UserColumnsProtocol(Protocol):
    """SQLAlchemy class-level user columns consumed by query builders."""

    id: ClassVar[InstrumentedAttribute[UUID]]


class _OAuthAccountColumnsProtocol(Protocol):
    """SQLAlchemy class-level OAuth account columns consumed by query builders."""

    user_id: ClassVar[InstrumentedAttribute[UUID]]
    oauth_name: ClassVar[InstrumentedAttribute[str]]
    account_id: ClassVar[InstrumentedAttribute[str]]


class _OAuthAccountRowCreateKwargs(TypedDict):
    """Keyword payload used to construct an OAuth account ORM row."""

    user_id: UUID
    oauth_name: str
    account_id: str
    account_email: str
    access_token: str
    expires_at: int | None
    refresh_token: str | None


class _OAuthAccountRowFactory(Protocol):
    """Constructor shape used by the OAuth account SQLAlchemy model."""

    def __call__(self, **kwargs: Unpack[_OAuthAccountRowCreateKwargs]) -> _OAuthAccountRow:
        """Return a new OAuth account ORM row."""


class _RecoveryCodeUser(Protocol):
    """User row shape needed by atomic recovery-code consumption."""

    recovery_codes: dict[str, str] | None


class _RowcountResult(Protocol):
    """Result shape for SQLAlchemy DML statements that report affected rows."""

    rowcount: int


@dataclass(frozen=True, slots=True)
class _RecoveryCodeConsumeRequest[UP: SQLAlchemyUserModelProtocol]:
    """Data required by recovery-code consume strategies."""

    session: AsyncSessionT
    user_model: UserModelT[UP]
    user: UP
    lookup_hex: str
    repository: SQLAlchemyAsyncRepository[UP]
    user_load: Any


class _RecoveryCodeConsumeStrategy[UP: SQLAlchemyUserModelProtocol](Protocol):
    """Dialect-specific recovery-code consumption strategy."""

    async def consume(self, request: _RecoveryCodeConsumeRequest[UP]) -> bool:
        """Consume the recovery code identified by ``lookup_hex``."""


class _SqliteJsonRemoveStrategy:
    """Consume recovery codes atomically with SQLite JSON column functions."""

    @staticmethod
    async def consume[UP: SQLAlchemyUserModelProtocol](
        request: _RecoveryCodeConsumeRequest[UP],
    ) -> bool:
        """Consume a recovery-code lookup entry using SQLite's atomic JSON update.

        Returns:
            ``True`` when a lookup entry was removed; otherwise ``False``.
        """
        mapper = inspect(request.user_model)
        primary_key_column = mapper.primary_key[0]
        recovery_codes_column = mapper.columns["recovery_codes"]
        lookup_path = f'$."{request.lookup_hex}"'
        updated_recovery_codes = func.nullif(func.json_remove(recovery_codes_column, lookup_path), "{}")
        result = await request.session.execute(
            update(request.user_model)
            .where(primary_key_column == request.user.id)
            .where(func.json_type(recovery_codes_column, lookup_path).is_not(None))
            .values(recovery_codes=updated_recovery_codes)
            .execution_options(synchronize_session=False),
        )
        if cast("_RowcountResult", result).rowcount != 1:
            return False

        await request.session.flush()
        refresh_result = await request.session.execute(
            select(request.user_model)
            .where(primary_key_column == request.user.id)
            .execution_options(populate_existing=True),
        )
        refresh_result.scalar_one_or_none()
        return True


class _SelectForUpdateStrategy:
    """Consume recovery codes with an explicit row lock for non-SQLite dialects."""

    @staticmethod
    async def consume[UP: SQLAlchemyUserModelProtocol](
        request: _RecoveryCodeConsumeRequest[UP],
    ) -> bool:
        """Consume a recovery-code lookup entry after locking the user row.

        Returns:
            ``True`` when a lookup entry was removed; otherwise ``False``.
        """
        primary_key_column = inspect(request.user_model).primary_key[0]
        result = await request.session.execute(
            select(request.user_model).where(primary_key_column == request.user.id).with_for_update(),
        )
        persistent_user = result.scalar_one_or_none()
        if persistent_user is None:
            return False

        recovery_code_user = cast("_RecoveryCodeUser", persistent_user)
        active_index = dict(recovery_code_user.recovery_codes or {})
        if request.lookup_hex not in active_index:
            return False

        active_index.pop(request.lookup_hex)
        recovery_code_user.recovery_codes = active_index or None
        await request.repository.update(
            persistent_user,
            auto_refresh=True,
            load=request.user_load or None,
        )
        return True


_SQLITE_JSON_REMOVE_RECOVERY_CODE_STRATEGY = _SqliteJsonRemoveStrategy()
_SELECT_FOR_UPDATE_RECOVERY_CODE_STRATEGY = _SelectForUpdateStrategy()


def _recovery_code_consume_strategy_for_dialect(dialect_name: str) -> _RecoveryCodeConsumeStrategy[Any]:
    """Return the recovery-code consume strategy for a SQL dialect name."""
    if dialect_name == "sqlite":
        return _SQLITE_JSON_REMOVE_RECOVERY_CODE_STRATEGY
    return _SELECT_FOR_UPDATE_RECOVERY_CODE_STRATEGY


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
        # Defense-in-depth: ``update`` consults a write allow-list derived from
        # the user model's actual write surface (mapped columns + relationships
        # + setter properties), so manager-level filters are not the only line
        # between caller payload and ``setattr``. Computation is deferred until
        # the first ``update`` call so constructing the adapter with a not-yet-
        # mapped placeholder class (used for lazy-import tests, deferred ORM
        # configuration, etc.) does not eagerly invoke the SQLAlchemy mapper.
        self._user_model_writable_fields_cache: frozenset[str] | None = None
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

    def _writable_user_fields(self) -> frozenset[str]:
        """Return the cached write allow-list for the configured user model.

        Computed on first call so the adapter can be constructed with a
        not-yet-mapped placeholder class without triggering the SQLAlchemy
        inspector eagerly. Subsequent calls return the cached value.
        """
        if self._user_model_writable_fields_cache is None:
            self._user_model_writable_fields_cache = _collect_writable_user_fields(self.user_model)
        return self._user_model_writable_fields_cache

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

    def _user_columns(self) -> type[_UserColumnsProtocol]:
        """Return the user model as the typed SQLAlchemy column surface."""
        return cast("type[_UserColumnsProtocol]", self.user_model)

    @staticmethod
    def _oauth_columns(oauth_model: type[Any]) -> type[_OAuthAccountColumnsProtocol]:
        """Return an OAuth account model as the typed SQLAlchemy column surface."""
        return cast("type[_OAuthAccountColumnsProtocol]", oauth_model)

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
        if field_name == "email":
            return await self._repository().get_one_or_none(email=value, load=self._user_load or None)
        return await self._repository().get_one_or_none(username=value, load=self._user_load or None)

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given OAuth account, if present."""
        oa = self._require_oauth_account_model()
        oauth_columns = self._oauth_columns(oa)
        statement = select(self.user_model).join(oa, oauth_columns.user_id == self._user_columns().id)
        return await self._repository(statement=statement).get_one_or_none(
            oauth_columns.oauth_name == oauth_name,
            oauth_columns.account_id == account_id,
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
        oauth_columns = SQLAlchemyUserDatabase._oauth_columns(repository.model_type)
        return await repository.get_one_or_none(
            oauth_columns.oauth_name == oauth_name,
            oauth_columns.account_id == account_id,
        )

    @staticmethod
    async def _insert_new_oauth_account(
        oa_model: type[Any],
        repository: SQLAlchemyAsyncRepository[_OAuthAccountRow],
        user: UP,
        account: OAuthAccountData,
    ) -> None:
        """Persist a new OAuth account row linked to ``user``."""
        oauth_account = cast("_OAuthAccountRowFactory", oa_model)(
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
        return await self._repository().get_many_and_count(
            LimitOffset(limit=limit, offset=offset),
            order_by=("email", True),
            load=self._user_load or None,
        )

    @override
    async def update(self, user: UP, update_dict: Mapping[str, Any]) -> UP:
        """Persist and return updates for an existing user.

        Manager-level callers already filter privileged and unknown fields, but
        this layer enforces a defense-in-depth check against the user model's
        actual write surface so that any caller bypassing the manager (custom
        code wired straight to the persistence adapter) cannot smuggle
        arbitrary attribute writes through ``setattr``.

        Returns:
            Updated user instance.

        Raises:
            ValueError: If ``update_dict`` references fields that are neither
                mapped attributes (columns or relationships) nor settable
                Python properties on the configured user model.
        """
        unknown_fields = update_dict.keys() - self._writable_user_fields()
        if unknown_fields:
            msg = (
                f"SQLAlchemyUserDatabase.update rejected fields not on "
                f"{self.user_model.__name__!r}: {sorted(unknown_fields)!r}."
            )
            raise ValueError(msg)
        persistent_user = await self.session.merge(user)
        for field_name, value in update_dict.items():
            setattr(persistent_user, field_name, value)

        return await self._repository().update(
            persistent_user,
            auto_refresh=True,
            load=self._user_load or None,
        )

    async def set_recovery_code_hashes(self, user: UP, code_index: dict[str, str]) -> UP:
        """Replace the user's active TOTP recovery-code lookup index.

        Returns:
            Updated user instance.
        """
        return await self.update(user, {"recovery_codes": dict(code_index) or None})

    async def find_recovery_code_hash_by_lookup(self, user: UP, lookup_hex: str) -> str | None:
        """Return the user's active recovery-code hash for ``lookup_hex``."""
        if not isinstance(user, self.user_model):
            return None
        stored_index = getattr(user, "recovery_codes", None) or {}
        return cast("dict[str, str]", stored_index).get(lookup_hex)

    async def consume_recovery_code_by_lookup(self, user: UP, lookup_hex: str) -> bool:
        """Atomically mark the recovery code keyed by ``lookup_hex`` consumed.

        Concurrent callers presenting the same recovery code MUST observe
        exactly one success and N-1 failures.

        Returns:
            ``True`` when the code was active and is now consumed; ``False`` when
            it was already consumed or never existed.
        """
        strategy = cast(
            "_RecoveryCodeConsumeStrategy[UP]",
            _recovery_code_consume_strategy_for_dialect(self.session.get_bind().dialect.name),
        )
        request = _RecoveryCodeConsumeRequest(
            session=self.session,
            user_model=self.user_model,
            user=user,
            lookup_hex=lookup_hex,
            repository=self._repository(),
            user_load=self._user_load,
        )
        return await strategy.consume(request)

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
