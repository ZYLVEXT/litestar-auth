"""SQLAlchemy-backed API-key store implementation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, Protocol, TypedDict, Unpack, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from sqlalchemy import delete, inspect, select

from litestar_auth._locks import _BoundedAsyncLockRegistry
from litestar_auth.db.base import ApiKeyData, BaseApiKeyStore
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.orm import InstrumentedAttribute
    from sqlalchemy.sql import Select
    from sqlalchemy.sql.elements import ColumnElement

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]
type _ApiKeyCreateLockKey = tuple[type[object], UUID]

_API_KEY_CREATE_LOCK_LIMIT = 4096
_API_KEY_CREATE_LOCKS = _BoundedAsyncLockRegistry[_ApiKeyCreateLockKey](max_size=_API_KEY_CREATE_LOCK_LIMIT)


class _ApiKeyRow(ModelProtocol, Protocol):
    """Structural fields used by the SQLAlchemy API-key store."""

    user_id: UUID
    key_id: str
    hashed_secret: bytes
    encrypted_secret: bytes | None
    name: str
    scopes: list[str]
    prefix_env: str
    signing_required: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    created_via: str
    client_metadata: dict[str, str] | None


class _ApiKeyColumnsProtocol(Protocol):
    """SQLAlchemy class-level API-key columns consumed by query builders."""

    user_id: ClassVar[InstrumentedAttribute[UUID]]
    key_id: ClassVar[InstrumentedAttribute[str]]
    encrypted_secret: ClassVar[InstrumentedAttribute[bytes | None]]
    signing_required: ClassVar[InstrumentedAttribute[bool]]
    expires_at: ClassVar[InstrumentedAttribute[datetime | None]]
    created_at: ClassVar[InstrumentedAttribute[datetime]]
    revoked_at: ClassVar[InstrumentedAttribute[datetime | None]]


class _ApiKeyRowCreateKwargs(TypedDict):
    """Keyword payload used to construct an API-key ORM row."""

    key_id: str
    user_id: UUID
    hashed_secret: bytes
    encrypted_secret: bytes | None
    name: str
    scopes: list[str]
    prefix_env: str
    signing_required: bool
    expires_at: datetime | None
    created_via: str
    client_metadata: dict[str, str] | None


class _ApiKeyRowUpdateKwargs(TypedDict, total=False):
    """Mutable API-key row fields updated by the store."""

    encrypted_secret: bytes | None
    last_used_at: datetime | None
    name: str | None
    revoked_at: datetime | None
    scopes: list[str] | None


class _ApiKeyRowFactory[AK: _ApiKeyRow](Protocol):
    """Constructor shape used by the API-key SQLAlchemy model."""

    def __call__(self, **kwargs: Unpack[_ApiKeyRowCreateKwargs]) -> AK:
        """Return a new API-key ORM row."""


class SQLAlchemyApiKeyStore[AK: _ApiKeyRow](BaseApiKeyStore[AK, UUID]):
    """Persist API keys via a caller-provided SQLAlchemy model and async session."""

    def __init__(self, session: AsyncSessionT, *, api_key_model: type[AK]) -> None:
        """Initialize the API-key store.

        Args:
            session: Async SQLAlchemy session used for all store operations.
            api_key_model: SQLAlchemy model implementing the API-key storage contract.
        """
        self.session = session
        self.api_key_model = api_key_model

    def _columns(self) -> type[_ApiKeyColumnsProtocol]:
        """Return the API-key model as the typed SQLAlchemy column surface."""
        return cast("type[_ApiKeyColumnsProtocol]", self.api_key_model)

    async def _persist_and_refresh(self, api_key: AK) -> AK:
        """Flush pending row changes, refresh the instance, and return it.

        Returns:
            Refreshed API-key row.
        """
        await self.session.flush()
        await self.session.refresh(api_key)
        return api_key

    async def _apply_and_persist(self, api_key: AK, **changes: Unpack[_ApiKeyRowUpdateKwargs]) -> AK:
        """Apply supplied API-key row changes and persist the refreshed row.

        Returns:
            Refreshed API-key row.
        """
        if (encrypted_secret := changes.get("encrypted_secret")) is not None:
            api_key.encrypted_secret = encrypted_secret
        if (last_used_at := changes.get("last_used_at")) is not None:
            api_key.last_used_at = last_used_at
        if (name := changes.get("name")) is not None:
            api_key.name = name
        if (revoked_at := changes.get("revoked_at")) is not None:
            api_key.revoked_at = revoked_at
        if (scopes := changes.get("scopes")) is not None:
            api_key.scopes = list(scopes)
        return await self._persist_and_refresh(api_key)

    @override
    async def create(self, data: ApiKeyData[UUID]) -> AK:
        """Persist and return a newly created API key.

        Returns:
            Newly persisted API-key row.

        Raises:
            ValueError: If ``encrypted_secret`` is supplied for a non-signing key.
        """
        if not data.signing_required and data.encrypted_secret is not None:
            msg = "encrypted_secret is only valid when signing_required is true."
            raise ValueError(msg)
        api_key_model = cast("_ApiKeyRowFactory[AK]", self.api_key_model)
        api_key = api_key_model(
            key_id=data.key_id,
            user_id=data.user_id,
            hashed_secret=data.hashed_secret,
            encrypted_secret=data.encrypted_secret,
            name=data.name,
            scopes=list(data.scopes),
            prefix_env=data.prefix_env,
            signing_required=data.signing_required,
            expires_at=data.expires_at,
            created_via=data.created_via,
            client_metadata=None if data.client_metadata is None else dict(data.client_metadata),
        )
        self.session.add(api_key)
        return await self._persist_and_refresh(api_key)

    @override
    async def create_for_user_with_limit(self, data: ApiKeyData[UUID], *, max_keys_per_user: int) -> AK | None:
        """Persist an API key only while the user remains below the active-key limit.

        Returns:
            Newly persisted API-key row, or ``None`` when the active-key limit has been reached.
        """
        async with _API_KEY_CREATE_LOCKS.lock((cast("type[object]", self.api_key_model), data.user_id)):
            await self._lock_api_key_owner(data.user_id)
            if len(await self.list_for_user(data.user_id)) >= max_keys_per_user:
                return None
            return await self.create(data)

    @override
    async def get_by_key_id(self, key_id: str, *, include_inactive: bool = False) -> AK | None:
        """Return an API key by public key id when present and active."""
        api_key_columns = self._columns()
        statement = self._active_statement(select(self.api_key_model), include_inactive=include_inactive).where(
            api_key_columns.key_id == key_id,
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    @override
    async def list_for_user(self, user_id: UUID, *, include_inactive: bool = False) -> list[AK]:
        """Return API keys for a user, excluding revoked or expired rows by default."""
        api_key_columns = self._columns()
        statement = (
            self._active_statement(select(self.api_key_model), include_inactive=include_inactive)
            .where(api_key_columns.user_id == user_id)
            .order_by(api_key_columns.created_at, api_key_columns.key_id)
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    @override
    async def delete_for_user(self, user_id: UUID) -> int:
        """Permanently delete all API-key rows owned by ``user_id``.

        Returns:
            Number of deleted rows reported by the database driver.
        """
        api_key_columns = self._columns()
        result = await self.session.execute(delete(self.api_key_model).where(api_key_columns.user_id == user_id))
        await self.session.flush()
        return int(getattr(result, "rowcount", 0) or 0)

    @override
    async def revoke(self, key_id: str, *, revoked_at: datetime) -> AK | None:
        """Soft-revoke an API key and return the updated row when present.

        Returns:
            Updated API-key row, or ``None`` when no row matches ``key_id``.
        """
        api_key = await self.get_by_key_id(key_id, include_inactive=True)
        if api_key is None:
            return None
        if api_key.revoked_at is None:
            return await self._apply_and_persist(api_key, revoked_at=revoked_at)
        return api_key

    @override
    async def update(self, key_id: str, *, name: str | None = None, scopes: list[str] | None = None) -> AK | None:
        """Update mutable API-key metadata and return the updated active row.

        Returns:
            Updated API-key row, or ``None`` when no active row matches ``key_id``.
        """
        api_key = await self.get_by_key_id(key_id)
        if api_key is None:
            return None
        return await self._apply_and_persist(api_key, name=name, scopes=scopes)

    @override
    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> AK | None:
        """Update the last-used timestamp for an active API key.

        Returns:
            Updated API-key row, or ``None`` when no active row matches ``key_id``.
        """
        api_key = await self.get_by_key_id(key_id)
        if api_key is None:
            return None
        return await self._apply_and_persist(api_key, last_used_at=last_used_at)

    @override
    async def list_signing_keys_requiring_reencrypt(
        self,
        requires_reencrypt: Callable[[AK], bool],
        *,
        include_inactive: bool = False,
    ) -> list[AK]:
        """Return signing API-key rows whose encrypted secret needs keyring rotation."""
        api_key_columns = self._columns()
        statement = (
            self._active_statement(select(self.api_key_model), include_inactive=include_inactive)
            .where(
                api_key_columns.signing_required.is_(True),
                api_key_columns.encrypted_secret.is_not(None),
            )
            .order_by(api_key_columns.created_at, api_key_columns.key_id)
        )
        result = await self.session.execute(statement)
        candidates = result.scalars().all()
        return [api_key for api_key in candidates if requires_reencrypt(api_key)]

    @override
    async def replace_signing_key_encrypted_secret(self, key_id: str, *, encrypted_secret: bytes) -> AK | None:
        """Replace one signing API-key row's encrypted secret without changing other fields.

        Returns:
            Updated API-key row, or ``None`` when ``key_id`` does not identify a signing key with an encrypted secret.
        """
        api_key_columns = self._columns()
        statement = select(self.api_key_model).where(
            api_key_columns.key_id == key_id,
            api_key_columns.signing_required.is_(True),
            api_key_columns.encrypted_secret.is_not(None),
        )
        result = await self.session.execute(statement)
        api_key = result.scalar_one_or_none()
        if api_key is None:
            return None
        return await self._apply_and_persist(api_key, encrypted_secret=encrypted_secret)

    def _active_statement(self, statement: Select[tuple[AK]], *, include_inactive: bool) -> Select[tuple[AK]]:
        """Apply revoked/expired filtering unless inactive rows were requested.

        Returns:
            The original statement or one constrained to active rows.
        """
        if include_inactive:
            return statement
        api_key_columns = self._columns()
        now = datetime.now(tz=UTC)
        return statement.where(
            api_key_columns.revoked_at.is_(None),
            (api_key_columns.expires_at.is_(None)) | (api_key_columns.expires_at > now),
        )

    async def _lock_api_key_owner(self, user_id: UUID) -> None:
        """Acquire a database row lock on the API-key owner before enforcing write limits."""
        owner_id_column = self._api_key_owner_id_column()
        await self.session.execute(select(owner_id_column).where(owner_id_column == user_id).with_for_update())

    def _api_key_owner_id_column(self) -> ColumnElement[UUID]:
        """Return the parent user primary-key column referenced by the API-key ``user_id`` foreign key.

        Returns:
            Parent user primary-key column referenced by ``api_key_model.user_id``.

        Raises:
            ConfigurationError: If the API-key model does not expose exactly one ``user_id`` foreign key.
        """
        api_key_columns = inspect(self.api_key_model).columns
        if "user_id" not in api_key_columns:
            msg = "api_key_model must map a user_id column."
            raise ConfigurationError(msg)
        user_id_foreign_keys = tuple(api_key_columns["user_id"].foreign_keys)
        if len(user_id_foreign_keys) != 1:
            msg = "api_key_model.user_id must reference exactly one user table foreign key."
            raise ConfigurationError(msg)
        return cast("ColumnElement[UUID]", user_id_foreign_keys[0].column)
