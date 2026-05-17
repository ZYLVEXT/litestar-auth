"""SQLAlchemy-backed API-key store implementation."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast, override
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from sqlalchemy import delete, inspect, select

from litestar_auth.db.base import ApiKeyData, BaseApiKeyStore
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session
    from sqlalchemy.sql import Select
    from sqlalchemy.sql.elements import ColumnElement

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]
type _ApiKeyCreateLockKey = tuple[type[object], UUID]

_API_KEY_CREATE_LOCK_LIMIT = 4096


class _ApiKeyCreateLockRegistry:
    """Bound process-local API-key creation locks while preserving active entries."""

    def __init__(self, *, max_size: int = _API_KEY_CREATE_LOCK_LIMIT) -> None:
        """Initialize a bounded lock registry.

        Args:
            max_size: Maximum number of idle and recently used locks to retain. When active concurrency exceeds this
                value, held locks are retained until they can be safely evicted after release.

        Raises:
            ValueError: If ``max_size`` is less than one.
        """
        if max_size < 1:
            msg = "max_size must be at least 1."
            raise ValueError(msg)
        self.max_size = max_size
        self._locks: OrderedDict[_ApiKeyCreateLockKey, asyncio.Lock] = OrderedDict()

    def __len__(self) -> int:
        """Return the number of currently retained lock entries."""
        return len(self._locks)

    def __getitem__(self, key: _ApiKeyCreateLockKey) -> asyncio.Lock:
        """Return a lock for ``key`` and evict oldest idle entries over the limit."""
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
            self._evict_idle_locks(exclude_key=key)
            return lock
        self._locks.move_to_end(key)
        return lock

    @asynccontextmanager
    async def lock(self, key: _ApiKeyCreateLockKey) -> AsyncIterator[None]:
        """Hold the per-key create lock and prune idle overflow after release."""
        lock = self[key]
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()
            self._evict_idle_locks()

    def _evict_idle_locks(self, *, exclude_key: _ApiKeyCreateLockKey | None = None) -> None:
        """Evict oldest unlocked entries until the registry is within its idle bound."""
        while len(self._locks) > self.max_size:
            evicted_key = next(
                (key for key, lock in self._locks.items() if key != exclude_key and not lock.locked()),
                None,
            )
            if evicted_key is None:
                return
            del self._locks[evicted_key]


_API_KEY_CREATE_LOCKS = _ApiKeyCreateLockRegistry()


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
        api_key_model = cast("Any", self.api_key_model)
        api_key = cast(
            "AK",
            api_key_model(
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
            ),
        )
        self.session.add(api_key)
        await self.session.flush()
        await self.session.refresh(api_key)
        return api_key

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
        api_key_model = cast("Any", self.api_key_model)
        statement = self._active_statement(select(self.api_key_model), include_inactive=include_inactive).where(
            api_key_model.key_id == key_id,
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    @override
    async def list_for_user(self, user_id: UUID, *, include_inactive: bool = False) -> list[AK]:
        """Return API keys for a user, excluding revoked or expired rows by default."""
        api_key_model = cast("Any", self.api_key_model)
        statement = (
            self
            ._active_statement(select(self.api_key_model), include_inactive=include_inactive)
            .where(api_key_model.user_id == user_id)
            .order_by(api_key_model.created_at, api_key_model.key_id)
        )
        result = await self.session.execute(statement)
        return list(cast("Any", result).scalars().all())

    @override
    async def delete_for_user(self, user_id: UUID) -> int:
        """Permanently delete all API-key rows owned by ``user_id``.

        Returns:
            Number of deleted rows reported by the database driver.
        """
        api_key_model = cast("Any", self.api_key_model)
        result = await self.session.execute(delete(self.api_key_model).where(api_key_model.user_id == user_id))
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
            api_key.revoked_at = revoked_at
            await self.session.flush()
            await self.session.refresh(api_key)
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
        if name is not None:
            api_key.name = name
        if scopes is not None:
            api_key.scopes = list(scopes)
        await self.session.flush()
        await self.session.refresh(api_key)
        return api_key

    @override
    async def update_last_used_at(self, key_id: str, *, last_used_at: datetime) -> AK | None:
        """Update the last-used timestamp for an active API key.

        Returns:
            Updated API-key row, or ``None`` when no active row matches ``key_id``.
        """
        api_key = await self.get_by_key_id(key_id)
        if api_key is None:
            return None
        api_key.last_used_at = last_used_at
        await self.session.flush()
        await self.session.refresh(api_key)
        return api_key

    @override
    async def list_signing_keys_requiring_reencrypt(
        self,
        requires_reencrypt: Callable[[AK], bool],
        *,
        include_inactive: bool = False,
    ) -> list[AK]:
        """Return signing API-key rows whose encrypted secret needs keyring rotation."""
        api_key_model = cast("Any", self.api_key_model)
        statement = (
            self
            ._active_statement(select(self.api_key_model), include_inactive=include_inactive)
            .where(
                api_key_model.signing_required.is_(True),
                api_key_model.encrypted_secret.is_not(None),
            )
            .order_by(api_key_model.created_at, api_key_model.key_id)
        )
        result = await self.session.execute(statement)
        candidates = cast("Any", result).scalars().all()
        return [api_key for api_key in candidates if requires_reencrypt(api_key)]

    @override
    async def replace_signing_key_encrypted_secret(self, key_id: str, *, encrypted_secret: bytes) -> AK | None:
        """Replace one signing API-key row's encrypted secret without changing other fields.

        Returns:
            Updated API-key row, or ``None`` when ``key_id`` does not identify a signing key with an encrypted secret.
        """
        api_key_model = cast("Any", self.api_key_model)
        statement = select(self.api_key_model).where(
            api_key_model.key_id == key_id,
            api_key_model.signing_required.is_(True),
            api_key_model.encrypted_secret.is_not(None),
        )
        result = await self.session.execute(statement)
        api_key = result.scalar_one_or_none()
        if api_key is None:
            return None
        api_key.encrypted_secret = encrypted_secret
        await self.session.flush()
        await self.session.refresh(api_key)
        return api_key

    def _active_statement(self, statement: Select[tuple[AK]], *, include_inactive: bool) -> Select[tuple[AK]]:
        """Apply revoked/expired filtering unless inactive rows were requested.

        Returns:
            The original statement or one constrained to active rows.
        """
        if include_inactive:
            return statement
        api_key_model = cast("Any", self.api_key_model)
        now = datetime.now(tz=UTC)
        return statement.where(
            api_key_model.revoked_at.is_(None),
            (api_key_model.expires_at.is_(None)) | (api_key_model.expires_at > now),
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
