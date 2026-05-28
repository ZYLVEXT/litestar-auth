"""Database-backed authentication strategy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    NotRequired,
    Protocol,
    Required,
    TypedDict,
    Unpack,
    overload,
    override,
    runtime_checkable,
)

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session

from litestar_auth.authentication.strategy._db_refresh import _DatabaseRefreshSessionMixin
from litestar_auth.authentication.strategy._db_repositories import TokenRepositoryType, build_token_repository
from litestar_auth.authentication.strategy._opaque_tokens import (
    digest_opaque_token,
    mint_opaque_token,
    validate_token_bytes,
)
from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    Strategy,
    UserManagerProtocol,
)
from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels
from litestar_auth.config import validate_production_secret
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from advanced_alchemy.repository import SQLAlchemyAsyncRepository
    from sqlalchemy.sql.base import Executable

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]

DEFAULT_MAX_AGE = timedelta(hours=1)
DEFAULT_REFRESH_MAX_AGE = timedelta(days=30)
DEFAULT_TOKEN_BYTES = 32


@runtime_checkable
class _RowcountResult(Protocol):
    """SQLAlchemy result shape used after single-statement UPDATE/DELETE execution."""

    rowcount: int


@runtime_checkable
class _AccessTokenRow[UP: UserProtocol[Any]](Protocol):
    """Persisted access-token fields required for authentication."""

    created_at: datetime
    user: UP


@dataclass(frozen=True, slots=True)
class DatabaseTokenStrategyConfig:
    """Configuration for :class:`DatabaseTokenStrategy`."""

    session: AsyncSessionT
    token_hash_secret: str
    token_models: DatabaseTokenModels | None = None
    max_age: timedelta = DEFAULT_MAX_AGE
    refresh_max_age: timedelta = DEFAULT_REFRESH_MAX_AGE
    token_bytes: int = DEFAULT_TOKEN_BYTES
    unsafe_testing: bool = False


class DatabaseTokenStrategyOptions(TypedDict):
    """Keyword options accepted by :class:`DatabaseTokenStrategy`."""

    session: Required[AsyncSessionT]
    token_hash_secret: Required[str]
    token_models: NotRequired[DatabaseTokenModels | None]
    max_age: NotRequired[timedelta]
    refresh_max_age: NotRequired[timedelta]
    token_bytes: NotRequired[int]
    unsafe_testing: NotRequired[bool]


class DatabaseTokenStrategy[UP: UserProtocol[Any], ID](
    _DatabaseRefreshSessionMixin[UP, ID],
    Strategy[UP, ID],
    RefreshableStrategy[UP, ID],
):
    """Stateful strategy that persists opaque tokens in the database."""

    @overload
    def __init__(self, *, config: DatabaseTokenStrategyConfig) -> None: ...

    @overload
    def __init__(self, **options: Unpack[DatabaseTokenStrategyOptions]) -> None: ...

    def __init__(
        self,
        *,
        config: DatabaseTokenStrategyConfig | None = None,
        **options: Unpack[DatabaseTokenStrategyOptions],
    ) -> None:
        """Initialize the strategy.

        Args:
            config: Database-token strategy configuration.
            **options: Individual database-token strategy settings. Do not combine
                with ``config``.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
            ConfigurationError: When ``token_hash_secret`` fails minimum-length requirements.
        """
        if config is not None and options:
            msg = "Pass either DatabaseTokenStrategyConfig or keyword options, not both."
            raise ValueError(msg)
        settings = DatabaseTokenStrategyConfig(**options) if config is None else config
        try:
            validate_production_secret(settings.token_hash_secret, label="DatabaseTokenStrategy token_hash_secret")
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc
        validate_token_bytes(settings.token_bytes, label="DatabaseTokenStrategy")

        self.session = settings.session
        self._token_hash_secret = settings.token_hash_secret.encode()
        self.token_models = DatabaseTokenModels() if settings.token_models is None else settings.token_models
        self.access_token_model = self.token_models.access_token_model
        self.refresh_token_model = self.token_models.refresh_token_model
        self._access_token_repository_type = build_token_repository(self.access_token_model)
        self._refresh_token_repository_type = build_token_repository(self.refresh_token_model)
        self.max_age = settings.max_age
        self.refresh_max_age = settings.refresh_max_age
        self.token_bytes = settings.token_bytes
        self.unsafe_testing = settings.unsafe_testing
        self._refresh_token_request_metadata: dict[str, str] | None = None

    def with_session(self, session: AsyncSessionT) -> DatabaseTokenStrategy[UP, ID]:
        """Return a copy of the strategy bound to the provided async session."""
        return type(self)(
            session=session,
            token_hash_secret=self._token_hash_secret.decode(),
            token_models=self.token_models,
            max_age=self.max_age,
            refresh_max_age=self.refresh_max_age,
            token_bytes=self.token_bytes,
            unsafe_testing=self.unsafe_testing,
        )

    def _repository(self, repository_type: TokenRepositoryType) -> SQLAlchemyAsyncRepository[Any]:
        """Create a repository bound to the current session.

        Returns:
            Repository instance for token persistence.
        """
        return repository_type(session=self.session)

    def _token_digest(self, token: str) -> str:
        """Return the keyed digest stored for a raw token."""
        return digest_opaque_token(token_hash_secret=self._token_hash_secret, token=token)

    def _is_token_expired(self, created_at: datetime, max_age: timedelta) -> bool:
        """Return whether a token created at ``created_at`` exceeds ``max_age``."""
        normalized = self._normalize_timestamp(created_at)
        expires_at = normalized + max_age
        return expires_at <= datetime.now(tz=UTC)

    async def _execute_delete(self, statement: Executable) -> int:
        """Execute a delete statement and return its matched row count.

        Returns:
            Number of rows matched by the statement.
        """
        result = await self.session.execute(statement)
        if isinstance(result, _RowcountResult):
            return result.rowcount or 0
        return 0

    async def _resolve_token(
        self,
        repository: SQLAlchemyAsyncRepository[Any],
        raw_token: str,
        *,
        load: list[Any],
    ) -> object | None:
        """Look up a token row by digest.

        Returns:
            Persisted token row when found, otherwise ``None``.
        """
        token_digest = self._token_digest(raw_token)
        return await repository.get_one_or_none(token=token_digest, load=load)

    async def cleanup_expired_tokens(self, session: AsyncSession) -> int:
        """Delete expired access and refresh tokens for the configured TTLs.

        Returns:
            Total number of deleted access-token and refresh-token rows.
        """
        now = datetime.now(tz=UTC)
        access_cutoff = now - self.max_age
        refresh_cutoff = now - self.refresh_max_age

        access_result = await session.execute(
            delete(self.access_token_model).where(self.access_token_model.created_at <= access_cutoff),
        )
        refresh_result = await session.execute(
            delete(self.refresh_token_model).where(self.refresh_token_model.created_at <= refresh_cutoff),
        )
        await session.commit()

        access_rowcount = getattr(access_result, "rowcount", 0) or 0
        refresh_rowcount = getattr(refresh_result, "rowcount", 0) or 0
        return access_rowcount + refresh_rowcount

    @override
    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> UP | None:
        """Resolve a user from an opaque database token.

        Returns:
            Related user when the token exists and is not expired, otherwise ``None``.
        """
        if token is None:
            return None

        access_token = await self._resolve_access_token(token)
        if access_token is None or self._is_token_expired(access_token.created_at, self.max_age):
            return None

        return access_token.user

    async def _resolve_access_token(self, raw_token: str) -> _AccessTokenRow[UP] | None:
        """Return the persisted access-token row for ``raw_token`` when present."""
        token_row = await self._resolve_token(
            self._repository(self._access_token_repository_type),
            raw_token,
            load=[self.access_token_model.user],
        )
        if isinstance(token_row, _AccessTokenRow):
            return token_row
        return None

    @override
    async def write_token(self, user: UP) -> str:
        """Persist and return a new opaque token for the user.

        Returns:
            Newly created opaque token string.
        """
        token, token_digest = mint_opaque_token(token_bytes=self.token_bytes, token_hash_secret=self._token_hash_secret)
        access_token = self.access_token_model(token=token_digest, user_id=user.id)
        await self._repository(self._access_token_repository_type).add(access_token, auto_refresh=True)
        return token

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Delete a persisted token."""
        token_digest = self._token_digest(token)
        await self._repository(self._access_token_repository_type).delete_where(token=token_digest, auto_commit=False)
        await self.session.commit()

    @override
    async def write_refresh_token(self, user: UP) -> str:
        """Persist and return a new opaque refresh token for the user.

        Returns:
            Newly created opaque refresh-token string.
        """
        token, token_digest = mint_opaque_token(token_bytes=self.token_bytes, token_hash_secret=self._token_hash_secret)
        refresh_token = self.refresh_token_model(
            token=token_digest,
            user_id=user.id,
            client_metadata=self._consume_refresh_token_request_metadata(),
        )
        await self._repository(self._refresh_token_repository_type).add(refresh_token, auto_refresh=True)
        return token

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all persisted access and refresh tokens for the given user."""
        await self._repository(self._access_token_repository_type).delete_where(user_id=user.id, auto_commit=False)
        await self._repository(self._refresh_token_repository_type).delete_where(user_id=user.id, auto_commit=False)
        await self.session.commit()
