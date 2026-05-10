"""Database-backed authentication strategy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, NotRequired, Protocol, Required, TypedDict, Unpack, cast, overload, override

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session

from litestar_auth.authentication.strategy._db_repositories import TokenRepositoryType, build_token_repository
from litestar_auth.authentication.strategy._opaque_tokens import (
    digest_opaque_token,
    mint_opaque_token,
    validate_token_bytes,
)
from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    RefreshSession,
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
_CLIENT_METADATA_USER_AGENT_KEY = "user_agent"
_MAX_CLIENT_METADATA_VALUE_LENGTH = 255


class _RefreshTokenRow(Protocol):
    """Persistence contract needed by refresh-token rotation."""

    token: str
    created_at: datetime
    session_id: str
    last_used_at: datetime | None
    client_metadata: dict[str, str] | None
    user_id: object
    user: object


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


class DatabaseTokenStrategy[UP: UserProtocol[Any], ID](Strategy[UP, ID], RefreshableStrategy[UP, ID]):
    """Stateful strategy that persists opaque tokens in the database."""

    @overload
    def __init__(self, *, config: DatabaseTokenStrategyConfig) -> None:
        pass  # pragma: no cover

    @overload
    def __init__(self, **options: Unpack[DatabaseTokenStrategyOptions]) -> None:
        pass  # pragma: no cover

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

    @staticmethod
    def _normalize_timestamp(value: datetime) -> datetime:
        """Normalize persisted timestamps to UTC-aware datetimes.

        Returns:
            UTC-aware timestamp.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _is_token_expired(self, created_at: datetime, max_age: timedelta) -> bool:
        """Return whether a token created at ``created_at`` exceeds ``max_age``."""
        normalized = self._normalize_timestamp(created_at)
        expires_at = normalized + max_age
        return expires_at <= datetime.now(tz=UTC)

    def _token_digest(self, token: str) -> str:
        """Return the keyed digest stored for a raw token."""
        return digest_opaque_token(token_hash_secret=self._token_hash_secret, token=token)

    async def _execute_delete(self, statement: Executable) -> int:
        """Execute a delete statement and return its matched row count.

        Returns:
            Number of rows matched by the statement.
        """
        result = await self.session.execute(statement)
        return cast("int", getattr(result, "rowcount", 0) or 0)

    @staticmethod
    def _bounded_client_metadata_value(value: object) -> str | None:
        """Return a normalized, bounded metadata value safe for refresh-session storage."""
        if not isinstance(value, str):
            return None
        normalized = " ".join(value.split())
        if not normalized:
            return None
        return normalized[:_MAX_CLIENT_METADATA_VALUE_LENGTH]

    @classmethod
    def _extract_refresh_token_client_metadata(cls, request: object) -> dict[str, str] | None:
        """Return bounded client metadata derived from the current HTTP request."""
        headers = getattr(request, "headers", {})
        user_agent = cls._bounded_client_metadata_value(getattr(headers, "get", lambda _: None)("user-agent"))
        if user_agent is None:
            return None
        return {_CLIENT_METADATA_USER_AGENT_KEY: user_agent}

    def set_refresh_token_request_context(self, request: object) -> None:
        """Capture safe request metadata for the next refresh-token write or rotation."""
        self._refresh_token_request_metadata = self._extract_refresh_token_client_metadata(request)

    def _consume_refresh_token_request_metadata(self) -> dict[str, str] | None:
        """Return captured request metadata and clear it from the strategy instance."""
        metadata = self._refresh_token_request_metadata
        self._refresh_token_request_metadata = None
        return metadata

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

    async def _delete_expired_refresh_sessions_for_user(self, user: UP) -> int:
        """Delete expired refresh-token rows for ``user``.

        Returns:
            Number of deleted rows.
        """
        cutoff = datetime.now(tz=UTC) - self.refresh_max_age
        return await self._execute_delete(
            delete(self.refresh_token_model).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.created_at <= cutoff,
            ),
        )

    @staticmethod
    def _refresh_session_from_row(row: _RefreshTokenRow) -> RefreshSession:
        """Build safe public refresh-session metadata from a persistence row.

        Returns:
            Refresh-session metadata without token storage details.
        """
        return RefreshSession(
            session_id=row.session_id,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            client_metadata=row.client_metadata,
        )

    async def list_refresh_sessions(self, user: UP) -> list[RefreshSession]:
        """Return active refresh sessions belonging to ``user``.

        Expired refresh-token rows are deleted before active sessions are returned.

        Returns:
            Active refresh-session metadata ordered by creation time.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        if expired_count:
            await self.session.commit()

        result = await self.session.execute(
            select(self.refresh_token_model)
            .where(self.refresh_token_model.user_id == user.id)
            .order_by(self.refresh_token_model.created_at),
        )
        rows = cast("list[_RefreshTokenRow]", result.scalars().all())
        return [self._refresh_session_from_row(row) for row in rows]

    async def revoke_refresh_session(self, user: UP, session_id: str) -> bool:
        """Revoke one active refresh session for ``user`` by public session id.

        Returns:
            ``True`` when a matching active session was deleted, otherwise ``False``.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        deleted_count = await self._execute_delete(
            delete(self.refresh_token_model).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.session_id == session_id,
            ),
        )
        if expired_count or deleted_count:
            await self.session.commit()
        return deleted_count > 0

    async def revoke_other_refresh_sessions(self, user: UP, current_session_id: str | None) -> int:
        """Revoke active refresh sessions for ``user`` except ``current_session_id``.

        Returns:
            Number of active refresh sessions revoked.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        conditions = [self.refresh_token_model.user_id == user.id]
        if current_session_id is not None:
            conditions.append(self.refresh_token_model.session_id != current_session_id)
        deleted_count = await self._execute_delete(delete(self.refresh_token_model).where(*conditions))
        if expired_count or deleted_count:
            await self.session.commit()
        return deleted_count

    async def identify_refresh_session(self, user: UP, refresh_token: str) -> str | None:
        """Return the public refresh-session id for ``refresh_token`` when it belongs to ``user``.

        Returns:
            Public refresh-session id, or ``None`` when the token is missing, expired, or not owned by ``user``.
        """
        persisted_token = cast(
            "_RefreshTokenRow | None",
            await self._resolve_token(
                self._repository(self._refresh_token_repository_type),
                refresh_token,
                load=[],
            ),
        )
        if persisted_token is None or persisted_token.user_id != user.id:
            return None
        if self._is_token_expired(persisted_token.created_at, self.refresh_max_age):
            await self._delete_refresh_token_row(persisted_token)
            await self.session.commit()
            return None
        return persisted_token.session_id

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
        del user_manager
        if token is None:
            return None

        access_token = cast(
            "Any",
            await self._resolve_token(
                self._repository(self._access_token_repository_type),
                token,
                load=[self.access_token_model.user],
            ),
        )
        if access_token is None or self._is_token_expired(access_token.created_at, self.max_age):
            return None

        return cast("UP", access_token.user)

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
        del user
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

    async def _load_refresh_token_for_rotation(self, refresh_token: str) -> _RefreshTokenRow | None:
        """Load a refresh-token row for rotation.

        Returns:
            Persisted refresh-token row with its user loaded, otherwise ``None``.
        """
        return cast(
            "_RefreshTokenRow | None",
            await self._resolve_token(
                self._repository(self._refresh_token_repository_type),
                refresh_token,
                load=[self.refresh_token_model.user],
            ),
        )

    async def _delete_refresh_token_row(self, persisted_token: _RefreshTokenRow) -> None:
        """Mark a persisted refresh-token row for deletion within the current transaction."""
        await self._repository(self._refresh_token_repository_type).delete_where(
            token=persisted_token.token,
            auto_commit=False,
        )

    async def _mint_replacement_refresh_token(
        self,
        user: UP,
        persisted_token: _RefreshTokenRow,
        *,
        client_metadata: dict[str, str] | None,
    ) -> str:
        """Persist and return a replacement refresh token for ``user``.

        Returns:
            Newly created opaque refresh-token string.
        """
        rotated_refresh_token, token_digest = mint_opaque_token(
            token_bytes=self.token_bytes,
            token_hash_secret=self._token_hash_secret,
        )
        rotated_model = self.refresh_token_model(
            token=token_digest,
            user_id=user.id,
            session_id=persisted_token.session_id,
            created_at=persisted_token.created_at,
            last_used_at=datetime.now(tz=UTC),
            client_metadata=client_metadata if client_metadata is not None else persisted_token.client_metadata,
        )
        await self._repository(self._refresh_token_repository_type).add(
            rotated_model,
            auto_commit=False,
            auto_refresh=True,
        )
        return rotated_refresh_token

    @override
    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> tuple[UP, str] | None:
        """Rotate a refresh token and return the related user plus replacement.

        Returns:
            Tuple of the resolved user and rotated refresh token, or ``None`` when invalid.
        """
        del user_manager
        client_metadata = self._consume_refresh_token_request_metadata()
        persisted_token = await self._load_refresh_token_for_rotation(refresh_token)
        if persisted_token is None:
            return None
        if self._is_token_expired(persisted_token.created_at, self.refresh_max_age):
            await self._delete_refresh_token_row(persisted_token)
            return None

        user = cast("UP", persisted_token.user)
        await self._delete_refresh_token_row(persisted_token)
        rotated_refresh_token = await self._mint_replacement_refresh_token(
            user,
            persisted_token,
            client_metadata=client_metadata,
        )
        return user, rotated_refresh_token

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all persisted access and refresh tokens for the given user."""
        await self._repository(self._access_token_repository_type).delete_where(user_id=user.id, auto_commit=False)
        await self._repository(self._refresh_token_repository_type).delete_where(user_id=user.id, auto_commit=False)
        await self.session.commit()
