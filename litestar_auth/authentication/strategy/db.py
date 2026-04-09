"""Database-backed authentication strategy."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any, cast, override

from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session

from litestar_auth.authentication.strategy._opaque_tokens import digest_opaque_token
from litestar_auth.authentication.strategy.base import RefreshableStrategy, Strategy, UserManagerProtocol
from litestar_auth.authentication.strategy.db_models import AccessToken, DatabaseTokenModels, RefreshToken
from litestar_auth.config import validate_secret_length
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]

DEFAULT_MAX_AGE = timedelta(hours=1)
DEFAULT_REFRESH_MAX_AGE = timedelta(days=30)
DEFAULT_TOKEN_BYTES = 32

logger = logging.getLogger(__name__)


def build_legacy_plaintext_tokens_warning_message() -> str:
    """Return the runtime warning text for migration-only plaintext-token compatibility."""
    return (
        "DatabaseTokenStrategy is configured to accept legacy plaintext tokens. "
        "This migration-only mode increases the impact of database compromise and should be disabled "
        "after you rotate sessions and purge legacy rows."
    )


def build_legacy_plaintext_tokens_validation_message(*, rollout_setting: str) -> str:
    """Return the production validation error for migration-only plaintext-token compatibility."""
    return (
        "DatabaseTokenStrategy accept_legacy_plaintext_tokens=True is migration-only and disabled by "
        "default in production. To explicitly accept temporary plaintext-token compatibility during a "
        f"controlled rollout, set {rollout_setting} and remove it after rotating sessions and purging legacy rows."
    )


@cache
def _build_token_repository(token_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository type bound to the provided token model.

    Returns:
        Cached Advanced Alchemy async repository subclass for ``token_model``.
    """
    return type(
        f"{token_model.__name__}Repository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": token_model, "id_attribute": "token"},
    )


AccessTokenRepository = _build_token_repository(AccessToken)
RefreshTokenRepository = _build_token_repository(RefreshToken)


class DatabaseTokenStrategy[UP: UserProtocol[Any], ID](Strategy[UP, ID], RefreshableStrategy[UP, ID]):
    """Stateful strategy that persists opaque tokens in the database."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        session: AsyncSessionT,
        token_hash_secret: str,
        token_models: DatabaseTokenModels | None = None,
        max_age: timedelta = DEFAULT_MAX_AGE,
        refresh_max_age: timedelta = DEFAULT_REFRESH_MAX_AGE,
        token_bytes: int = DEFAULT_TOKEN_BYTES,
        accept_legacy_plaintext_tokens: bool = False,
        unsafe_testing: bool = False,
    ) -> None:
        """Initialize the strategy.

        Args:
            session: SQLAlchemy session used by the repository.
            token_hash_secret: High-entropy secret used for keyed token hashing (HMAC-SHA256).
            token_models: Access-token and refresh-token ORM models used for persistence. Omit to
                keep the bundled ``AccessToken`` / ``RefreshToken`` behavior.
            max_age: Maximum token age before it is rejected.
            refresh_max_age: Maximum refresh-token age before it is rejected.
            token_bytes: Number of random bytes used for token generation.
            accept_legacy_plaintext_tokens: When enabled, accept previously persisted raw tokens
                stored before digest-at-rest hardening. This is intended for migrations only.
            unsafe_testing: Explicit per-instance escape hatch for tests that need to
                suppress production-only warnings around temporary insecure
                compatibility modes.

        Raises:
            ConfigurationError: When ``token_hash_secret`` fails minimum-length requirements.
        """
        try:
            validate_secret_length(token_hash_secret, label="DatabaseTokenStrategy token_hash_secret")
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc

        self.session = session
        self._token_hash_secret = token_hash_secret.encode()
        self.token_models = DatabaseTokenModels() if token_models is None else token_models
        self.access_token_model = self.token_models.access_token_model
        self.refresh_token_model = self.token_models.refresh_token_model
        self._access_token_repository_type = _build_token_repository(self.access_token_model)
        self._refresh_token_repository_type = _build_token_repository(self.refresh_token_model)
        self.max_age = max_age
        self.refresh_max_age = refresh_max_age
        self.token_bytes = token_bytes
        self.accept_legacy_plaintext_tokens = accept_legacy_plaintext_tokens
        self.unsafe_testing = unsafe_testing
        if accept_legacy_plaintext_tokens and not unsafe_testing:
            logger.warning(
                build_legacy_plaintext_tokens_warning_message(),
                extra={"event": "db_tokens_accept_legacy_plaintext"},
            )

    def with_session(self, session: AsyncSessionT) -> DatabaseTokenStrategy[UP, ID]:
        """Return a copy of the strategy bound to the provided async session."""
        return type(self)(
            session=session,
            token_hash_secret=self._token_hash_secret.decode(),
            token_models=self.token_models,
            max_age=self.max_age,
            refresh_max_age=self.refresh_max_age,
            token_bytes=self.token_bytes,
            accept_legacy_plaintext_tokens=self.accept_legacy_plaintext_tokens,
            unsafe_testing=self.unsafe_testing,
        )

    def _repository(self) -> SQLAlchemyAsyncRepository[Any]:
        """Create a repository bound to the current session.

        Returns:
            Repository instance for access-token persistence.
        """
        return self._access_token_repository_type(session=self.session)

    def _refresh_repository(self) -> SQLAlchemyAsyncRepository[Any]:
        """Create a repository bound to the current session for refresh tokens.

        Returns:
            Repository instance for refresh-token persistence.
        """
        return self._refresh_token_repository_type(session=self.session)

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

    async def _resolve_token(
        self,
        repository: SQLAlchemyAsyncRepository[Any],
        raw_token: str,
        *,
        load: list[Any],
    ) -> object | None:
        """Look up a token row by digest, optionally falling back to legacy plaintext.

        When legacy mode is active, both queries execute unconditionally to
        prevent timing side-channels that reveal token storage format.

        Returns:
            Persisted token row when found, otherwise ``None``.
        """
        token_digest = self._token_digest(raw_token)
        entity = await repository.get_one_or_none(token=token_digest, load=load)
        legacy_entity: object | None = None
        if self.accept_legacy_plaintext_tokens:
            legacy_entity = await repository.get_one_or_none(token=raw_token, load=load)
        return entity if entity is not None else legacy_entity

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
        del user_manager
        if token is None:
            return None

        access_token = cast(
            "Any",
            await self._resolve_token(
                self._repository(),
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
        token = secrets.token_urlsafe(self.token_bytes)
        access_token = self.access_token_model(token=self._token_digest(token), user_id=user.id)
        await self._repository().add(access_token, auto_refresh=True)
        return token

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Delete a persisted token."""
        del user
        token_digest = self._token_digest(token)
        await self._repository().delete_where(token=token_digest, auto_commit=False)
        if self.accept_legacy_plaintext_tokens:
            await self._repository().delete_where(token=token, auto_commit=False)
        await self.session.commit()

    @override
    async def write_refresh_token(self, user: UP) -> str:
        """Persist and return a new opaque refresh token for the user.

        Returns:
            Newly created opaque refresh-token string.
        """
        token = secrets.token_urlsafe(self.token_bytes)
        refresh_token = self.refresh_token_model(token=self._token_digest(token), user_id=user.id)
        await self._refresh_repository().add(refresh_token, auto_refresh=True)
        return token

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
        persisted_token = cast(
            "Any",
            await self._resolve_token(
                self._refresh_repository(),
                refresh_token,
                load=[self.refresh_token_model.user],
            ),
        )
        if persisted_token is None:
            return None
        if self._is_token_expired(persisted_token.created_at, self.refresh_max_age):
            await self._refresh_repository().delete_where(token=persisted_token.token, auto_commit=False)
            return None

        user = cast("UP", persisted_token.user)
        await self._refresh_repository().delete_where(token=persisted_token.token, auto_commit=False)
        rotated_refresh_token = secrets.token_urlsafe(self.token_bytes)
        rotated_model = self.refresh_token_model(token=self._token_digest(rotated_refresh_token), user_id=user.id)
        await self._refresh_repository().add(rotated_model, auto_commit=False, auto_refresh=True)
        return user, rotated_refresh_token

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all persisted access and refresh tokens for the given user."""
        await self._repository().delete_where(user_id=user.id, auto_commit=False)
        await self._refresh_repository().delete_where(user_id=user.id, auto_commit=False)
        await self.session.commit()
