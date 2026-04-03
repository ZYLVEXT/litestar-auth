"""Integration tests for the database token strategy."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import TYPE_CHECKING, Any

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy import select
from sqlalchemy.orm import DeclarativeBase

import litestar_auth.authentication.strategy.db as db_strategy_module
from litestar_auth.authentication.strategy import DatabaseTokenModels
from litestar_auth.authentication.strategy._opaque_tokens import digest_opaque_token
from litestar_auth.authentication.strategy.base import RefreshableStrategy, Strategy
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.models import (
    AccessTokenMixin,
    RefreshTokenMixin,
    User,
    UserAuthRelationshipMixin,
    UserModelMixin,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Session
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.schema import MetaData
    from sqlalchemy.sql.base import Executable

pytestmark = pytest.mark.integration
EXPECTED_CLEANUP_DELETIONS = 2
_TOKEN_HASH_SECRET = "test-token-hash-secret-1234567890-1234567890"


class CustomTokenBase(DeclarativeBase):
    """App-owned registry for custom DB-token strategy models."""

    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class CustomTokenUUIDBase(UUIDPrimaryKey, CustomTokenBase):
    """UUID primary-key base bound to the custom DB-token registry."""

    __abstract__ = True


class CustomTokenUser(UserModelMixin, UserAuthRelationshipMixin, CustomTokenUUIDBase):
    """Custom user model wired to custom access-token and refresh-token tables."""

    __tablename__ = "custom_token_user"

    auth_access_token_model = "CustomAccessToken"
    auth_refresh_token_model = "CustomRefreshToken"
    auth_oauth_account_model = None


class CustomAccessToken(AccessTokenMixin, CustomTokenBase):
    """Custom access-token model for DB-token strategy integration coverage."""

    __tablename__ = "custom_access_token"

    auth_user_model = "CustomTokenUser"
    auth_user_table = "custom_token_user"


class CustomRefreshToken(RefreshTokenMixin, CustomTokenBase):
    """Custom refresh-token model for DB-token strategy integration coverage."""

    __tablename__ = "custom_refresh_token"

    auth_user_model = "CustomTokenUser"
    auth_user_table = "custom_token_user"


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Create the bundled and custom DB-token metadata for this module's session fixture.

    Returns:
        Metadata collections created for this module's SQLite session fixture.
    """
    return User.metadata, CustomTokenUser.metadata


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for repository tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped session."""
        self._session = session
        self.info: dict[str, Any] = {}

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return self._session.bind

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            Bound SQLAlchemy connectable.
        """
        return self._session.get_bind()

    @property
    def no_autoflush(self) -> object:
        """Expose the wrapped session no-autoflush context manager."""
        return self._session.no_autoflush

    def add(self, instance: object) -> None:
        """Add an instance to the session."""
        self._session.add(instance)

    def add_all(self, instances: Sequence[object]) -> None:
        """Add multiple instances to the session."""
        self._session.add_all(instances)

    def expunge(self, instance: object) -> None:
        """Expunge an instance from the session."""
        self._session.expunge(instance)

    async def commit(self) -> None:
        """Commit the current transaction."""
        self._session.commit()

    async def delete(self, instance: object) -> None:
        """Delete an instance from the session."""
        self._session.delete(instance)

    async def execute(
        self,
        statement: Executable,
        params: Mapping[str, object] | Sequence[Mapping[str, object]] | None = None,
        *,
        execution_options: Mapping[str, object] | None = None,
    ) -> object:
        """Execute a SQL statement.

        Returns:
            SQLAlchemy execution result.
        """
        if execution_options is None:
            return self._session.execute(statement, params=params)
        return self._session.execute(statement, params=params, execution_options=execution_options)

    async def flush(self) -> None:
        """Flush pending changes."""
        self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge an instance into the session.

        Returns:
            The merged mapped instance.
        """
        return self._session.merge(instance, load=load)

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: Iterable[str] | None = None,
        with_for_update: ForUpdateParameter = None,
    ) -> None:
        """Refresh an instance from the database."""
        self._session.refresh(instance, attribute_names=attribute_names, with_for_update=with_for_update)


class UnusedUserManager:
    """Placeholder user manager for the shared strategy interface."""

    @staticmethod
    async def get(user_id: object) -> User | None:
        """Return ``None`` because the DB strategy resolves users directly.

        Returns:
            Always ``None``.
        """
        del user_id
        return None


class UnusedCustomUserManager:
    """Placeholder user manager for custom-user strategy tests."""

    @staticmethod
    async def get(user_id: object) -> CustomTokenUser | None:
        """Return ``None`` because the DB strategy resolves custom users directly.

        Returns:
            Always ``None``.
        """
        del user_id
        return None


def _create_user(session: Session, *, email: str) -> User:
    """Persist a user for token strategy tests.

    Returns:
        Stored user instance.
    """
    user = User(email=email, hashed_password="hashed-password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _create_custom_token_user(session: Session, *, email: str) -> CustomTokenUser:
    """Persist a custom user for token-strategy tests that swap token ORM models.

    Returns:
        Stored custom user instance.
    """
    user = CustomTokenUser(email=email, hashed_password="hashed-password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _strategy_session(session: Session) -> AsyncSession:
    """Return an async-compatible adapter for the sync test session."""
    return AsyncSessionAdapter(session)  # ty: ignore[invalid-return-type]


def test_database_token_strategy_module_reload_executes_definition_paths(session: Session) -> None:
    """Reloading the module exercises definition-time paths for coverage."""
    reloaded_module = importlib.reload(db_strategy_module)
    strategy = reloaded_module.DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert reloaded_module.AccessTokenRepository.model_type is AccessToken
    assert reloaded_module.RefreshTokenRepository.model_type is RefreshToken
    assert isinstance(strategy, reloaded_module.DatabaseTokenStrategy)


async def test_database_token_strategy_writes_and_reads_tokens(session: Session) -> None:
    """DatabaseTokenStrategy persists a token row and resolves its user."""
    user = _create_user(session, email="db-strategy@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=5),
    )

    assert isinstance(strategy, Strategy)

    token = await strategy.write_token(user)
    persisted_token = session.scalar(select(AccessToken).where(AccessToken.user_id == user.id))
    resolved_user = await strategy.read_token(token, UnusedUserManager())

    assert persisted_token is not None
    assert persisted_token.user_id == user.id
    assert persisted_token.token != token
    assert resolved_user is not None
    assert resolved_user.id == user.id


async def test_database_token_strategy_initializes_defaults_and_rebinds_session(session: Session) -> None:
    """The strategy defaults to hashed tokens and can be rebound to another session adapter."""
    user = _create_user(session, email="rebind@example.com")
    original_session = _strategy_session(session)
    strategy = DatabaseTokenStrategy(
        session=original_session,
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=7),
        refresh_max_age=timedelta(days=14),
        token_bytes=24,
    )

    assert isinstance(strategy, Strategy)
    assert isinstance(strategy, RefreshableStrategy)
    assert strategy.accept_legacy_plaintext_tokens is False

    token = await strategy.write_token(user)
    rebound_session = _strategy_session(session)
    rebound_strategy = strategy.with_session(rebound_session)
    resolved_user = await rebound_strategy.read_token(token, UnusedUserManager())

    assert rebound_strategy is not strategy
    assert rebound_strategy.session is rebound_session
    assert rebound_strategy.max_age == strategy.max_age
    assert rebound_strategy.refresh_max_age == strategy.refresh_max_age
    assert rebound_strategy.token_bytes == strategy.token_bytes
    assert rebound_strategy.accept_legacy_plaintext_tokens is False
    assert rebound_strategy.token_models == strategy.token_models
    assert resolved_user is not None
    assert resolved_user.id == user.id


async def test_database_token_strategy_supports_custom_token_model_contract(session: Session) -> None:
    """Custom mixin-composed token models can back the DB token strategy without bundled token tables."""
    user = _create_custom_token_user(session, email="custom-token-contract@example.com")
    token_models = DatabaseTokenModels(
        access_token_model=CustomAccessToken,
        refresh_token_model=CustomRefreshToken,
    )
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        token_models=token_models,
    )

    access_token = await strategy.write_token(user)
    refresh_token = await strategy.write_refresh_token(user)
    resolved_user = await strategy.read_token(access_token, UnusedCustomUserManager())
    rotation = await strategy.rotate_refresh_token(refresh_token, UnusedCustomUserManager())
    await strategy.destroy_token(access_token, user)

    persisted_access_tokens = session.scalars(
        select(CustomAccessToken).where(CustomAccessToken.user_id == user.id),
    ).all()
    persisted_refresh_tokens = session.scalars(
        select(CustomRefreshToken).where(CustomRefreshToken.user_id == user.id),
    ).all()

    assert session.scalar(select(AccessToken).where(AccessToken.user_id == user.id)) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None
    assert resolved_user is not None
    assert resolved_user.id == user.id
    assert rotation is not None
    rotated_user, rotated_refresh_token = rotation
    assert rotated_user.id == user.id
    assert rotated_refresh_token != refresh_token
    assert persisted_access_tokens == []
    assert len(persisted_refresh_tokens) == 1
    assert persisted_refresh_tokens[0].token not in {refresh_token, rotated_refresh_token}


async def test_database_token_strategy_cleanup_expired_tokens_supports_custom_token_models(session: Session) -> None:
    """Expired-token cleanup targets custom token tables when the strategy contract is overridden."""
    user = _create_custom_token_user(session, email="custom-token-cleanup@example.com")
    now = datetime.now(tz=UTC)
    session.add_all(
        [
            CustomAccessToken(
                token="expired-custom-access-token",
                user_id=user.id,
                created_at=now - timedelta(minutes=10),
            ),
            CustomAccessToken(
                token="fresh-custom-access-token",
                user_id=user.id,
                created_at=now - timedelta(minutes=2),
            ),
            CustomRefreshToken(
                token="expired-custom-refresh-token",
                user_id=user.id,
                created_at=now - timedelta(days=40),
            ),
            CustomRefreshToken(
                token="fresh-custom-refresh-token",
                user_id=user.id,
                created_at=now - timedelta(days=5),
            ),
        ],
    )
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        token_models=DatabaseTokenModels(
            access_token_model=CustomAccessToken,
            refresh_token_model=CustomRefreshToken,
        ),
        max_age=timedelta(minutes=5),
        refresh_max_age=timedelta(days=30),
    )

    deleted_count = await strategy.cleanup_expired_tokens(_strategy_session(session))

    assert deleted_count == EXPECTED_CLEANUP_DELETIONS
    assert (
        session.scalar(select(CustomAccessToken).where(CustomAccessToken.token == "expired-custom-access-token"))
        is None
    )
    assert (
        session.scalar(select(CustomRefreshToken).where(CustomRefreshToken.token == "expired-custom-refresh-token"))
        is None
    )
    assert (
        session.scalar(select(CustomAccessToken).where(CustomAccessToken.token == "fresh-custom-access-token"))
        is not None
    )
    assert (
        session.scalar(select(CustomRefreshToken).where(CustomRefreshToken.token == "fresh-custom-refresh-token"))
        is not None
    )


async def test_database_token_strategy_accepts_legacy_plaintext_mode_when_enabled(session: Session) -> None:
    """Legacy plaintext migration mode remains opt-in and preserves compatibility."""
    user = _create_user(session, email="legacy-init@example.com")
    legacy_token = "legacy-init-token"
    session.add(AccessToken(token=legacy_token, user_id=user.id))
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        accept_legacy_plaintext_tokens=True,
    )

    resolved_user = await strategy.read_token(legacy_token, UnusedUserManager())

    assert strategy.accept_legacy_plaintext_tokens is True
    assert resolved_user is not None
    assert resolved_user.id == user.id


async def test_database_token_strategy_rejects_legacy_plaintext_access_tokens_by_default(session: Session) -> None:
    """Digest-only mode does not authenticate legacy plaintext access-token rows."""
    user = _create_user(session, email="legacy-default-access@example.com")
    legacy_token = "legacy-default-access-token"
    session.add(AccessToken(token=legacy_token, user_id=user.id))
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert await strategy.read_token(legacy_token, UnusedUserManager()) is None


async def test_database_token_strategy_rejects_legacy_plaintext_refresh_tokens_by_default(session: Session) -> None:
    """Digest-only mode does not rotate legacy plaintext refresh-token rows."""
    user = _create_user(session, email="legacy-default-refresh@example.com")
    legacy_refresh_token = "legacy-default-refresh-token"
    session.add(RefreshToken(token=legacy_refresh_token, user_id=user.id))
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert await strategy.rotate_refresh_token(legacy_refresh_token, UnusedUserManager()) is None


async def test_database_token_strategy_destroy_token_removes_row(session: Session) -> None:
    """Destroying a token removes it from the database."""
    user = _create_user(session, email="destroy-token@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    token = await strategy.write_token(user)
    await strategy.destroy_token(token, user)

    assert session.scalar(select(AccessToken).where(AccessToken.user_id == user.id)) is None


async def test_database_token_strategy_rejects_missing_and_expired_tokens(session: Session) -> None:
    """Missing and expired tokens do not authenticate a user."""
    user = _create_user(session, email="expired-token@example.com")
    token_hash_secret = _TOKEN_HASH_SECRET
    expired_token = AccessToken(
        token=digest_opaque_token(token_hash_secret=token_hash_secret.encode(), token="expired-token"),
        user_id=user.id,
        created_at=datetime.now(tz=UTC) - timedelta(minutes=6),
    )
    fresh_token = AccessToken(
        token=digest_opaque_token(token_hash_secret=token_hash_secret.encode(), token="fresh-token"),
        user_id=user.id,
        created_at=datetime.now(tz=UTC) - timedelta(minutes=6),
    )
    session.add_all([expired_token, fresh_token])
    session.commit()

    strategy_session = _strategy_session(session)
    strict_strategy = DatabaseTokenStrategy(
        session=strategy_session,
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=5),
    )
    relaxed_strategy = DatabaseTokenStrategy(
        session=strategy_session,
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=10),
    )

    assert await strict_strategy.read_token(None, UnusedUserManager()) is None
    assert await strict_strategy.read_token("missing-token", UnusedUserManager()) is None
    assert await strict_strategy.read_token("expired-token", UnusedUserManager()) is None

    resolved_user = await relaxed_strategy.read_token("fresh-token", UnusedUserManager())

    assert resolved_user is not None
    assert resolved_user.id == user.id


async def test_database_token_strategy_normalizes_timestamps_and_rejects_boundary_tokens(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Timestamp normalization accepts offset-aware rows and rejects exact-expiry tokens."""
    frozen_now = datetime(2026, 3, 28, 15, 0, tzinfo=UTC)

    class FrozenDateTime:
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            if tz is None:
                return frozen_now.replace(tzinfo=None)
            return frozen_now.astimezone(tz)

    monkeypatch.setattr(db_strategy_module, "datetime", FrozenDateTime)

    user = _create_user(session, email="timestamp-edge@example.com")
    expired_boundary_token = "expires-now-token"
    offset_aware_token = "offset-aware-token"
    session.add_all(
        [
            AccessToken(
                token=digest_opaque_token(
                    token_hash_secret=_TOKEN_HASH_SECRET.encode(),
                    token=expired_boundary_token,
                ),
                user_id=user.id,
                created_at=frozen_now - timedelta(minutes=5),
            ),
            AccessToken(
                token=digest_opaque_token(
                    token_hash_secret=_TOKEN_HASH_SECRET.encode(),
                    token=offset_aware_token,
                ),
                user_id=user.id,
                created_at=(frozen_now - timedelta(minutes=4)).astimezone(timezone(timedelta(hours=2))),
            ),
        ],
    )
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=5),
    )

    assert await strategy.read_token(expired_boundary_token, UnusedUserManager()) is None

    resolved_user = await strategy.read_token(offset_aware_token, UnusedUserManager())

    assert resolved_user is not None
    assert resolved_user.id == user.id


def test_database_token_strategy_normalize_timestamp_converts_offset_datetimes(session: Session) -> None:
    """Offset-aware timestamps should be normalized to UTC before age checks."""
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    offset_timestamp = datetime(2026, 3, 28, 17, 0, tzinfo=timezone(timedelta(hours=2)))

    normalized = strategy._normalize_timestamp(offset_timestamp)

    assert normalized == datetime(2026, 3, 28, 15, 0, tzinfo=UTC)


async def test_database_token_strategy_cleanup_expired_tokens(session: Session) -> None:
    """Cleanup removes only expired access and refresh tokens and returns the count."""
    user = _create_user(session, email="cleanup@example.com")
    now = datetime.now(tz=UTC)
    session.add_all(
        [
            AccessToken(
                token="expired-access-token",
                user_id=user.id,
                created_at=now - timedelta(minutes=10),
            ),
            AccessToken(
                token="fresh-access-token",
                user_id=user.id,
                created_at=now - timedelta(minutes=2),
            ),
            RefreshToken(
                token="expired-refresh-token",
                user_id=user.id,
                created_at=now - timedelta(days=40),
            ),
            RefreshToken(
                token="fresh-refresh-token",
                user_id=user.id,
                created_at=now - timedelta(days=5),
            ),
        ],
    )
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        max_age=timedelta(minutes=5),
        refresh_max_age=timedelta(days=30),
    )

    deleted_count = await strategy.cleanup_expired_tokens(_strategy_session(session))

    assert deleted_count == EXPECTED_CLEANUP_DELETIONS
    assert session.scalar(select(AccessToken).where(AccessToken.token == "expired-access-token")) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.token == "expired-refresh-token")) is None
    assert session.scalar(select(AccessToken).where(AccessToken.token == "fresh-access-token")) is not None
    assert session.scalar(select(RefreshToken).where(RefreshToken.token == "fresh-refresh-token")) is not None


async def test_database_token_strategy_supports_legacy_plaintext_access_tokens(session: Session) -> None:
    """Legacy plaintext access tokens can still be read and destroyed during migration."""
    user = _create_user(session, email="legacy-access@example.com")
    legacy_token = "legacy-plaintext-access-token"
    session.add(AccessToken(token=legacy_token, user_id=user.id))
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        accept_legacy_plaintext_tokens=True,
    )

    resolved_user = await strategy.read_token(legacy_token, UnusedUserManager())
    await strategy.destroy_token(legacy_token, user)

    assert resolved_user is not None
    assert resolved_user.id == user.id
    assert session.scalar(select(AccessToken).where(AccessToken.token == legacy_token)) is None


async def test_database_token_strategy_rotates_legacy_plaintext_refresh_tokens(session: Session) -> None:
    """Refresh-token rotation falls back to legacy plaintext rows when enabled."""
    user = _create_user(session, email="legacy-refresh@example.com")
    legacy_refresh_token = "legacy-plaintext-refresh-token"
    session.add(RefreshToken(token=legacy_refresh_token, user_id=user.id))
    session.commit()

    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        accept_legacy_plaintext_tokens=True,
    )

    rotation = await strategy.rotate_refresh_token(legacy_refresh_token, UnusedUserManager())
    persisted_tokens = session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()

    assert rotation is not None
    rotated_user, rotated_refresh_token = rotation
    assert rotated_user.id == user.id
    assert rotated_refresh_token != legacy_refresh_token
    assert len(persisted_tokens) == 1
    assert persisted_tokens[0].token != legacy_refresh_token


async def test_database_token_strategy_writes_and_rotates_refresh_tokens(session: Session) -> None:
    """Refresh tokens are persisted hashed and rotated to a replacement token."""
    user = _create_user(session, email="rotate-refresh@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    refresh_token = await strategy.write_refresh_token(user)
    rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())
    persisted_tokens = session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()

    assert rotation is not None
    rotated_user, rotated_refresh_token = rotation
    assert rotated_user.id == user.id
    assert rotated_refresh_token != refresh_token
    assert len(persisted_tokens) == 1
    assert persisted_tokens[0].token not in {refresh_token, rotated_refresh_token}


async def test_database_token_strategy_rotate_refresh_token_returns_none_when_missing(session: Session) -> None:
    """Missing refresh tokens should not rotate."""
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert await strategy.rotate_refresh_token("missing-refresh-token", UnusedUserManager()) is None


async def test_database_token_strategy_rotate_refresh_token_deletes_expired_rows(session: Session) -> None:
    """Expired refresh tokens are deleted and rejected during rotation."""
    user = _create_user(session, email="expired-refresh@example.com")
    refresh_token = "expired-refresh-token"
    session.add(
        RefreshToken(
            token=digest_opaque_token(token_hash_secret=_TOKEN_HASH_SECRET.encode(), token=refresh_token),
            user_id=user.id,
            created_at=datetime.now(tz=UTC) - timedelta(days=31),
        ),
    )
    session.commit()
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        refresh_max_age=timedelta(days=30),
    )

    assert await strategy.rotate_refresh_token(refresh_token, UnusedUserManager()) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None


async def test_database_token_strategy_invalidate_all_tokens_removes_user_rows(session: Session) -> None:
    """invalidate_all_tokens() should remove both access and refresh rows for the user."""
    user = _create_user(session, email="invalidate-all@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    await strategy.write_token(user)
    await strategy.write_refresh_token(user)

    await strategy.invalidate_all_tokens(user)

    assert session.scalar(select(AccessToken).where(AccessToken.user_id == user.id)) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None


def test_database_token_strategy_rejects_short_hash_secret(session: Session) -> None:
    """Short token hash secrets should fail fast during strategy initialization."""
    with pytest.raises(ConfigurationError, match="token_hash_secret"):
        DatabaseTokenStrategy(
            session=_strategy_session(session),
            token_hash_secret="short",
        )
