"""Integration tests for the database token strategy."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

import litestar_auth.authentication.strategy.db as db_strategy_module
from litestar_auth.authentication.strategy import DatabaseTokenModels
from litestar_auth.authentication.strategy._opaque_tokens import digest_opaque_token
from litestar_auth.authentication.strategy.base import RefreshableStrategy, RefreshSessionManagementStrategy, Strategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.models import (
    AccessTokenMixin,
    RefreshTokenMixin,
    User,
    UserAuthRelationshipMixin,
    UserModelMixin,
)
from tests.integration.conftest import enable_aiosqlite_foreign_keys

DatabaseTokenStrategy = db_strategy_module.DatabaseTokenStrategy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
    from pathlib import Path

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
    from sqlalchemy.orm import Session
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.schema import MetaData
    from sqlalchemy.sql.base import Executable

    from litestar_auth.authentication.strategy._db_rotation import _RefreshTokenRow

pytestmark = pytest.mark.integration
EXPECTED_CLEANUP_DELETIONS = 2
EXPECTED_REVOKED_SESSIONS_WITHOUT_CURRENT = 2
_TOKEN_HASH_SECRET = "test-token-hash-secret-1234567890-1234567890"
CONCURRENT_REFRESH_ROTATION_COUNT = 2


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


class PasswordColumnTokenBase(DeclarativeBase):
    """App-owned registry for a custom password-column DB-token strategy contract."""

    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class PasswordColumnTokenUUIDBase(UUIDPrimaryKey, PasswordColumnTokenBase):
    """UUID primary-key base bound to the custom password-column token registry."""

    __abstract__ = True


class PasswordHashColumnUser(UserModelMixin, UserAuthRelationshipMixin, PasswordColumnTokenUUIDBase):
    """Custom user model that keeps ``hashed_password`` on a ``password_hash`` column."""

    __tablename__ = "custom_password_hash_user"

    auth_access_token_model = "PasswordHashColumnAccessToken"
    auth_refresh_token_model = "PasswordHashColumnRefreshToken"
    auth_oauth_account_model = None
    auth_hashed_password_column_name = "password_hash"


class PasswordHashColumnAccessToken(AccessTokenMixin, PasswordColumnTokenBase):
    """Custom access-token model for the custom password-column user contract."""

    __tablename__ = "custom_password_hash_access_token"

    auth_user_model = "PasswordHashColumnUser"
    auth_user_table = "custom_password_hash_user"


class PasswordHashColumnRefreshToken(RefreshTokenMixin, PasswordColumnTokenBase):
    """Custom refresh-token model for the custom password-column user contract."""

    __tablename__ = "custom_password_hash_refresh_token"

    auth_user_model = "PasswordHashColumnUser"
    auth_user_table = "custom_password_hash_user"


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Create the bundled and custom DB-token metadata for this module's session fixture.

    Returns:
        Metadata collections created for this module's SQLite session fixture.
    """
    return User.metadata, CustomTokenUser.metadata, PasswordHashColumnUser.metadata


@pytest.fixture
async def async_sqlite_session_maker(
    tmp_path: Path,
    sqlalchemy_metadata: tuple[MetaData, ...],
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Create an aiosqlite-backed async session maker for DB-token concurrency tests.

    Yields:
        Async session maker bound to an isolated SQLite database.
    """
    database_path = tmp_path / "database-token-concurrency.sqlite"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        for metadata in sqlalchemy_metadata:
            await connection.run_sync(metadata.create_all)

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


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
    async def get(user_id: object) -> User | None:  # noqa: ARG004
        """Return ``None`` because the DB strategy resolves users directly.

        Returns:
            Always ``None``.
        """
        return None


class UnusedCustomUserManager:
    """Placeholder user manager for custom-user strategy tests."""

    @staticmethod
    async def get(user_id: object) -> CustomTokenUser | None:  # noqa: ARG004
        """Return ``None`` because the DB strategy resolves custom users directly.

        Returns:
            Always ``None``.
        """
        return None


class UnusedPasswordHashColumnUserManager:
    """Placeholder user manager for custom password-column strategy tests."""

    @staticmethod
    async def get(user_id: object) -> PasswordHashColumnUser | None:  # noqa: ARG004
        """Return ``None`` because the DB strategy resolves custom users directly.

        Returns:
            Always ``None``.
        """
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


def _create_password_hash_column_user(session: Session, *, email: str) -> PasswordHashColumnUser:
    """Persist a custom user that maps ``hashed_password`` to a ``password_hash`` column.

    Returns:
        Stored custom user instance.
    """
    user = PasswordHashColumnUser(email=email, hashed_password="hashed-password")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _strategy_session(session: Session) -> AsyncSession:
    """Return an async-compatible adapter for the sync test session."""
    return AsyncSessionAdapter(session)  # ty: ignore[invalid-return-type]


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

    token = await strategy.write_token(user)
    rebound_session = _strategy_session(session)
    rebound_strategy = strategy.with_session(rebound_session)
    resolved_user = await rebound_strategy.read_token(token, UnusedUserManager())

    assert rebound_strategy is not strategy
    assert rebound_strategy.session is rebound_session
    assert rebound_strategy.max_age == strategy.max_age
    assert rebound_strategy.refresh_max_age == strategy.refresh_max_age
    assert rebound_strategy.token_bytes == strategy.token_bytes
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


async def test_database_token_strategy_supports_password_column_name_hook(session: Session) -> None:
    """Custom users can keep the ``hashed_password`` attribute via the supported password-column hook."""
    user = _create_password_hash_column_user(session, email="custom-password-hash@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        token_models=DatabaseTokenModels(
            access_token_model=PasswordHashColumnAccessToken,
            refresh_token_model=PasswordHashColumnRefreshToken,
        ),
    )

    access_token = await strategy.write_token(user)
    refresh_token = await strategy.write_refresh_token(user)
    resolved_user = await strategy.read_token(access_token, UnusedPasswordHashColumnUserManager())
    rotation = await strategy.rotate_refresh_token(refresh_token, UnusedPasswordHashColumnUserManager())
    stored_hash = session.execute(select(PasswordHashColumnUser.__table__.c.password_hash)).scalar_one()

    assert PasswordHashColumnUser.__mapper__.attrs["hashed_password"].columns[0].name == "password_hash"
    assert stored_hash == "hashed-password"
    assert (
        session.scalar(
            select(PasswordHashColumnAccessToken).where(PasswordHashColumnAccessToken.user_id == user.id),
        )
        is not None
    )
    assert resolved_user is not None
    assert resolved_user.id == user.id
    assert rotation is not None
    rotated_user, rotated_refresh_token = rotation
    assert rotated_user.id == user.id
    assert rotated_refresh_token != refresh_token


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


def test_database_token_strategy_ignores_empty_or_invalid_refresh_client_metadata(session: Session) -> None:
    """Invalid or empty request metadata is ignored instead of being persisted."""
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert strategy._bounded_client_metadata_value(object()) is None
    assert strategy._bounded_client_metadata_value(" \n\t ") is None
    assert strategy._extract_refresh_token_client_metadata(object()) is None


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


async def test_database_token_strategy_writes_and_rotates_refresh_tokens(session: Session) -> None:
    """Refresh tokens are persisted hashed and rotated to a replacement token."""
    user = _create_user(session, email="rotate-refresh@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    refresh_token = await strategy.write_refresh_token(user)
    initial_persisted_token = session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert initial_persisted_token is not None
    initial_session_id = initial_persisted_token.session_id
    initial_created_at = initial_persisted_token.created_at

    rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())
    persisted_tokens = session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()

    assert rotation is not None
    rotated_user, rotated_refresh_token = rotation
    assert rotated_user.id == user.id
    assert rotated_refresh_token != refresh_token
    assert len(persisted_tokens) == 1
    assert persisted_tokens[0].token not in {refresh_token, rotated_refresh_token}
    assert persisted_tokens[0].session_id == initial_session_id
    assert UUID(persisted_tokens[0].session_id)
    assert persisted_tokens[0].created_at == initial_created_at
    assert persisted_tokens[0].last_used_at is not None
    assert persisted_tokens[0].client_metadata is None


async def test_database_token_strategy_lists_only_active_refresh_sessions_for_user(session: Session) -> None:
    """Refresh-session listing returns only active rows belonging to the requested user."""
    user = _create_user(session, email="list-sessions@example.com")
    foreign_user = _create_user(session, email="foreign-list-sessions@example.com")
    now = datetime.now(tz=UTC)
    session.add_all(
        [
            RefreshToken(
                token="active-session-token",
                user_id=user.id,
                created_at=now - timedelta(days=2),
                last_used_at=now - timedelta(hours=1),
                client_metadata={"user_agent": "Session List Test/1.0"},
            ),
            RefreshToken(
                token="expired-session-token",
                user_id=user.id,
                created_at=now - timedelta(days=40),
            ),
            RefreshToken(
                token="foreign-session-token",
                user_id=foreign_user.id,
                created_at=now - timedelta(days=1),
            ),
        ],
    )
    session.commit()
    active_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "active-session-token"),
    )
    active_last_used_at = session.scalar(
        select(RefreshToken.last_used_at).where(RefreshToken.token == "active-session-token"),
    )
    foreign_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "foreign-session-token"),
    )
    assert active_session_id is not None
    assert foreign_session_id is not None
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        refresh_max_age=timedelta(days=30),
    )

    sessions = await strategy.list_refresh_sessions(user)

    assert isinstance(strategy, RefreshSessionManagementStrategy)
    assert [refresh_session.session_id for refresh_session in sessions] == [active_session_id]
    assert sessions[0].client_metadata == {"user_agent": "Session List Test/1.0"}
    assert sessions[0].last_used_at == active_last_used_at
    assert session.scalar(select(RefreshToken).where(RefreshToken.token == "expired-session-token")) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == foreign_session_id)) is not None
    assert await strategy.list_refresh_sessions(user) == sessions


async def test_database_token_strategy_persists_totp_stepup_marker_on_refresh_session(session: Session) -> None:
    """TOTP step-up markers live on DB-backed refresh sessions and expire server-side."""
    user = _create_user(session, email="db-stepup@example.com")
    foreign_user = _create_user(session, email="foreign-db-stepup@example.com")
    session.add_all(
        [
            RefreshToken(token="stepup-session-token", user_id=user.id),
            RefreshToken(token="foreign-stepup-session-token", user_id=foreign_user.id),
        ],
    )
    session.commit()
    session_id = session.scalar(select(RefreshToken.session_id).where(RefreshToken.token == "stepup-session-token"))
    foreign_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "foreign-stepup-session-token"),
    )
    assert session_id is not None
    assert foreign_session_id is not None
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    await strategy.issue_totp_stepup(user, "missing-session", ttl_seconds=300)
    await strategy.issue_totp_stepup(user, foreign_session_id, ttl_seconds=300)
    await strategy.issue_totp_stepup(user, session_id, ttl_seconds=300)

    persisted = session.scalar(select(RefreshToken).where(RefreshToken.session_id == session_id))
    assert persisted is not None
    assert await strategy.has_recent_totp_verification(user, session_id) is True
    assert await strategy.has_recent_totp_verification(user, foreign_session_id) is False
    assert (persisted.client_metadata or {}).get("totp_stepup_expires_at") is not None

    await strategy.issue_totp_stepup(user, session_id, ttl_seconds=0)

    assert await strategy.has_recent_totp_verification(user, session_id) is False
    persisted.client_metadata = {"totp_stepup_expires_at": "not-a-float"}
    session.commit()
    assert await strategy.has_recent_totp_verification(user, session_id) is False
    persisted.client_metadata = {"totp_stepup_expires_at": str(datetime.now(tz=UTC).timestamp() - 1)}
    session.commit()
    assert await strategy.has_recent_totp_verification(user, session_id) is False
    assert persisted.client_metadata is None


async def test_database_token_strategy_revoke_refresh_session_is_user_scoped(session: Session) -> None:
    """Revoking one refresh session cannot delete another user's row."""
    user = _create_user(session, email="revoke-session@example.com")
    foreign_user = _create_user(session, email="foreign-revoke-session@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    await strategy.write_refresh_token(user)
    await strategy.write_refresh_token(foreign_user)
    user_session_id = session.scalar(select(RefreshToken.session_id).where(RefreshToken.user_id == user.id))
    foreign_session_id = session.scalar(select(RefreshToken.session_id).where(RefreshToken.user_id == foreign_user.id))
    assert user_session_id is not None
    assert foreign_session_id is not None

    missing_result = await strategy.revoke_refresh_session(user, "missing-session-id")
    foreign_result = await strategy.revoke_refresh_session(user, foreign_session_id)
    revoked_result = await strategy.revoke_refresh_session(user, user_session_id)

    assert missing_result is False
    assert foreign_result is False
    assert revoked_result is True
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == user_session_id)) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == foreign_session_id)) is not None


async def test_database_token_strategy_revoke_refresh_session_ignores_expired_match(session: Session) -> None:
    """Revoking an expired refresh session cleans it up and reports not found."""
    user = _create_user(session, email="expired-revoke-session@example.com")
    session.add(
        RefreshToken(
            token="expired-revoke-session-token",
            user_id=user.id,
            created_at=datetime.now(tz=UTC) - timedelta(days=40),
        ),
    )
    session.commit()
    expired_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "expired-revoke-session-token"),
    )
    assert expired_session_id is not None
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        refresh_max_age=timedelta(days=30),
    )

    revoked = await strategy.revoke_refresh_session(user, expired_session_id)

    assert revoked is False
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == expired_session_id)) is None


async def test_database_token_strategy_revoke_other_refresh_sessions_preserves_current(session: Session) -> None:
    """Revoking other refresh sessions preserves the supplied current session id."""
    user = _create_user(session, email="revoke-other-sessions@example.com")
    foreign_user = _create_user(session, email="foreign-revoke-other-sessions@example.com")
    now = datetime.now(tz=UTC)
    session.add_all(
        [
            RefreshToken(token="current-refresh-session", user_id=user.id, created_at=now - timedelta(days=1)),
            RefreshToken(token="other-refresh-session", user_id=user.id, created_at=now - timedelta(hours=1)),
            RefreshToken(token="expired-other-refresh-session", user_id=user.id, created_at=now - timedelta(days=40)),
            RefreshToken(token="foreign-refresh-session", user_id=foreign_user.id, created_at=now),
        ],
    )
    session.commit()
    current_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "current-refresh-session"),
    )
    other_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "other-refresh-session"),
    )
    expired_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "expired-other-refresh-session"),
    )
    foreign_session_id = session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.token == "foreign-refresh-session"),
    )
    assert current_session_id is not None
    assert other_session_id is not None
    assert expired_session_id is not None
    assert foreign_session_id is not None
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
        refresh_max_age=timedelta(days=30),
    )

    revoked_count = await strategy.revoke_other_refresh_sessions(user, current_session_id)

    assert revoked_count == 1
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == current_session_id)) is not None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == other_session_id)) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == expired_session_id)) is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == foreign_session_id)) is not None


async def test_database_token_strategy_revoke_other_refresh_sessions_without_current_deletes_user_sessions(
    session: Session,
) -> None:
    """Without a current session id, revoking other sessions deletes all active user refresh sessions."""
    user = _create_user(session, email="revoke-all-sessions@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    await strategy.write_refresh_token(user)
    await strategy.write_refresh_token(user)

    revoked_count = await strategy.revoke_other_refresh_sessions(user, None)
    second_revoked_count = await strategy.revoke_other_refresh_sessions(user, None)

    assert revoked_count == EXPECTED_REVOKED_SESSIONS_WITHOUT_CURRENT
    assert second_revoked_count == 0
    assert session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None


async def test_database_token_strategy_rotate_refresh_token_returns_none_when_missing(session: Session) -> None:
    """Missing refresh tokens should not rotate."""
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )

    assert await strategy.rotate_refresh_token("missing-refresh-token", UnusedUserManager()) is None


async def test_database_token_strategy_refresh_token_replay_revokes_session_chain(session: Session) -> None:
    """Replaying a consumed refresh token revokes the active refresh session."""
    user = _create_user(session, email="refresh-replay@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    refresh_token = await strategy.write_refresh_token(user)
    persisted_refresh_token = session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert persisted_refresh_token is not None
    session_id = persisted_refresh_token.session_id

    rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())
    replay_rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())

    assert rotation is not None
    assert replay_rotation is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == session_id)) is None


async def test_database_token_strategy_concurrent_refresh_rotation_has_single_winner(
    async_sqlite_session_maker: async_sessionmaker[AsyncSession],
) -> None:
    """Concurrent refresh-token rotations against one token produce one rotation and revoke the session."""
    async with async_sqlite_session_maker() as setup_session:
        user = User(email="refresh-concurrent@example.com", hashed_password="hashed-password")
        setup_session.add(user)
        await setup_session.commit()
        await setup_session.refresh(user)
        strategy = DatabaseTokenStrategy(
            session=setup_session,
            token_hash_secret=_TOKEN_HASH_SECRET,
        )
        refresh_token = await strategy.write_refresh_token(user)
        await setup_session.commit()
        user_id = user.id

    barrier = asyncio.Barrier(CONCURRENT_REFRESH_ROTATION_COUNT)

    class _SynchronizedDatabaseTokenStrategy(DatabaseTokenStrategy[User, UUID]):
        async def _replace_refresh_token_digest(
            self,
            persisted_token: _RefreshTokenRow,
            *,
            consumed_token_digest: str,
            client_metadata: dict[str, str] | None,
        ) -> str | None:
            await barrier.wait()
            return await super()._replace_refresh_token_digest(
                persisted_token,
                consumed_token_digest=consumed_token_digest,
                client_metadata=client_metadata,
            )

    async def rotate_once() -> tuple[User, str] | None:
        async with async_sqlite_session_maker() as rotation_session:
            strategy = _SynchronizedDatabaseTokenStrategy(
                session=rotation_session,
                token_hash_secret=_TOKEN_HASH_SECRET,
            )
            rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())
            await rotation_session.commit()
            return rotation

    rotations = await asyncio.gather(*(rotate_once() for _ in range(CONCURRENT_REFRESH_ROTATION_COUNT)))
    successful_rotations = [rotation for rotation in rotations if rotation is not None]

    assert len(successful_rotations) == 1
    assert rotations.count(None) == 1

    async with async_sqlite_session_maker() as verification_session:
        result = await verification_session.execute(select(RefreshToken).where(RefreshToken.user_id == user_id))
        assert result.scalars().all() == []


async def test_database_token_strategy_identify_consumed_refresh_token_revokes_session_chain(
    session: Session,
) -> None:
    """Presenting a consumed refresh token for session lookup revokes the active refresh session."""
    user = _create_user(session, email="refresh-identify-replay@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    refresh_token = await strategy.write_refresh_token(user)
    persisted_refresh_token = session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert persisted_refresh_token is not None
    session_id = persisted_refresh_token.session_id
    assert await strategy.rotate_refresh_token(refresh_token, UnusedUserManager()) is not None

    identified_session_id = await strategy.identify_refresh_session(user, refresh_token)

    assert identified_session_id is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == session_id)) is None


async def test_database_token_strategy_stale_refresh_rotation_does_not_succeed(session: Session) -> None:
    """A stale rotation attempt cannot replace a token already consumed by another rotation."""
    user = _create_user(session, email="refresh-stale@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    refresh_token = await strategy.write_refresh_token(user)
    stale_row = await strategy._load_refresh_token_for_rotation(refresh_token)
    assert stale_row is not None
    session.expunge(stale_row)

    first_rotation = await strategy.rotate_refresh_token(refresh_token, UnusedUserManager())
    stale_rotation = await strategy._replace_refresh_token_digest(
        stale_row,
        consumed_token_digest=digest_opaque_token(token_hash_secret=_TOKEN_HASH_SECRET.encode(), token=refresh_token),
        client_metadata=None,
    )

    assert first_rotation is not None
    assert stale_rotation is None


async def test_database_token_strategy_stale_refresh_rotation_without_consumed_marker_returns_none(
    session: Session,
) -> None:
    """A stale rotation fails closed even if no consumed marker can identify the session."""
    user = _create_user(session, email="refresh-stale-unmarked@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    refresh_token = await strategy.write_refresh_token(user)
    stale_row = await strategy._load_refresh_token_for_rotation(refresh_token)
    assert stale_row is not None
    session.expunge(stale_row)
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.token == stale_row.token)
        .values(token="externally-replaced-refresh-digest"),
    )
    session.commit()

    stale_rotation = await strategy._replace_refresh_token_digest(
        stale_row,
        consumed_token_digest=digest_opaque_token(token_hash_secret=_TOKEN_HASH_SECRET.encode(), token=refresh_token),
        client_metadata=None,
    )

    assert stale_rotation is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is not None


async def test_database_token_strategy_rotate_returns_none_when_atomic_replace_loses(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public rotation path returns ``None`` when the atomic digest replacement loses a race."""
    user = _create_user(session, email="refresh-atomic-loss@example.com")
    strategy = DatabaseTokenStrategy(
        session=_strategy_session(session),
        token_hash_secret=_TOKEN_HASH_SECRET,
    )
    refresh_token = await strategy.write_refresh_token(user)

    monkeypatch.setattr(strategy, "_replace_refresh_token_digest", AsyncMock(return_value=None))

    assert await strategy.rotate_refresh_token(refresh_token, UnusedUserManager()) is None


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
