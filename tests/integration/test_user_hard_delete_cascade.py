"""Integration coverage for hard-delete cleanup of user-owned auth state."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.strategy.redis import RedisClientProtocol, RedisTokenStrategy
from litestar_auth.db import ApiKeyData, OAuthAccountData
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore, SQLAlchemyUserDatabase
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import ApiKey, OAuthAccount, User, UserRole
from litestar_auth.oauth_encryption import OAuthTokenEncryption
from tests._helpers import cast_fakeredis
from tests.integration.conftest import enable_aiosqlite_foreign_keys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fakeredis import FakeAsyncRedis as AsyncFakeRedis
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


pytestmark = pytest.mark.integration

TOKEN_HASH_SECRET = "hard-delete-token-secret-0123456789abcdef"
API_KEY_SECRET_DIGEST = b"1" * 64


@dataclass(slots=True)
class _Backend:
    strategy: object


@pytest.fixture
async def hard_delete_session_maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Create an aiosqlite session maker with SQLite FK enforcement enabled.

    Yields:
        Async session maker bound to an isolated SQLite database.
    """
    database_path = tmp_path / "hard-delete-cascade.sqlite"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


async def test_user_lifecycle_hard_delete_removes_dependent_sql_and_redis_state(
    hard_delete_session_maker: async_sessionmaker[AsyncSession],
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Lifecycle delete clears token, API-key, OAuth, TOTP, and Redis session artifacts."""
    redis_strategy = RedisTokenStrategy[User, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=timedelta(minutes=5),
        subject_decoder=UUID,
    )
    async with hard_delete_session_maker() as session:
        database = _user_database(session)
        api_key_store = SQLAlchemyApiKeyStore(session, api_key_model=ApiKey)
        db_strategy = DatabaseTokenStrategy[User, UUID](
            session=session,
            token_hash_secret=TOKEN_HASH_SECRET,
            max_age=timedelta(minutes=5),
        )
        manager = BaseUserManager[User, UUID](
            database,
            security=UserManagerSecurity[UUID](
                verification_token_secret="0123456789abcdef" * 4,
                reset_password_token_secret="fedcba9876543210" * 4,
                api_key_hash_secret="89abcdef01234567" * 4,
                id_parser=UUID,
            ),
            api_key_store=api_key_store,
            backends=(_Backend(strategy=db_strategy), _Backend(strategy=redis_strategy)),
        )
        user = await database.create({"email": "hard-delete@example.com", "hashed_password": "hashed-password"})
        await database.update(user, {"totp_secret": "secret", "recovery_codes": {"lookup": "hash"}})
        await database.upsert_oauth_account(
            user,
            account=OAuthAccountData(
                oauth_name="github",
                account_id="hard-delete-gh",
                account_email=user.email,
                access_token="access",
                expires_at=3600,
                refresh_token="refresh",
            ),
        )
        await api_key_store.create(
            ApiKeyData(
                key_id="hard-delete-key",
                user_id=user.id,
                hashed_secret=API_KEY_SECRET_DIGEST,
                encrypted_secret=None,
                name="Hard delete",
                scopes=["read"],
                prefix_env="prod",
                signing_required=False,
                expires_at=None,
                created_via="integration-test",
            ),
        )
        redis_token = await redis_strategy.write_token(user)
        await redis_strategy.issue_totp_stepup(user, "session-1", ttl_seconds=300)
        await db_strategy.write_token(user)
        await db_strategy.write_refresh_token(user)
        await session.commit()
        user_id = user.id
        redis_token_key = redis_strategy._key(redis_token)
        redis_token_index_key = redis_strategy._user_index_key(str(user_id))
        redis_stepup_key = redis_strategy._totp_stepup_key(str(user_id), "session-1")
        redis_stepup_index_key = redis_strategy._totp_stepup_index_key(str(user_id))

        await manager.delete(user_id)
        await session.commit()

    async with hard_delete_session_maker() as session:
        assert await _row_count(session, User) == 0
        assert await _row_count(session, AccessToken) == 0
        assert await _row_count(session, RefreshToken) == 0
        assert await _row_count(session, ApiKey) == 0
        assert await _row_count(session, OAuthAccount) == 0

    assert await async_fakeredis.get(redis_token_key) is None
    assert await async_fakeredis.exists(redis_token_index_key) == 0
    assert await async_fakeredis.get(redis_stepup_key) is None
    assert await async_fakeredis.exists(redis_stepup_index_key) == 0


async def test_database_fk_cascade_clears_sql_stores_without_lifecycle_fanout(
    hard_delete_session_maker: async_sessionmaker[AsyncSession],
) -> None:
    """Database-level ON DELETE CASCADE removes SQL dependents when the user row is deleted directly."""
    async with hard_delete_session_maker() as session:
        database = _user_database(session)
        user = await database.create({"email": "fk-cascade@example.com", "hashed_password": "hashed-password"})
        await database.upsert_oauth_account(
            user,
            account=OAuthAccountData(
                oauth_name="github",
                account_id="fk-cascade-gh",
                account_email=user.email,
                access_token="access",
                expires_at=None,
                refresh_token=None,
            ),
        )
        await SQLAlchemyApiKeyStore(session, api_key_model=ApiKey).create(
            ApiKeyData(
                key_id="fk-cascade-key",
                user_id=user.id,
                hashed_secret=API_KEY_SECRET_DIGEST,
                encrypted_secret=None,
                name="FK cascade",
                scopes=[],
                prefix_env="prod",
                signing_required=False,
                expires_at=None,
                created_via="integration-test",
            ),
        )
        session.add(AccessToken(token="access-token-row", user_id=user.id))
        session.add(RefreshToken(token="refresh-token-row", user_id=user.id))
        await session.commit()

        await database.delete(user.id)
        await session.commit()

    async with hard_delete_session_maker() as session:
        assert await _row_count(session, AccessToken) == 0
        assert await _row_count(session, RefreshToken) == 0
        assert await _row_count(session, ApiKey) == 0
        assert await _row_count(session, OAuthAccount) == 0


def test_user_owned_foreign_keys_declare_ondelete_cascade() -> None:
    """Every bundled FK to the user table declares ON DELETE CASCADE."""
    for model in (AccessToken, RefreshToken, ApiKey, OAuthAccount, UserRole):
        user_id_column = inspect(model).columns["user_id"]
        foreign_key = next(iter(user_id_column.foreign_keys))
        assert foreign_key.ondelete == "CASCADE"


def _user_database(session: AsyncSession) -> SQLAlchemyUserDatabase[User]:
    """Return a SQLAlchemy user database bound to the bundled OAuth model."""
    oauth_token_encryption = OAuthTokenEncryption(base64.urlsafe_b64encode(b"0" * 32).decode())
    return SQLAlchemyUserDatabase(
        session,
        user_model=User,
        oauth_account_model=OAuthAccount,
        oauth_token_encryption=oauth_token_encryption,
    )


async def _row_count(session: AsyncSession, model: type[Any]) -> int:
    """Return row count for ``model``."""
    result = await session.execute(select(func.count()).select_from(model))
    return result.scalar_one()
