"""Concurrency regressions for TOTP recovery-code and replay-store consumption."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from litestar_auth._totp_stores import RedisUsedTotpCodeStore, RedisUsedTotpCodeStoreClient
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User
from tests._helpers import cast_fakeredis
from tests.integration.conftest import enable_aiosqlite_foreign_keys

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fakeredis import FakeAsyncRedis as AsyncFakeRedis
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


pytestmark = pytest.mark.integration

CONSUMER_COUNT = 8


@pytest.fixture
async def sqlite_session_maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Create an aiosqlite-backed async session maker for concurrency tests.

    Yields:
        Async session maker bound to an isolated SQLite database.
    """
    database_path = tmp_path / "recovery-code-concurrency.sqlite"
    engine: AsyncEngine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    enable_aiosqlite_foreign_keys(engine)
    async with engine.begin() as connection:
        await connection.run_sync(User.metadata.create_all)

    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


async def test_sqlalchemy_aiosqlite_recovery_code_consume_has_single_winner(
    sqlite_session_maker: async_sessionmaker[AsyncSession],
) -> None:
    """Concurrent recovery-code consumers against SQLite observe one successful consume."""
    async with sqlite_session_maker() as session:
        database = SQLAlchemyUserDatabase(session=session, user_model=User)
        user = await database.create(
            {
                "email": "recovery-code-concurrency@example.com",
                "hashed_password": "hashed-password",
            },
        )
        await database.set_recovery_code_hashes(user, {"lookup-1": "hash-1", "lookup-2": "hash-2"})
        await session.commit()
        user_id = user.id

    barrier = asyncio.Barrier(CONSUMER_COUNT)

    async def consume_once() -> bool:
        async with sqlite_session_maker() as session:
            database = SQLAlchemyUserDatabase(session=session, user_model=User)
            user = await database.get(user_id)
            assert user is not None
            await barrier.wait()
            consumed = await database.consume_recovery_code_by_lookup(user, "lookup-1")
            await session.commit()
            return consumed

    results = await asyncio.gather(*(consume_once() for _ in range(CONSUMER_COUNT)))

    assert results.count(True) == 1
    assert results.count(False) == CONSUMER_COUNT - 1

    async with sqlite_session_maker() as session:
        database = SQLAlchemyUserDatabase(session=session, user_model=User)
        reloaded_user = await database.get(user_id)

    assert reloaded_user is not None
    assert reloaded_user.recovery_codes == {"lookup-2": "hash-2"}


async def test_redis_used_totp_store_concurrent_code_mark_has_single_winner(
    async_fakeredis: AsyncFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Redis-backed TOTP replay store consumes one shared code once."""
    monkeypatch.setattr("litestar_auth._totp_stores._load_used_totp_redis_asyncio", lambda: None)
    store = RedisUsedTotpCodeStore(
        redis=cast_fakeredis(async_fakeredis, RedisUsedTotpCodeStoreClient),
        key_prefix="totp-used:",
    )
    barrier = asyncio.Barrier(CONSUMER_COUNT)

    async def mark_once() -> bool:
        await barrier.wait()
        result = await store.mark_used("user-1", 123, ttl_seconds=60)
        return result.stored

    results = await asyncio.gather(*(mark_once() for _ in range(CONSUMER_COUNT)))

    assert results.count(True) == 1
    assert results.count(False) == CONSUMER_COUNT - 1
    assert await async_fakeredis.get("totp-used:user-1:123") == b"1"
