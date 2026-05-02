"""Extra tests for DB/Redis auth strategies to close remaining coverage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.strategy.base import SessionBindable
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.redis import (
    RedisClientProtocol,
    RedisTokenStrategy,
    RedisTokenStrategyConfig,
)
from litestar_auth.models import User
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"

pytestmark = pytest.mark.unit


@dataclass(slots=True)
class _DummyUser:
    """Minimal user object with an ``id`` attribute used by strategies."""

    id: UUID


class _DummyUserManager:
    async def get(self, user_id: Any) -> _DummyUser | None:  # noqa: ANN401
        return _DummyUser(UUID(str(user_id)))


class _FakeSession:
    """Async-session double used to exercise DatabaseTokenStrategy helpers."""

    def __init__(self) -> None:
        self.executed: list[Any] = []
        self.committed = False

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        del args, kwargs
        self.executed.append(statement)

        class _Result:
            rowcount = 1

        return _Result()

    async def commit(self) -> None:
        self.committed = True


def test_database_token_strategy_with_session_clones_configuration() -> None:
    """with_session() should return a new instance bound to the provided session."""
    base_session = _FakeSession()
    strategy = DatabaseTokenStrategy(
        session=cast("Any", base_session),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    other_session = _FakeSession()
    cloned = strategy.with_session(cast("Any", other_session))

    assert cloned is not strategy
    assert isinstance(cloned, DatabaseTokenStrategy)
    assert cloned.session is other_session
    assert cloned.max_age == strategy.max_age
    assert cloned.refresh_max_age == strategy.refresh_max_age
    assert cloned.token_bytes == strategy.token_bytes


def test_database_token_strategy_is_session_bindable() -> None:
    """DatabaseTokenStrategy should satisfy the runtime session-binding protocol."""
    strategy = DatabaseTokenStrategy(
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    assert isinstance(strategy, SessionBindable)


def test_database_token_strategy_accepts_user_uuid_type_parameters() -> None:
    """`DatabaseTokenStrategy[UP, ID]` specializes cleanly to the bundled ORM user and id."""
    strategy = DatabaseTokenStrategy[User, UUID](
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )
    assert isinstance(strategy, SessionBindable)
    assert isinstance(strategy, DatabaseTokenStrategy)


def test_database_token_strategy_rejects_removed_legacy_plaintext_kwarg() -> None:
    """The legacy plaintext compatibility kwarg has been removed from the public constructor."""
    with pytest.raises(TypeError, match="accept_legacy_plaintext_tokens"):
        cast("Any", DatabaseTokenStrategy)(
            session=cast("Any", _FakeSession()),
            token_hash_secret="test-token-hash-secret-1234567890-1234567890",
            accept_legacy_plaintext_tokens=True,
        )


async def test_database_token_strategy_cleanup_expired_tokens_uses_rowcount_and_commit() -> None:
    """cleanup_expired_tokens() should execute deletes for both models and commit once."""
    session = _FakeSession()
    strategy = DatabaseTokenStrategy(
        session=cast("Any", session),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    deleted = await strategy.cleanup_expired_tokens(cast("Any", session))

    expected_deleted = 2
    assert deleted == expected_deleted
    assert session.committed is True
    # Ensure both AccessToken and RefreshToken DELETEs were executed (matches ``delete(Model).where(...)``).
    stmt_text = " ".join(str(stmt).lower() for stmt in session.executed)
    assert "access_token" in stmt_text
    assert "refresh_token" in stmt_text


async def test_redis_token_strategy_read_token_none_and_invalidate_all_tokens(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisTokenStrategy.read_token(None) and missing-index invalidation should cover remaining branches."""
    strategy = RedisTokenStrategy(
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        ),
    )
    user_manager = _DummyUserManager()

    # read_token(None, ...) early-return branch.
    assert await strategy.read_token(None, user_manager) is None

    user = _DummyUser(uuid4())
    token = await strategy.write_token(user)
    deleted_index_count = await async_fakeredis.delete(strategy._user_index_key(str(user.id)))
    assert deleted_index_count == 1

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get(strategy._key(token)) == str(user.id).encode()


async def test_redis_token_strategy_invalidate_all_tokens_uses_index_when_present(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """invalidate_all_tokens() should prefer the per-user index when it exists."""
    strategy = RedisTokenStrategy(
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        ),
    )
    user = _DummyUser(uuid4())
    token = await strategy.write_token(user)

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get(strategy._key(token)) is None
    assert await async_fakeredis.exists(strategy._user_index_key(str(user.id))) == 0


async def test_redis_token_strategy_invalidate_all_tokens_without_index_leaves_foreign_keys(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Index-only invalidation should not inspect unrelated token keys."""
    strategy = RedisTokenStrategy(
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        ),
    )
    user = _DummyUser(uuid4())
    other_user = _DummyUser(uuid4())
    token = await strategy.write_token(other_user)
    deleted_index_count = await async_fakeredis.delete(strategy._user_index_key(str(other_user.id)))
    assert deleted_index_count == 1

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get(strategy._key(token)) == str(other_user.id).encode()
