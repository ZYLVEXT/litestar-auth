"""Regression coverage for RedisTokenStrategy behavior."""

from __future__ import annotations

import importlib
from datetime import timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.strategy import redis as redis_strategy_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key
from litestar_auth.authentication.strategy.redis import (
    DEFAULT_KEY_PREFIX,
    DEFAULT_TOKEN_BYTES,
    RedisClientProtocol,
    RedisTokenStrategy,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit._helpers import _safe_key_part
from tests._helpers import ExampleUser, cast_fakeredis

pytestmark = pytest.mark.unit
TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
CUSTOM_TOKEN_BYTES = 24
FIVE_MINUTES_TTL_SECONDS = 300
FIVE_MINUTES_TTL_FLOOR = FIVE_MINUTES_TTL_SECONDS - 1
MINIMUM_TTL_SECONDS = 1
MINIMUM_TTL_FLOOR = 0

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis, AsyncFakeRedisFactory


class ExampleUserManager:
    """User manager double returning a preloaded user."""

    def __init__(self, user: ExampleUser) -> None:
        """Store the expected user for lookup assertions."""
        self.user = user
        self.seen_user_ids: list[object] = []

    async def get(self, user_id: object) -> ExampleUser | None:
        """Return the configured user when the identifier matches."""
        self.seen_user_ids.append(user_id)
        return self.user if user_id == self.user.id else None


class _RecordingRedisClient:
    """Delegate to fakeredis while recording TTL arguments for timing-sensitive tests."""

    def __init__(self, redis: AsyncFakeRedis) -> None:
        """Store the wrapped fakeredis client."""
        self.redis = redis
        self.setex_calls: list[tuple[str, int, str]] = []
        self.expire_calls: list[tuple[str, int]] = []

    async def setex(self, name: str, time: int, value: str, /) -> object:
        """Record an expiring value write and execute it against fakeredis.

        Returns:
            The wrapped fakeredis ``setex`` result.
        """
        self.setex_calls.append((name, time, value))
        return await self.redis.setex(name, time, value)

    async def sadd(self, name: str, *values: str) -> int:
        """Delegate set membership writes to fakeredis.

        Returns:
            The number of added set members.
        """
        return await self.redis.sadd(name, *values)  # ty: ignore[invalid-await]

    async def expire(self, name: str, time: int) -> bool:
        """Record key expiry updates and execute them against fakeredis.

        Returns:
            Whether fakeredis applied the expiration.
        """
        self.expire_calls.append((name, time))
        return await self.redis.expire(name, time)


def _disable_optional_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass the optional redis dependency import during unit tests."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)


def _token_key(token: str) -> str:
    """Build the expected hashed Redis key for a token.

    Returns:
        Redis storage key for the opaque token.
    """
    return build_opaque_token_key(
        key_prefix=DEFAULT_KEY_PREFIX,
        token_hash_secret=TOKEN_HASH_SECRET.encode(),
        token=token,
    )


def test_redis_strategy_rejects_short_token_hash_secret(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisTokenStrategy requires a sufficiently long token-hash secret."""
    _disable_optional_import(monkeypatch)

    with pytest.raises(ConfigurationError, match="RedisTokenStrategy token_hash_secret must be at least 32 characters"):
        RedisTokenStrategy(redis=cast_fakeredis(async_fakeredis, RedisClientProtocol), token_hash_secret="short")


def test_redis_strategy_initializes_custom_configuration(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisTokenStrategy should preserve its validated constructor settings."""
    _disable_optional_import(monkeypatch)
    lifetime = timedelta(seconds=0)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=lifetime,
        token_bytes=CUSTOM_TOKEN_BYTES,
        key_prefix="custom-prefix:",
        subject_decoder=UUID,
    )

    assert strategy.redis is async_fakeredis
    assert strategy.lifetime == lifetime
    assert strategy.token_bytes == CUSTOM_TOKEN_BYTES
    assert strategy.key_prefix == "custom-prefix:"
    assert strategy.subject_decoder is UUID
    assert strategy._ttl_seconds == 1
    assert strategy._key("token-custom") == build_opaque_token_key(
        key_prefix="custom-prefix:",
        token_hash_secret=TOKEN_HASH_SECRET.encode(),
        token="token-custom",
    )
    assert strategy._user_index_key("user-123") == f"custom-prefix:user:{_safe_key_part('user-123')}"
    assert strategy._decode_user_id(b"user-123") == "user-123"
    assert strategy._decode_user_id("user-123") == "user-123"


def test_redis_strategy_user_index_key_hashes_subject_text(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Per-user index keys hash raw subjects so delimiters cannot shape Redis keys."""
    _disable_optional_import(monkeypatch)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )

    index_key = strategy._user_index_key("tenant:admin")

    assert index_key == f"{DEFAULT_KEY_PREFIX}user:{_safe_key_part('tenant:admin')}"
    assert "tenant:admin" not in index_key


async def test_redis_strategy_write_token_persists_token_and_updates_user_index(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """write_token() should write the token key and maintain the per-user index."""
    _disable_optional_import(monkeypatch)
    monkeypatch.setattr(redis_strategy_module.secrets, "token_urlsafe", lambda _: "token-write")
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=timedelta(minutes=5),
        token_bytes=16,
    )

    token = await strategy.write_token(user)

    token_key = _token_key(token)
    index_key = strategy._user_index_key(str(user.id))
    assert token == "token-write"
    assert await async_fakeredis.get(token_key) == str(user.id).encode()
    assert await async_fakeredis.smembers(index_key) == {token_key.encode()}  # ty: ignore[invalid-await]
    assert FIVE_MINUTES_TTL_FLOOR <= await async_fakeredis.ttl(token_key) <= FIVE_MINUTES_TTL_SECONDS
    assert FIVE_MINUTES_TTL_FLOOR <= await async_fakeredis.ttl(index_key) <= FIVE_MINUTES_TTL_SECONDS
    assert token not in token_key


async def test_redis_strategy_write_token_enforces_minimum_ttl(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """write_token() should clamp non-positive lifetimes to a one-second TTL."""
    _disable_optional_import(monkeypatch)
    monkeypatch.setattr(redis_strategy_module.secrets, "token_urlsafe", lambda _: "token-min-ttl")
    user = ExampleUser(id=uuid4())
    recording_redis = _RecordingRedisClient(async_fakeredis)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast("RedisClientProtocol", recording_redis),
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=timedelta(seconds=0),
    )

    await strategy.write_token(user)

    token_key = _token_key("token-min-ttl")
    index_key = strategy._user_index_key(str(user.id))
    assert recording_redis.setex_calls == [(token_key, MINIMUM_TTL_SECONDS, str(user.id))]
    assert recording_redis.expire_calls == [(index_key, MINIMUM_TTL_SECONDS)]


@pytest.mark.parametrize("response_mode", ["bytes", "str"], ids=["bytes", "str"])
async def test_redis_strategy_read_token_returns_user_from_stored_subject(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
    response_mode: str,
) -> None:
    """read_token() should decode the stored user id and resolve the user."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis = async_fakeredis_factory(decode_responses=response_mode == "str")
    token_key = _token_key("token-read")
    assert await redis.set(token_key, str(user.id)) is True
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(redis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    resolved_user = await strategy.read_token("token-read", user_manager)

    assert resolved_user == user
    assert user_manager.seen_user_ids == [user.id]


async def test_redis_strategy_read_token_returns_none_for_missing_or_empty_input(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """read_token() should ignore absent tokens and Redis misses."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )

    assert await strategy.read_token(None, user_manager) is None
    assert await strategy.read_token("missing-token", user_manager) is None
    assert user_manager.seen_user_ids == []


async def test_redis_strategy_read_token_returns_none_when_subject_decoder_fails(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """read_token() should treat decoder failures as invalid tokens."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    token_key = _token_key("token-invalid-subject")
    assert await redis.set(token_key, "not-a-uuid") is True
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(redis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    class ShouldNotBeCalledUserManager:
        """Fail the test if `get()` is reached after decoder failure."""

        async def get(self, user_id: object) -> ExampleUser | None:
            del user_id
            msg = "user manager should not be called for invalid token subjects"
            raise AssertionError(msg)

    assert await strategy.read_token("token-invalid-subject", ShouldNotBeCalledUserManager()) is None


async def test_redis_strategy_destroy_token_removes_token_key_and_user_index_entry(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """destroy_token() should delete the token and remove it from the user index."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    token = "token-destroy"
    token_key = _token_key(token)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )
    index_key = strategy._user_index_key(str(user.id))
    assert await async_fakeredis.set(token_key, str(user.id)) is True
    assert await async_fakeredis.sadd(index_key, token_key) == 1  # ty: ignore[invalid-await]

    await strategy.destroy_token(token, user)

    assert await async_fakeredis.get(token_key) is None
    assert await async_fakeredis.smembers(index_key) == set()  # ty: ignore[invalid-await]


async def test_redis_strategy_invalidate_all_tokens_returns_after_index_delete(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """invalidate_all_tokens() should delete only keys present in the user index."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    token_key = _token_key("token-index-only")
    extra_key = _token_key("token-outside-index")
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )
    index_key = strategy._user_index_key(str(user.id))
    assert await async_fakeredis.set(token_key, str(user.id)) is True
    assert await async_fakeredis.set(extra_key, str(user.id)) is True
    assert await async_fakeredis.sadd(index_key, token_key) == 1  # ty: ignore[invalid-await]

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get(token_key) is None
    assert await async_fakeredis.exists(index_key) == 0
    assert await async_fakeredis.get(extra_key) == str(user.id).encode()


async def test_redis_strategy_invalidate_all_tokens_uses_per_user_index(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """invalidate_all_tokens() should delete indexed user tokens and the index key."""
    _disable_optional_import(monkeypatch)
    token_values = iter(["token-a", "token-b", "token-other"])
    monkeypatch.setattr(
        redis_strategy_module.secrets,
        "token_urlsafe",
        lambda _nbytes: next(token_values),
    )
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())

    first_token = await strategy.write_token(user)
    second_token = await strategy.write_token(user)
    other_token = await strategy.write_token(other_user)

    await strategy.invalidate_all_tokens(user)

    first_key = strategy._key(first_token)
    second_key = strategy._key(second_token)
    other_key = strategy._key(other_token)
    index_key = strategy._user_index_key(str(user.id))
    assert await async_fakeredis.get(first_key) is None
    assert await async_fakeredis.get(second_key) is None
    assert await async_fakeredis.get(other_key) == str(other_user.id).encode()
    assert await async_fakeredis.exists(index_key) == 0


async def test_redis_strategy_invalidate_all_tokens_without_index_leaves_orphaned_tokens(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """invalidate_all_tokens() should not inspect tokens when the per-user index is missing."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(redis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
    )
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())
    matching_key_one = strategy._key("orphan-a")
    matching_key_two = strategy._key("orphan-b")
    foreign_key = strategy._key("orphan-other")
    ignored_prefix_key = "other-prefix:orphan-ignored"

    assert await redis.set(matching_key_one, str(user.id)) is True
    assert await redis.set(matching_key_two, str(user.id)) is True
    assert await redis.set(foreign_key, str(other_user.id)) is True
    assert await redis.set(ignored_prefix_key, str(user.id)) is True

    await strategy.invalidate_all_tokens(user)

    assert await redis.get(matching_key_one) == str(user.id)
    assert await redis.get(matching_key_two) == str(user.id)
    assert await redis.get(foreign_key) == str(other_user.id)
    assert await redis.get(ignored_prefix_key) == str(user.id)


async def test_redis_strategy_module_reload_preserves_public_behavior(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Reloading the module under coverage preserves strategy behavior."""
    reloaded_module = importlib.reload(redis_strategy_module)

    def load_redis() -> object:
        """Bypass the optional Redis import during the reload smoke test.

        Returns:
            Placeholder object standing in for the Redis module.
        """
        return object()

    monkeypatch.setattr(reloaded_module, "_load_redis_asyncio", load_redis)
    monkeypatch.setattr(reloaded_module.secrets, "token_urlsafe", lambda _: "reloaded-token")

    user = ExampleUser(id=uuid4())
    strategy = reloaded_module.RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    token = await strategy.write_token(user)
    resolved_user = await strategy.read_token(token, ExampleUserManager(user))
    await strategy.destroy_token(token, user)

    assert reloaded_module.DEFAULT_KEY_PREFIX == DEFAULT_KEY_PREFIX
    assert reloaded_module.DEFAULT_TOKEN_BYTES == DEFAULT_TOKEN_BYTES
    assert token == "reloaded-token"
    assert resolved_user == user
    assert await async_fakeredis.get(strategy._key(token)) is None
