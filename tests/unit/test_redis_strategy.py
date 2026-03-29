"""Regression coverage for RedisTokenStrategy behavior."""

from __future__ import annotations

import importlib
from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.strategy import redis as redis_strategy_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key
from litestar_auth.authentication.strategy.redis import (
    DEFAULT_KEY_PREFIX,
    DEFAULT_TOKEN_BYTES,
    RedisTokenStrategy,
)
from litestar_auth.exceptions import ConfigurationError
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit
TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
CUSTOM_TOKEN_BYTES = 24
CUSTOM_MAX_SCAN_KEYS = 7

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


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


class FakeRedis:
    """Small in-memory Redis double for RedisTokenStrategy regressions."""

    def __init__(self) -> None:
        """Initialize in-memory key, set, and call-recording stores."""
        self.values: dict[str, bytes | str | None] = {}
        self.sets: dict[str, set[str]] = {}
        self.setex_calls: list[tuple[str, int, str]] = []
        self.deleted_batches: list[tuple[str, ...]] = []
        self.expire_calls: list[tuple[str, int]] = []
        self.scan_patterns: list[str | None] = []

    async def get(self, name: str, /) -> bytes | str | None:
        """Return the stored Redis value for the given key."""
        return self.values.get(name)

    async def setex(self, name: str, time: int, value: str, /) -> object:
        """Store a value and record the TTL-bearing write.

        Returns:
            Placeholder Redis response object.
        """
        self.setex_calls.append((name, time, value))
        self.values[name] = value.encode()
        return object()

    async def delete(self, *names: str) -> int:
        """Delete keys and set entries while recording the batch.

        Returns:
            Number of names passed to the delete call.
        """
        self.deleted_batches.append(names)
        for name in names:
            self.values.pop(name, None)
            self.sets.pop(name, None)
        return len(names)

    async def sadd(self, name: str, *values: str) -> int:
        """Add values to a set key.

        Returns:
            Number of newly added members.
        """
        bucket = self.sets.setdefault(name, set())
        before = len(bucket)
        bucket.update(values)
        return len(bucket) - before

    async def srem(self, name: str, *values: str) -> int:
        """Remove values from a set key.

        Returns:
            Number of removed members.
        """
        bucket = self.sets.get(name)
        if bucket is None:
            return 0
        before = len(bucket)
        for value in values:
            bucket.discard(value)
        return before - len(bucket)

    async def smembers(self, name: str) -> set[bytes]:
        """Return the encoded members for a set key."""
        return {member.encode() for member in self.sets.get(name, set())}

    async def expire(self, name: str, time: int) -> bool:
        """Record expire calls without enforcing TTL eviction.

        Returns:
            ``True`` to match Redis success semantics.
        """
        self.expire_calls.append((name, time))
        return True

    def scan_iter(
        self,
        match: object | None = None,
        count: int | None = None,
        _type: str | None = None,
        **kwargs: object,
    ) -> AsyncIterator[str]:
        """Yield keys whose prefix matches the Redis glob pattern.

        Returns:
            Async iterator over matching keys.
        """
        del count, _type, kwargs
        pattern = str(match) if match is not None else None
        self.scan_patterns.append(pattern)
        prefix = pattern.removesuffix("*") if pattern is not None else ""

        async def iterator() -> AsyncIterator[str]:  # noqa: RUF029
            for key in list(self.values):
                if key.startswith(prefix):
                    yield key

        return iterator()


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


def test_redis_strategy_rejects_short_token_hash_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy requires a sufficiently long token-hash secret."""
    _disable_optional_import(monkeypatch)

    with pytest.raises(ConfigurationError, match="RedisTokenStrategy token_hash_secret must be at least 32 characters"):
        RedisTokenStrategy(redis=FakeRedis(), token_hash_secret="short")


def test_redis_strategy_initializes_custom_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy should preserve its validated constructor settings."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    lifetime = timedelta(seconds=0)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=lifetime,
        token_bytes=CUSTOM_TOKEN_BYTES,
        key_prefix="custom-prefix:",
        subject_decoder=UUID,
        max_scan_keys=CUSTOM_MAX_SCAN_KEYS,
    )

    assert strategy.redis is redis
    assert strategy.lifetime == lifetime
    assert strategy.token_bytes == CUSTOM_TOKEN_BYTES
    assert strategy.key_prefix == "custom-prefix:"
    assert strategy.subject_decoder is UUID
    assert strategy._max_scan_keys == CUSTOM_MAX_SCAN_KEYS
    assert strategy._ttl_seconds == 1
    assert strategy._key("token-custom") == build_opaque_token_key(
        key_prefix="custom-prefix:",
        token_hash_secret=TOKEN_HASH_SECRET.encode(),
        token="token-custom",
    )
    assert strategy._user_index_key("user-123") == "custom-prefix:user:user-123"
    assert strategy._decode_user_id(b"user-123") == "user-123"
    assert strategy._decode_user_id("user-123") == "user-123"


async def test_redis_strategy_write_token_persists_token_and_updates_user_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """write_token() should write the token key and maintain the per-user index."""
    _disable_optional_import(monkeypatch)
    monkeypatch.setattr(redis_strategy_module.secrets, "token_urlsafe", lambda _: "token-write")
    redis = FakeRedis()
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=timedelta(minutes=5),
        token_bytes=16,
    )

    token = await strategy.write_token(user)

    token_key = _token_key(token)
    index_key = f"{DEFAULT_KEY_PREFIX}user:{user.id}"
    assert token == "token-write"
    assert redis.setex_calls == [(token_key, 300, str(user.id))]
    assert redis.values[token_key] == str(user.id).encode()
    assert redis.sets[index_key] == {token_key}
    assert redis.expire_calls == [(index_key, 300)]
    assert token not in token_key


async def test_redis_strategy_write_token_enforces_minimum_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """write_token() should clamp non-positive lifetimes to a one-second TTL."""
    _disable_optional_import(monkeypatch)
    monkeypatch.setattr(redis_strategy_module.secrets, "token_urlsafe", lambda _: "token-min-ttl")
    redis = FakeRedis()
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
        token_hash_secret=TOKEN_HASH_SECRET,
        lifetime=timedelta(seconds=0),
    )

    await strategy.write_token(user)

    token_key = _token_key("token-min-ttl")
    index_key = f"{DEFAULT_KEY_PREFIX}user:{user.id}"
    assert redis.setex_calls == [(token_key, 1, str(user.id))]
    assert redis.expire_calls == [(index_key, 1)]


async def test_redis_strategy_read_token_returns_user_from_stored_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """read_token() should decode the stored user id and resolve the user."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis = FakeRedis()
    token_key = _token_key("token-read")
    redis.values[token_key] = str(user.id).encode()
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    resolved_user = await strategy.read_token("token-read", user_manager)

    assert resolved_user == user
    assert user_manager.seen_user_ids == [user.id]


async def test_redis_strategy_read_token_returns_none_for_missing_or_empty_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """read_token() should ignore absent tokens and Redis misses."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis = FakeRedis()
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)

    assert await strategy.read_token(None, user_manager) is None
    assert await strategy.read_token("missing-token", user_manager) is None
    assert user_manager.seen_user_ids == []


async def test_redis_strategy_read_token_returns_none_when_subject_decoder_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """read_token() should treat decoder failures as invalid tokens."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    token_key = _token_key("token-invalid-subject")
    redis.values[token_key] = "not-a-uuid"
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
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
) -> None:
    """destroy_token() should delete the token and remove it from the user index."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    user = ExampleUser(id=uuid4())
    token = "token-destroy"
    token_key = _token_key(token)
    index_key = f"{DEFAULT_KEY_PREFIX}user:{user.id}"
    redis.values[token_key] = str(user.id).encode()
    redis.sets[index_key] = {token_key}
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)

    await strategy.destroy_token(token, user)

    assert redis.deleted_batches == [(token_key,)]
    assert token_key not in redis.values
    assert redis.sets[index_key] == set()


async def test_redis_strategy_invalidate_all_tokens_returns_after_index_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """invalidate_all_tokens() should skip scan fallback when the user index is populated."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    user = ExampleUser(id=uuid4())
    index_key = f"{DEFAULT_KEY_PREFIX}user:{user.id}"
    token_key = _token_key("token-index-only")
    redis.sets[index_key] = {token_key}
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)

    await strategy.invalidate_all_tokens(user)

    assert redis.deleted_batches == [(token_key, index_key)]
    assert redis.scan_patterns == []


async def test_redis_strategy_invalidate_all_tokens_uses_per_user_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """invalidate_all_tokens() should delete indexed user tokens and the index key."""
    _disable_optional_import(monkeypatch)
    token_values = iter(["token-a", "token-b", "token-other"])
    monkeypatch.setattr(
        redis_strategy_module.secrets,
        "token_urlsafe",
        lambda _nbytes: next(token_values),
    )
    redis = FakeRedis()
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)
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
    assert set(redis.deleted_batches[-1]) == {first_key, second_key, index_key}
    assert first_key not in redis.values
    assert second_key not in redis.values
    assert other_key in redis.values
    assert index_key not in redis.sets


async def test_redis_strategy_invalidate_all_tokens_falls_back_to_scan_without_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """invalidate_all_tokens() should scan matching keys when the per-user index is missing."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())
    matching_key_one = strategy._key("scan-a")
    matching_key_two = strategy._key("scan-b")
    foreign_key = strategy._key("scan-other")
    orphan_key = strategy._key("scan-orphan")
    ignored_prefix_key = "other-prefix:scan-ignored"

    redis.values[matching_key_one] = str(user.id).encode()
    redis.values[matching_key_two] = str(user.id)
    redis.values[foreign_key] = str(other_user.id).encode()
    redis.values[orphan_key] = None
    redis.values[ignored_prefix_key] = str(user.id).encode()

    await strategy.invalidate_all_tokens(user)

    assert redis.scan_patterns == [f"{DEFAULT_KEY_PREFIX}*"]
    assert redis.deleted_batches == [(matching_key_one, matching_key_two)]
    assert matching_key_one not in redis.values
    assert matching_key_two not in redis.values
    assert foreign_key in redis.values
    assert orphan_key in redis.values
    assert ignored_prefix_key in redis.values


async def test_redis_strategy_invalidate_all_tokens_respects_scan_safety_cap(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Scan fallback should stop once the configured safety cap is exceeded."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
        token_hash_secret=TOKEN_HASH_SECRET,
        max_scan_keys=1,
    )
    user = ExampleUser(id=uuid4())
    first_key = strategy._key("scan-cap-first")
    second_key = strategy._key("scan-cap-second")
    redis.values[first_key] = str(user.id).encode()
    redis.values[second_key] = str(user.id).encode()

    with caplog.at_level("WARNING", logger=redis_strategy_module.logger.name):
        await strategy.invalidate_all_tokens(user)

    assert redis.deleted_batches == [(first_key,)]
    assert second_key in redis.values
    assert "Scan-based token invalidation hit safety cap" in caplog.text


async def test_redis_strategy_scan_fallback_skips_delete_when_no_keys_match_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scan fallback should avoid delete calls when no token belongs to the user."""
    _disable_optional_import(monkeypatch)
    redis = FakeRedis()
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis, token_hash_secret=TOKEN_HASH_SECRET)
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())
    redis.values[strategy._key("scan-other-only")] = str(other_user.id).encode()

    await strategy.invalidate_all_tokens(user)

    assert redis.scan_patterns == [f"{DEFAULT_KEY_PREFIX}*"]
    assert redis.deleted_batches == []


async def test_redis_strategy_module_reload_preserves_public_behavior(
    monkeypatch: pytest.MonkeyPatch,
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

    redis = FakeRedis()
    user = ExampleUser(id=uuid4())
    strategy = reloaded_module.RedisTokenStrategy[ExampleUser, UUID](
        redis=redis,
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
    assert redis.deleted_batches == [(strategy._key(token),)]
