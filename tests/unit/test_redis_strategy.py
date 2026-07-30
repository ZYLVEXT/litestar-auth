"""Regression coverage for RedisTokenStrategy behavior."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID, uuid4

import pytest
from authweave_core import Invalid

from litestar_auth.authentication.strategy import _opaque_tokens as opaque_tokens_module
from litestar_auth.authentication.strategy import redis as redis_strategy_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key
from litestar_auth.authentication.strategy.base import (
    HumanSessionAuthenticated,
    HumanSessionStrategy,
    UserManagerProtocol,
)
from litestar_auth.authentication.strategy.redis import (
    DEFAULT_KEY_PREFIX,
    RedisClientProtocol,
    RedisTokenStrategy,
    RedisTokenStrategyConfig,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit._key_derivation import _safe_key_part
from tests._helpers import ExampleUser, cast_fakeredis

pytestmark = pytest.mark.unit
TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
CUSTOM_TOKEN_BYTES = 24
FIVE_MINUTES_TTL_SECONDS = 300
FIVE_MINUTES_TTL_FLOOR = FIVE_MINUTES_TTL_SECONDS - 1
MINIMUM_TTL_SECONDS = 1
MINIMUM_TTL_FLOOR = 0
FRACTIONAL_LIFETIME_REDIS_TTL_SECONDS = 2

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis, AsyncFakeRedisFactory


async def _authenticated_user(
    strategy: HumanSessionStrategy[ExampleUser, UUID],
    token: str,
    user_manager: UserManagerProtocol[ExampleUser, UUID],
) -> ExampleUser:
    attempt = await strategy.authenticate_token(token, user_manager)
    assert isinstance(attempt, HumanSessionAuthenticated)
    return attempt.user


async def _assert_invalid(
    strategy: HumanSessionStrategy[ExampleUser, UUID],
    token: str,
    user_manager: UserManagerProtocol[ExampleUser, UUID],
) -> None:
    attempt = await strategy.authenticate_token(token, user_manager)
    assert isinstance(attempt, Invalid)


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
        self.set_ex_calls: list[tuple[str, str, int]] = []
        self.expire_calls: list[tuple[str, int]] = []

    async def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool = False,
        px: int | None = None,
        ex: int | None = None,
    ) -> object:
        """Record expiring ``SET EX`` writes and delegate other sets to fakeredis.

        Returns:
            The wrapped fakeredis ``set`` result.
        """
        if ex is not None and not nx and px is None:
            self.set_ex_calls.append((name, value, ex))
            return await self.redis.set(name, value, ex=ex)
        return await self.redis.set(name, value, nx=nx, px=px, ex=ex)

    async def get(self, name: str, /) -> object:
        """Delegate value reads to fakeredis.

        Returns:
            The wrapped fakeredis ``get`` result.
        """
        return await self.redis.get(name)

    async def sadd(self, name: str, *values: str) -> int:
        """Delegate set membership writes to fakeredis.

        Returns:
            The number of added set members.
        """
        return await self.redis.sadd(name, *values)

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
        RedisTokenStrategy(
            config=RedisTokenStrategyConfig(
                redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
                token_hash_secret="short",
            ),
        )


def test_redis_strategy_rejects_token_bytes_below_minimum(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisTokenStrategy refuses opaque-token sizes below the 128-bit floor."""
    _disable_optional_import(monkeypatch)

    with pytest.raises(ConfigurationError, match="RedisTokenStrategy token_bytes=8 is below the minimum of 16"):
        RedisTokenStrategy(
            config=RedisTokenStrategyConfig(
                redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
                token_hash_secret=TOKEN_HASH_SECRET,
                token_bytes=8,
            ),
        )


def test_redis_strategy_rejects_config_combined_with_keyword_options(async_fakeredis: AsyncFakeRedis) -> None:
    """RedisTokenStrategy accepts either a config object or keyword options."""
    with pytest.raises(ValueError, match="RedisTokenStrategyConfig or keyword options"):
        RedisTokenStrategy(
            config=RedisTokenStrategyConfig(
                redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
                token_hash_secret=TOKEN_HASH_SECRET,
            ),
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        )


def test_redis_strategy_initializes_custom_configuration(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisTokenStrategy should preserve its validated constructor settings."""
    _disable_optional_import(monkeypatch)
    lifetime = timedelta(seconds=0)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            lifetime=lifetime,
            token_bytes=CUSTOM_TOKEN_BYTES,
            key_prefix="custom-prefix:",
            subject_decoder=UUID,
        ),
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
    assert strategy._decode_token_payload("v1:3:user-123") == (3, "user-123")
    assert strategy._decode_token_payload("user-123") is None
    assert strategy._decode_token_payload("v1:3") is None
    assert strategy._decode_token_payload("v1:-1:user-123") is None
    assert strategy._decode_token_payload("v1:not-int:user-123") is None


def test_redis_strategy_fractional_lifetime_never_expires_early(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis second precision must round a positive fractional lifetime up."""
    _disable_optional_import(monkeypatch)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            lifetime=timedelta(seconds=1, microseconds=1),
        ),
    )

    assert strategy._ttl_seconds == FRACTIONAL_LIFETIME_REDIS_TTL_SECONDS


def test_redis_strategy_user_index_key_hashes_subject_text(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Per-user index keys hash raw subjects so delimiters cannot shape Redis keys."""
    _disable_optional_import(monkeypatch)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
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
    monkeypatch.setattr(opaque_tokens_module.secrets, "token_urlsafe", lambda _: "token-write")
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            lifetime=timedelta(minutes=5),
            token_bytes=16,
        ),
    )

    token = await strategy.write_token(user)

    token_key = _token_key(token)
    index_key = strategy._user_index_key(str(user.id))
    assert token == "token-write"
    assert await async_fakeredis.get(token_key) == f"v1:0:{user.id}".encode()
    assert await async_fakeredis.smembers(index_key) == {token_key.encode()}
    assert FIVE_MINUTES_TTL_FLOOR <= await async_fakeredis.ttl(token_key) <= FIVE_MINUTES_TTL_SECONDS
    assert FIVE_MINUTES_TTL_FLOOR <= await async_fakeredis.ttl(index_key) <= FIVE_MINUTES_TTL_SECONDS
    assert token not in token_key


async def test_redis_strategy_write_token_enforces_minimum_ttl(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """write_token() should clamp non-positive lifetimes to a one-second TTL."""
    _disable_optional_import(monkeypatch)
    monkeypatch.setattr(opaque_tokens_module.secrets, "token_urlsafe", lambda _: "token-min-ttl")
    user = ExampleUser(id=uuid4())
    recording_redis = _RecordingRedisClient(async_fakeredis)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast("RedisClientProtocol", recording_redis),
            token_hash_secret=TOKEN_HASH_SECRET,
            lifetime=timedelta(seconds=0),
        ),
    )

    await strategy.write_token(user)

    token_key = _token_key("token-min-ttl")
    index_key = strategy._user_index_key(str(user.id))
    assert recording_redis.set_ex_calls == [(token_key, f"v1:0:{user.id}", MINIMUM_TTL_SECONDS)]
    assert recording_redis.expire_calls == [(index_key, MINIMUM_TTL_SECONDS)]


@pytest.mark.parametrize("response_mode", ["bytes", "str"], ids=["bytes", "str"])
async def test_redis_strategy_authenticates_stored_subject(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
    response_mode: str,
) -> None:
    """Typed authentication decodes the stored user id and resolves the user."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis = async_fakeredis_factory(decode_responses=response_mode == "str")
    token_key = _token_key("token-read")
    assert await redis.set(token_key, f"v1:0:{user.id}") is True
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(redis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            subject_decoder=UUID,
        ),
    )

    resolved_user = await _authenticated_user(strategy, "token-read", user_manager)

    assert resolved_user == user
    assert user_manager.seen_user_ids == [user.id]


async def test_redis_strategy_rejects_legacy_raw_user_id(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Version 7 never reinterprets a legacy raw-user-id session record."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    token = "legacy-token"
    assert await async_fakeredis.set(_token_key(token), str(user.id)) is True
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            subject_decoder=UUID,
        ),
    )

    await _assert_invalid(strategy, token, ExampleUserManager(user))


async def test_redis_strategy_rejects_missing_token(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Typed authentication rejects Redis misses."""
    _disable_optional_import(monkeypatch)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
    )

    await _assert_invalid(strategy, "missing-token", user_manager)
    assert user_manager.seen_user_ids == []


async def test_redis_strategy_rejects_subject_when_decoder_fails(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Typed authentication treats decoder failures as invalid tokens."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    token_key = _token_key("token-invalid-subject")
    assert await redis.set(token_key, "v1:0:not-a-uuid") is True
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(redis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            subject_decoder=UUID,
        ),
    )

    class ShouldNotBeCalledUserManager:
        """Fail the test if `get()` is reached after decoder failure."""

        async def get(self, user_id: object) -> ExampleUser | None:
            msg = "user manager should not be called for invalid token subjects"
            raise AssertionError(msg)

    await _assert_invalid(strategy, "token-invalid-subject", ShouldNotBeCalledUserManager())


async def test_redis_strategy_rejects_corrupt_epoch(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Typed authentication fails closed when the stored user epoch is not an integer."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    user = ExampleUser(id=uuid4())
    token_key = _token_key("token-corrupt-epoch")
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(redis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            subject_decoder=UUID,
        ),
    )
    assert await redis.set(token_key, f"v1:0:{user.id}") is True
    assert await redis.set(strategy._user_epoch_key(str(user.id)), "not-int") is True

    await _assert_invalid(strategy, "token-corrupt-epoch", ExampleUserManager(user))


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
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
    )
    index_key = strategy._user_index_key(str(user.id))
    assert await async_fakeredis.set(token_key, str(user.id)) is True
    assert await async_fakeredis.sadd(index_key, token_key) == 1

    await strategy.destroy_token(token, user)

    assert await async_fakeredis.get(token_key) is None
    assert await async_fakeredis.smembers(index_key) == set()


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
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
    )
    index_key = strategy._user_index_key(str(user.id))
    assert await async_fakeredis.set(token_key, str(user.id)) is True
    assert await async_fakeredis.set(extra_key, str(user.id)) is True
    assert await async_fakeredis.sadd(index_key, token_key) == 1

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get(token_key) is None
    assert await async_fakeredis.exists(index_key) == 0
    assert await async_fakeredis.get(extra_key) == str(user.id).encode()
    await _assert_invalid(strategy, "token-outside-index", ExampleUserManager(user))
    assert await async_fakeredis.get(strategy._user_epoch_key(str(user.id))) == b"1"


async def test_redis_strategy_invalidate_all_tokens_uses_per_user_index(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """invalidate_all_tokens() should delete indexed user tokens and the index key."""
    _disable_optional_import(monkeypatch)
    token_values = iter(["token-a", "token-b", "token-other"])
    monkeypatch.setattr(
        opaque_tokens_module.secrets,
        "token_urlsafe",
        lambda _nbytes: next(token_values),
    )
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
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
    assert await async_fakeredis.get(other_key) == f"v1:0:{other_user.id}".encode()
    assert await async_fakeredis.exists(index_key) == 0


async def test_redis_strategy_invalidate_all_tokens_removes_indexed_totp_stepup_markers(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """invalidate_all_tokens() should remove per-user TOTP step-up markers."""
    _disable_optional_import(monkeypatch)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
    )
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())

    await strategy.issue_totp_stepup(user, "session-a", ttl_seconds=FIVE_MINUTES_TTL_SECONDS)
    await strategy.issue_totp_stepup(user, "session-b", ttl_seconds=FIVE_MINUTES_TTL_SECONDS)
    await strategy.issue_totp_stepup(other_user, "session-c", ttl_seconds=FIVE_MINUTES_TTL_SECONDS)

    await strategy.invalidate_all_tokens(user)

    first_key = strategy._totp_stepup_key(str(user.id), "session-a")
    second_key = strategy._totp_stepup_key(str(user.id), "session-b")
    other_key = strategy._totp_stepup_key(str(other_user.id), "session-c")
    index_key = strategy._totp_stepup_index_key(str(user.id))
    assert await async_fakeredis.get(first_key) is None
    assert await async_fakeredis.get(second_key) is None
    assert await async_fakeredis.get(other_key) == b"1"
    assert await async_fakeredis.exists(index_key) == 0


async def test_redis_strategy_issue_totp_stepup_non_positive_ttl_deletes_marker_and_index_entry(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """A non-positive TOTP step-up TTL removes an existing marker and index entry."""
    _disable_optional_import(monkeypatch)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
        ),
    )
    user = ExampleUser(id=uuid4())

    await strategy.issue_totp_stepup(user, "session-a", ttl_seconds=FIVE_MINUTES_TTL_SECONDS)
    await strategy.issue_totp_stepup(user, "session-a", ttl_seconds=0)

    marker_key = strategy._totp_stepup_key(str(user.id), "session-a")
    index_key = strategy._totp_stepup_index_key(str(user.id))
    assert await async_fakeredis.get(marker_key) is None
    assert await async_fakeredis.smembers(index_key) == set()


async def test_redis_strategy_invalidate_all_tokens_without_index_rejects_orphaned_tokens(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """invalidate_all_tokens() should reject orphaned tokens even when the per-user index is missing."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(redis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            subject_decoder=UUID,
        ),
    )
    user = ExampleUser(id=uuid4())
    other_user = ExampleUser(id=uuid4())
    matching_key_one = strategy._key("orphan-a")
    matching_key_two = strategy._key("orphan-b")
    foreign_key = strategy._key("orphan-other")
    ignored_prefix_key = "other-prefix:orphan-ignored"

    assert await redis.set(matching_key_one, f"v1:0:{user.id}") is True
    assert await redis.set(matching_key_two, f"v1:0:{user.id}") is True
    assert await redis.set(foreign_key, f"v1:0:{other_user.id}") is True
    assert await redis.set(ignored_prefix_key, str(user.id)) is True

    await strategy.invalidate_all_tokens(user)

    assert await redis.get(matching_key_one) == f"v1:0:{user.id}"
    assert await redis.get(matching_key_two) == f"v1:0:{user.id}"
    assert await redis.get(foreign_key) == f"v1:0:{other_user.id}"
    assert await redis.get(ignored_prefix_key) == str(user.id)
    await _assert_invalid(strategy, "orphan-a", ExampleUserManager(user))
    await _assert_invalid(strategy, "orphan-b", ExampleUserManager(user))
    assert await _authenticated_user(strategy, "orphan-other", ExampleUserManager(other_user)) == other_user


async def test_redis_strategy_write_token_after_invalidation_uses_current_epoch(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Tokens issued after invalidate_all_tokens() should validate against the bumped epoch."""
    _disable_optional_import(monkeypatch)
    token_values = iter(["token-before", "token-after"])
    monkeypatch.setattr(
        opaque_tokens_module.secrets,
        "token_urlsafe",
        lambda _nbytes: next(token_values),
    )
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            token_bytes=16,
            subject_decoder=UUID,
        ),
    )

    before_token = await strategy.write_token(user)
    await strategy.invalidate_all_tokens(user)
    after_token = await strategy.write_token(user)

    await _assert_invalid(strategy, before_token, user_manager)
    assert await _authenticated_user(strategy, after_token, user_manager) == user


async def test_redis_refresh_rotation_revokes_access_and_replay_revokes_chain(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Redis refresh rotation is single-use and replay revokes the whole session."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    user = ExampleUser(id=uuid4())
    manager = ExampleUserManager(user)
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(redis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    first_refresh = await strategy.write_refresh_token(user)
    session_id = await strategy.identify_refresh_session(user, first_refresh)
    assert session_id is not None
    first_access = await strategy.write_token_for_session(user, session_id)

    rotation = await strategy.rotate_refresh_token(first_refresh, manager)
    assert rotation is not None
    _, second_refresh = rotation
    await _assert_invalid(strategy, first_access, manager)
    second_access = await strategy.write_token_for_session(user, session_id)
    assert await _authenticated_user(strategy, second_access, manager) == user

    assert await strategy.rotate_refresh_token(first_refresh, manager) is None
    assert await strategy.identify_refresh_session(user, second_refresh) is None
    await _assert_invalid(strategy, second_access, manager)


async def test_redis_refresh_session_management_is_user_scoped(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Listing and targeted revocation never cross user ownership."""
    _disable_optional_import(monkeypatch)
    redis = async_fakeredis_factory(decode_responses=True)
    user = ExampleUser(id=uuid4())
    foreign_user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=cast_fakeredis(redis, RedisClientProtocol),
        token_hash_secret=TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    first = await strategy.write_refresh_token(user)
    second = await strategy.write_refresh_token(user)
    foreign = await strategy.write_refresh_token(foreign_user)
    first_id = await strategy.identify_refresh_session(user, first)
    second_id = await strategy.identify_refresh_session(user, second)
    foreign_id = await strategy.identify_refresh_session(foreign_user, foreign)
    assert first_id is not None
    assert second_id is not None
    assert foreign_id is not None
    with pytest.raises(ValueError, match="inactive refresh session"):
        await strategy.write_token_for_session(user, foreign_id)
    assert await strategy.revoke_refresh_session(user, foreign_id) is False
    assert await strategy.revoke_other_refresh_sessions(user, current_session_id=second_id) == 1
    assert [session.session_id for session in await strategy.list_refresh_sessions(user)] == [second_id]
    assert [session.session_id for session in await strategy.list_refresh_sessions(foreign_user)] == [foreign_id]
