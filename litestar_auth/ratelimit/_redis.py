"""Redis-backed rate-limiter backend."""

from __future__ import annotations

import time
from functools import partial
from typing import TYPE_CHECKING
from uuid import uuid4

from litestar_auth._clock import Clock, read_clock
from litestar_auth._optional_deps import _require_redis_asyncio

from ._key_derivation import DEFAULT_ACCOUNT_LOCKOUT_KEY_PREFIX, DEFAULT_KEY_PREFIX
from ._validation import RedisScriptResult, _validate_account_lockout_configuration, _validate_configuration

if TYPE_CHECKING:
    from ._protocol import AccountLockoutKey, RedisClientProtocol

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisRateLimiter")
_load_account_lockout_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisAccountLockoutStore")


def _decode_integer(value: RedisScriptResult) -> int:
    """Normalize Redis script results to integers.

    Returns:
        The decoded integer value.
    """
    if isinstance(value, bytes):
        value = value.decode()
    return int(value)


class RedisAccountLockoutStore:
    """Redis-backed per-account lockout store backed by expiring counters."""

    _REGISTER_FAILURE_SCRIPT = """
local key = KEYS[1]
local ttl = tonumber(ARGV[1])

local count = redis.call("INCR", key)
redis.call("EXPIRE", key, ttl)

return count
"""
    _IS_LOCKED_SCRIPT = """
local key = KEYS[1]
local failure_threshold = tonumber(ARGV[1])

local count = redis.call("GET", key)
if count == false then
    return 0
end

if tonumber(count) >= failure_threshold then
    return 1
end
return 0
"""

    def __init__(
        self,
        *,
        redis: RedisClientProtocol,
        failure_threshold: int,
        window_seconds: float,
        key_prefix: str = DEFAULT_ACCOUNT_LOCKOUT_KEY_PREFIX,
    ) -> None:
        """Store the Redis client and shared lockout configuration."""
        _load_account_lockout_redis_asyncio()
        _validate_account_lockout_configuration(
            failure_threshold=failure_threshold,
            window_seconds=window_seconds,
        )

        self.redis = redis
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix

    def _key(self, key: AccountLockoutKey) -> str:
        """Return the namespaced Redis key for ``key``."""
        return f"{self.key_prefix}{key}"

    @property
    def is_shared_across_workers(self) -> bool:
        """Redis-backed lockout counters are shared across workers using the same Redis."""
        return True

    @property
    def _ttl_seconds(self) -> int:
        """The lockout window in whole seconds for Redis ``EXPIRE``.

        Redis key expiry is second-granular, so the window is floored to whole seconds
        (minimum 1). Sub-second ``window_seconds`` therefore round to 1s here, unlike the
        float-precise :class:`InMemoryAccountLockoutStore`; with the 900s default and any
        realistic lockout window the two backends are equivalent.
        """
        return max(int(self.window_seconds), 1)

    async def _eval(self, script: str, key: AccountLockoutKey, *args: object) -> RedisScriptResult:
        """Execute a single-key Lua script against Redis.

        Returns:
            The scalar result returned by Redis.
        """
        return await self.redis.eval(script, 1, self._key(key), *args)

    async def register_failure(self, key: AccountLockoutKey) -> int:
        """Record a failed password-login attempt atomically and return its count.

        Returns:
            Current active failure count for ``key``.
        """
        return _decode_integer(await self._eval(self._REGISTER_FAILURE_SCRIPT, key, self._ttl_seconds))

    async def is_locked(self, key: AccountLockoutKey) -> bool:
        """Return whether ``key`` is locked in the current Redis TTL window."""
        return _decode_integer(await self._eval(self._IS_LOCKED_SCRIPT, key, self.failure_threshold)) == 1

    async def reset(self, key: AccountLockoutKey) -> None:
        """Delete the Redis counter for ``key``."""
        await self.redis.delete(self._key(key))


class RedisRateLimiter:
    """Redis-backed sliding-window rate limiter backed by a sorted set."""

    _CHECK_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_attempts = tonumber(ARGV[3])
local cutoff = now - window

redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
local count = redis.call("ZCARD", key)
if count == 0 then
    redis.call("DEL", key)
end

return count
"""
    _INCREMENT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local member = ARGV[3]
local ttl = tonumber(ARGV[4])
local cutoff = now - window

redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
redis.call("ZADD", key, now, member)
redis.call("EXPIRE", key, ttl)

return redis.call("ZCARD", key)
"""
    _RETRY_AFTER_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_attempts = tonumber(ARGV[3])
local cutoff = now - window

redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)
local count = redis.call("ZCARD", key)
if count == 0 then
    redis.call("DEL", key)
    return 0
end
if count < max_attempts then
    return 0
end

local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
if #oldest == 0 then
    return 0
end

local score_raw
if type(oldest[1]) == "table" then
    -- fakeredis (and some nested RESP3 paths) return one [[member, score]] row.
    score_raw = oldest[1][2]
else
    if #oldest < 2 then
        return 0
    end
    score_raw = oldest[2]
end
if score_raw == nil then
    return 0
end

-- Keep this policy aligned with ratelimit._window_math.retry_seconds:
-- an active full window reports at least one whole retry second.
return math.max(math.ceil(window - (now - tonumber(score_raw))), 1)
"""

    def __init__(
        self,
        *,
        redis: RedisClientProtocol,
        max_attempts: int,
        window_seconds: float,
        key_prefix: str = DEFAULT_KEY_PREFIX,
        clock: Clock = time.time,
    ) -> None:
        """Store the Redis client and shared rate-limiter configuration."""
        _load_redis_asyncio()
        _validate_configuration(max_attempts=max_attempts, window_seconds=window_seconds)

        self.redis = redis
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix
        self._clock: Clock = clock

    def _key(self, key: str) -> str:
        """Return the namespaced Redis key for ``key``."""
        return f"{self.key_prefix}{key}"

    @property
    def is_shared_across_workers(self) -> bool:
        """Redis-backed counters are shared across workers using the same Redis."""
        return True

    @property
    def _ttl_seconds(self) -> int:
        """The configured window in whole seconds."""
        return max(int(self.window_seconds), 1)

    async def _eval(self, script: str, key: str, *args: object) -> RedisScriptResult:
        """Execute a single-key Lua script against Redis.

        Returns:
            The scalar result returned by Redis.
        """
        return await self.redis.eval(script, 1, self._key(key), *args)

    async def check(self, key: str) -> bool:
        """Return whether ``key`` can perform another attempt."""
        count = _decode_integer(
            await self._eval(
                self._CHECK_SCRIPT,
                key,
                read_clock(self._clock),
                self.window_seconds,
                self.max_attempts,
            ),
        )
        return count < self.max_attempts

    async def increment(self, key: str) -> None:
        """Record a new attempt for ``key`` atomically in Redis."""
        now = read_clock(self._clock)
        await self._eval(
            self._INCREMENT_SCRIPT,
            key,
            now,
            self.window_seconds,
            f"{now:.9f}:{uuid4().hex}",
            self._ttl_seconds,
        )

    async def reset(self, key: str) -> None:
        """Delete the Redis sorted set for ``key``."""
        await self.redis.delete(self._key(key))

    async def retry_after(self, key: str) -> int:
        """Return the remaining block duration for ``key`` in whole seconds."""
        return max(
            _decode_integer(
                await self._eval(
                    self._RETRY_AFTER_SCRIPT,
                    key,
                    read_clock(self._clock),
                    self.window_seconds,
                    self.max_attempts,
                ),
            ),
            0,
        )
