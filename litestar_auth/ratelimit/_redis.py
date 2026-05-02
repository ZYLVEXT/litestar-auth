"""Redis-backed rate-limiter backend."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from uuid import uuid4

from litestar_auth._clock import Clock, read_clock

from . import _helpers as helpers_module
from ._helpers import DEFAULT_KEY_PREFIX, RedisScriptResult, _validate_configuration

if TYPE_CHECKING:
    from ._protocol import RedisClientProtocol


def _load_package_redis_asyncio() -> object:
    """Resolve the private shared Redis loader at runtime.

    Looking up the helper module attribute at call time keeps monkeypatches on
    ``litestar_auth.ratelimit._helpers._load_redis_asyncio`` visible to the
    backend without re-exporting that private helper from the public package.

    Returns:
        The object returned by the private helper Redis loader.
    """
    return helpers_module._load_redis_asyncio()  # noqa: SLF001


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
if #oldest < 2 then
    return 0
end

return math.max(math.ceil(window - (now - tonumber(oldest[2]))), 0)
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
        _load_package_redis_asyncio()
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
        """Return the configured window in whole seconds."""
        return max(int(self.window_seconds), 1)

    async def _eval(self, script: str, key: str, *args: object) -> RedisScriptResult:
        """Execute a single-key Lua script against Redis.

        Returns:
            The scalar result returned by Redis.
        """
        return await self.redis.eval(script, 1, self._key(key), *args)

    @staticmethod
    def _decode_integer(value: RedisScriptResult) -> int:
        """Normalize Redis script results to integers.

        Returns:
            The decoded integer value.
        """
        if isinstance(value, bytes):
            value = value.decode()
        return int(value)

    async def check(self, key: str) -> bool:
        """Return whether ``key`` can perform another attempt."""
        count = self._decode_integer(
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
            self._decode_integer(
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
