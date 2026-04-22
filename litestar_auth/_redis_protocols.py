"""Internal shared typing vocabulary for optional async Redis integrations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

type RedisKey = str
type RedisStoredValue = bytes | str
type RedisStoredMembers = set[bytes] | set[str]
type RedisDeleteCount = int
type RedisSetIfMissingResult = bool | None
type RedisTTLSeconds = int
type RedisTTLMilliseconds = int | None
type RedisScanPattern = str | None
type RedisEvalResult = bytes | str | int | float
type RedisNullableEvalResult = RedisEvalResult | None


class RedisDeleteClient(Protocol):
    """Async Redis client supporting key deletion."""

    async def delete(self, *names: RedisKey) -> RedisDeleteCount:
        """Delete one or more Redis keys."""


class RedisValueReadClient(Protocol):
    """Async Redis client supporting string-like value reads."""

    async def get(self, name: RedisKey, /) -> RedisStoredValue | None:
        """Return the stored value for a Redis key."""


class RedisConditionalSetClient(Protocol):
    """Async Redis client supporting ``SET`` with ``NX``/``PX`` options."""

    async def set(
        self,
        name: RedisKey,
        value: str,
        *,
        nx: bool = False,
        px: RedisTTLMilliseconds = None,
    ) -> RedisSetIfMissingResult:
        """Set a key, optionally requiring absence and/or a millisecond TTL."""


class RedisExpiringValueWriteClient(Protocol):
    """Async Redis client supporting ``SETEX`` writes."""

    async def setex(self, name: RedisKey, time: RedisTTLSeconds, value: str, /) -> object:
        """Store a Redis value with an expiration time in seconds."""


class RedisExpiringValueStoreClient(RedisValueReadClient, RedisExpiringValueWriteClient, Protocol):
    """Async Redis client supporting string reads plus expiring string writes."""


class RedisScriptEvalClient(Protocol):
    """Async Redis client supporting Lua script evaluation."""

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> RedisEvalResult:
        """Execute a Redis Lua script and return its scalar result."""


class RedisNullableScriptEvalClient(Protocol):
    """Async Redis client supporting Lua script evaluation that may return Redis nil."""

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> RedisNullableEvalResult:
        """Execute a Redis Lua script and return its nullable scalar result."""


class RedisRateLimiterClient(RedisDeleteClient, RedisScriptEvalClient, Protocol):
    """Internal async Redis client supporting the ``RedisRateLimiter`` contract."""


@runtime_checkable
class RedisSharedAuthClient(
    RedisRateLimiterClient,
    RedisConditionalSetClient,
    RedisExpiringValueStoreClient,
    Protocol,
):
    """Internal composite client backing the public contrib auth Redis protocol."""


class RedisSetMembershipClient(Protocol):
    """Async Redis client supporting set membership mutations and reads."""

    async def sadd(self, name: RedisKey, *values: str) -> int:
        """Add one or more values to a Redis set."""

    async def srem(self, name: RedisKey, *values: str) -> int:
        """Remove one or more values from a Redis set."""

    async def smembers(self, name: RedisKey) -> RedisStoredMembers:
        """Return all members of a Redis set."""


class RedisKeyExpiryClient(Protocol):
    """Async Redis client supporting TTL updates."""

    async def expire(self, name: RedisKey, time: RedisTTLSeconds) -> bool:
        """Set the TTL for a key in seconds."""


class RedisScanClient(Protocol):
    """Async Redis client supporting keyspace iteration."""

    def scan_iter(
        self,
        match: RedisScanPattern = None,
        count: int | None = None,
        _type: str | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> AsyncIterator[str]:
        """Iterate over Redis keys matching a pattern."""
