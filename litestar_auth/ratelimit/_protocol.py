"""Protocols shared by rate-limiter backends."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, Self, runtime_checkable

if TYPE_CHECKING:
    from types import TracebackType

    from ._helpers import RedisScriptResult


class RedisPipelineProtocol(Protocol):
    """Minimal async Redis pipeline used by the rate limiter."""

    async def __aenter__(self) -> Self:
        """Enter the async pipeline context.

        Returns:
            The pipeline instance.
        """

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Exit the async pipeline context."""

    def incr(self, name: str, amount: int = 1) -> Self:
        """Increment a Redis counter.

        Returns:
            The pipeline instance.
        """

    def expire(self, name: str, time: int, *, nx: bool = False) -> Self:
        """Set a TTL on a Redis key.

        Returns:
            The pipeline instance.
        """

    async def execute(self) -> list[Any]:
        """Execute queued pipeline commands."""


class RedisClientProtocol(Protocol):
    """Minimal async Redis client interface used by the rate limiter."""

    async def delete(self, *names: str) -> int:
        """Delete one or more Redis keys."""

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> RedisScriptResult:
        """Execute a Lua script.

        Returns:
            The scalar result returned by Redis.
        """


@runtime_checkable
class RateLimiterBackend(Protocol):
    """Protocol shared by rate-limiter backends."""

    @property
    def is_shared_across_workers(self) -> bool:
        """Return whether backend state is shared across worker processes."""

    async def check(self, key: str) -> bool:
        """Return whether another attempt is allowed for ``key``."""

    async def increment(self, key: str) -> None:
        """Record an attempt for ``key``."""

    async def reset(self, key: str) -> None:
        """Clear tracked attempts for ``key``."""

    async def retry_after(self, key: str) -> int:
        """Return the number of seconds until ``key`` can try again."""
