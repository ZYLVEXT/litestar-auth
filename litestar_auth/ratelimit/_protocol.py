"""Protocols shared by rate-limiter backends."""

from __future__ import annotations

from collections.abc import Mapping  # noqa: TC003
from typing import TYPE_CHECKING, NewType, Protocol, Self, runtime_checkable

from litestar_auth._redis_protocols import (
    RedisDeleteClient,
    RedisKey,
    RedisScriptEvalClient,
    RedisTTLSeconds,
)

if TYPE_CHECKING:
    from types import TracebackType

RateLimitKey = NewType("RateLimitKey", str)
AccountLockoutKey = NewType("AccountLockoutKey", str)
type RedisPipelineExecuteResult = tuple[int, bool]


class RateLimitClientAddress(Protocol):
    """Client address data needed for rate-limit key derivation."""

    @property
    def host(self) -> str | None:
        """Direct client host when the transport exposes one."""
        ...


class KnownRateLimitConnection(Protocol):
    """Minimal request-like surface used by rate-limit key derivation."""

    @property
    def headers(self) -> Mapping[str, str]:
        """Request headers."""

    @property
    def client(self) -> RateLimitClientAddress | None:
        """The direct client address, when Litestar exposes one."""

    @property
    def scope(self) -> Mapping[str, object]:
        """The ASGI connection scope."""

    async def json(self) -> object:
        """Parse and return the request JSON body."""


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

    def incr(self, name: RedisKey, amount: int = 1) -> Self:
        """Increment a Redis counter.

        Returns:
            The pipeline instance.
        """

    def expire(self, name: RedisKey, time: RedisTTLSeconds, *, nx: bool = False) -> Self:
        """Set a TTL on a Redis key.

        Returns:
            The pipeline instance.
        """

    async def execute(self) -> RedisPipelineExecuteResult:
        """Execute queued pipeline commands."""


class RedisClientProtocol(RedisDeleteClient, RedisScriptEvalClient, Protocol):
    """Minimal async Redis client interface used by Redis-backed rate-limit state.

    The higher-level Redis contrib shared-client protocol adds ``set(...)`` on
    top of this contract.
    """


@runtime_checkable
class AccountLockoutStore(Protocol):
    """Protocol shared by per-account lockout stores."""

    @property
    def is_shared_across_workers(self) -> bool:
        """Whether store state is shared across worker processes."""

    async def register_failure(self, key: AccountLockoutKey) -> int:
        """Record a failed password-login attempt and return the current count."""

    async def is_locked(self, key: AccountLockoutKey) -> bool:
        """Return whether the account key is currently locked."""

    async def reset(self, key: AccountLockoutKey) -> None:
        """Clear tracked failures for the account key."""


@runtime_checkable
class RateLimiterBackend(Protocol):
    """Protocol shared by rate-limiter backends."""

    @property
    def is_shared_across_workers(self) -> bool:
        """Whether backend state is shared across worker processes."""

    async def check(self, key: RateLimitKey) -> bool:
        """Return whether another attempt is allowed for ``key``."""

    async def increment(self, key: RateLimitKey) -> None:
        """Record an attempt for ``key``."""

    async def reset(self, key: RateLimitKey) -> None:
        """Clear tracked attempts for ``key``."""

    async def retry_after(self, key: RateLimitKey) -> int:
        """Return the number of seconds until ``key`` can try again."""
