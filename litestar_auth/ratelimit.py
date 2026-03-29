"""Rate-limiting backends for authentication endpoints."""

from __future__ import annotations

import asyncio
import hashlib
import importlib as _importlib
import logging
import math
import time
from collections import deque
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self, runtime_checkable
from uuid import uuid4

from litestar.exceptions import TooManyRequestsException

from litestar_auth._compat import _load_redis_asyncio as _load_redis_asyncio_compat
from litestar_auth.config import resolve_trusted_proxy_setting

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from litestar.connection import Request

type SlidingWindow = deque[float]
type RedisScriptResult = bytes | str | int | float

DEFAULT_KEY_PREFIX = "litestar_auth:ratelimit:"
logger = logging.getLogger(__name__)

_load_redis_asyncio = partial(_load_redis_asyncio_compat, feature_name="RedisRateLimiter")
importlib = _importlib


def _validate_configuration(*, max_attempts: int, window_seconds: float) -> None:
    """Validate shared rate-limiter settings.

    Raises:
        ValueError: If ``max_attempts`` or ``window_seconds`` is invalid.
    """
    if max_attempts < 1:
        msg = "max_attempts must be at least 1"
        raise ValueError(msg)
    if window_seconds <= 0:
        msg = "window_seconds must be greater than 0"
        raise ValueError(msg)


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


class InMemoryRateLimiter:
    """Async-safe in-memory sliding-window rate limiter.

    Not safe for multi-process or multi-host deployments; use :class:`RedisRateLimiter`
    for shared storage (e.g. multi-worker or multi-pod).
    """

    def __init__(
        self,
        *,
        max_attempts: int,
        window_seconds: float,
        max_keys: int = 100_000,
        sweep_interval: int = 1_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Store the limiter configuration and request counters.

        Raises:
            ValueError: If any limiter or storage configuration is invalid.
        """
        _validate_configuration(max_attempts=max_attempts, window_seconds=window_seconds)
        if max_keys < 1:
            msg = "max_keys must be at least 1"
            raise ValueError(msg)
        if sweep_interval < 1:
            msg = "sweep_interval must be at least 1"
            raise ValueError(msg)

        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.sweep_interval = sweep_interval
        self._clock = clock
        self._lock = asyncio.Lock()
        self._windows: dict[str, SlidingWindow] = {}
        self._operation_count = 0

    @property
    def is_shared_across_workers(self) -> bool:
        """In-memory counters are process-local and not shared across workers."""
        return False

    async def check(self, key: str) -> bool:
        """Return whether ``key`` can perform another attempt."""
        async with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            timestamps = self._prune(key, now)
            if timestamps is None:
                return True

            return len(timestamps) < self.max_attempts

    async def increment(self, key: str) -> None:
        """Record a new attempt for ``key`` in the current window."""
        async with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            timestamps = self._prune(key, now)
            if timestamps is None:
                self._evict_oldest_keys()
                timestamps = deque()
                self._windows[key] = timestamps

            timestamps.append(now)

    async def reset(self, key: str) -> None:
        """Clear the in-memory counter for ``key``."""
        async with self._lock:
            self._windows.pop(key, None)

    async def retry_after(self, key: str) -> int:
        """Return the remaining block duration for ``key`` in whole seconds."""
        async with self._lock:
            now = self._clock()
            timestamps = self._prune(key, now)
            if timestamps is None or len(timestamps) < self.max_attempts:
                return 0

            oldest_timestamp = timestamps[0]
            remaining = self.window_seconds - (now - oldest_timestamp)
            return max(math.ceil(remaining), 1)

    def _prune(self, key: str, now: float) -> SlidingWindow | None:
        """Remove expired timestamps for ``key`` and return active entries.

        Returns:
            Active timestamps for ``key`` or ``None`` when the window is empty.
        """
        timestamps = self._windows.get(key)
        if timestamps is None:
            return None

        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if not timestamps:
            self._windows.pop(key, None)
            return None

        return timestamps

    def _maybe_sweep(self, now: float) -> None:
        """Run periodic global pruning based on the configured sweep interval."""
        self._operation_count += 1
        if self._operation_count % self.sweep_interval == 0:
            self._sweep_all(now)

    def _sweep_all(self, now: float) -> None:
        """Prune all keys and drop globally expired windows."""
        for key in tuple(self._windows):
            self._prune(key, now)

    def _evict_oldest_keys(self) -> None:
        """Keep the tracked-key count below the configured cap.

        Evicts the least-recently-active key (earliest last timestamp)
        rather than the first-inserted key, preventing attackers from
        resetting their own rate-limit window through eviction pressure.
        """
        while len(self._windows) >= self.max_keys:
            lru_key = min(self._windows, key=lambda k: self._windows[k][-1] if self._windows[k] else 0.0)
            del self._windows[lru_key]


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
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Store the Redis client and shared rate-limiter configuration."""
        _load_redis_asyncio()
        _validate_configuration(max_attempts=max_attempts, window_seconds=window_seconds)

        self.redis = redis
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix
        self._clock = clock

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
                self._clock(),
                self.window_seconds,
                self.max_attempts,
            ),
        )
        return count < self.max_attempts

    async def increment(self, key: str) -> None:
        """Record a new attempt for ``key`` atomically in Redis."""
        now = self._clock()
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
                    self._clock(),
                    self.window_seconds,
                    self.max_attempts,
                ),
            ),
            0,
        )


type RateLimitScope = Literal["ip", "ip_email"]
type TotpSensitiveEndpoint = Literal["enable", "confirm_enable", "verify", "disable"]


_DEFAULT_TRUSTED_HEADERS: tuple[str, ...] = ("X-Forwarded-For",)


@dataclass(slots=True, frozen=True)
class EndpointRateLimit:
    """Per-endpoint rate-limit settings and request hook."""

    backend: RateLimiterBackend
    scope: RateLimitScope
    namespace: str
    trusted_proxy: bool = False
    identity_fields: tuple[str, ...] = ("identifier", "username", "email")
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS

    async def before_request(self, request: Request[Any, Any, Any]) -> None:
        """Reject the request with 429 when its key is over the configured limit.

        Security:
            Only set ``trusted_proxy=True`` when this service is behind a trusted
            proxy or load balancer that overwrites client IP headers. Otherwise,
            attackers can spoof headers like ``X-Forwarded-For`` and evade or
            poison rate-limiting keys.

        Raises:
            TooManyRequestsException: If the request exceeded the configured limit.
        """
        key = await self.build_key(request)
        if await self.backend.check(key):
            return

        retry_after = await self.backend.retry_after(key)
        logger.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_triggered",
                "namespace": self.namespace,
                "scope": self.scope,
                "trusted_proxy": self.trusted_proxy,
            },
        )
        msg = "Too many requests."
        raise TooManyRequestsException(
            detail=msg,
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    async def increment(self, request: Request[Any, Any, Any]) -> None:
        """Record a failed or rate-limited attempt for the current request."""
        await self.backend.increment(await self.build_key(request))

    async def reset(self, request: Request[Any, Any, Any]) -> None:
        """Clear stored attempts for the current request key."""
        await self.backend.reset(await self.build_key(request))

    async def build_key(self, request: Request[Any, Any, Any]) -> str:
        """Build the backend key for the given request.

        Returns:
            Namespaced rate-limit key for the request.
        """
        host = _client_host(request, trusted_proxy=self.trusted_proxy, trusted_headers=self.trusted_headers)
        parts = [self.namespace, _safe_key_part(host)]
        if self.scope == "ip_email":
            email = await _extract_email(request, identity_fields=self.identity_fields)
            if email:
                parts.append(_safe_key_part(email.strip().casefold()))

        return ":".join(parts)


@dataclass(slots=True, frozen=True)
class AuthRateLimitConfig:
    """Optional rate-limit rules for auth-related endpoints."""

    login: EndpointRateLimit | None = None
    refresh: EndpointRateLimit | None = None
    register: EndpointRateLimit | None = None
    forgot_password: EndpointRateLimit | None = None
    reset_password: EndpointRateLimit | None = None
    totp_enable: EndpointRateLimit | None = None
    totp_confirm_enable: EndpointRateLimit | None = None
    totp_verify: EndpointRateLimit | None = None
    totp_disable: EndpointRateLimit | None = None
    verify_token: EndpointRateLimit | None = None
    request_verify_token: EndpointRateLimit | None = None


@dataclass(slots=True, frozen=True)
class TotpRateLimitOrchestrator:
    """Orchestrate TOTP endpoint rate-limit behavior with explicit semantics.

    External behavior stays unchanged:
    - ``verify`` uses before-request checks, increments on invalid attempts, and
      resets on success/account-state failures.
    - ``enable`` and ``disable`` do not consume verify counters.

    Endpoints that should reset on account-state failures are listed in
    ``_ACCOUNT_STATE_RESET_ENDPOINTS`` (currently only ``verify``).
    """

    enable: EndpointRateLimit | None = None
    confirm_enable: EndpointRateLimit | None = None
    verify: EndpointRateLimit | None = None
    disable: EndpointRateLimit | None = None

    _ACCOUNT_STATE_RESET_ENDPOINTS: frozenset[TotpSensitiveEndpoint] = frozenset({"verify"})

    @property
    def _limiters(self) -> dict[TotpSensitiveEndpoint, EndpointRateLimit]:
        return {
            ep: limiter
            for ep, limiter in (
                ("enable", self.enable),
                ("confirm_enable", self.confirm_enable),
                ("verify", self.verify),
                ("disable", self.disable),
            )
            if limiter is not None
        }

    async def before_request(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Run endpoint-specific before-request checks."""
        if limiter := self._limiters.get(endpoint):
            await limiter.before_request(request)

    async def on_invalid_attempt(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Record endpoint-specific invalid attempt failures."""
        if limiter := self._limiters.get(endpoint):
            await limiter.increment(request)

    async def on_account_state_failure(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Apply endpoint-specific account-state failure behavior."""
        if endpoint in self._ACCOUNT_STATE_RESET_ENDPOINTS and (limiter := self._limiters.get(endpoint)):
            await limiter.reset(request)

    async def on_success(self, endpoint: TotpSensitiveEndpoint, request: Request[Any, Any, Any]) -> None:
        """Apply endpoint-specific success behavior."""
        if limiter := self._limiters.get(endpoint):
            await limiter.reset(request)


def _safe_key_part(value: str) -> str:
    """Hash a key component to prevent delimiter injection and collisions.

    Returns:
        Truncated SHA-256 hex digest of the value.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _client_host(
    request: Request[Any, Any, Any],
    *,
    trusted_proxy: bool = False,
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
) -> str:
    """Return the remote host for a request, or a stable fallback.

    Args:
        request: Incoming HTTP request.
        trusted_proxy: Whether to read client IP from proxy headers.
        trusted_headers: Ordered header names to consult when ``trusted_proxy``
            is ``True``.  Only headers your reverse proxy explicitly sets should
            be listed; defaults to ``("X-Forwarded-For",)`` to match common
            single-proxy deployments and avoid trusting provider-specific
            headers the proxy does not control.
    """

    def fallback_host() -> str:
        client = request.client
        if client is None or not client.host:
            return "unknown"
        return client.host

    if not resolve_trusted_proxy_setting(trusted_proxy=trusted_proxy):
        return fallback_host()

    headers = request.headers
    for header_name in trusted_headers:
        raw_value = headers.get(header_name) or headers.get(header_name.lower())
        if not raw_value:
            continue

        value = raw_value.strip()
        if not value:
            continue

        if header_name.lower() == "x-forwarded-for":
            value = value.split(",", 1)[0].strip()
            if not value:
                continue

        return value

    return fallback_host()


async def _extract_email(
    request: Request[Any, Any, Any],
    *,
    identity_fields: tuple[str, ...] = ("identifier", "username", "email"),
) -> str | None:
    """Best-effort extraction of identifier from a JSON request body.

    Searches through ``identity_fields`` in order, returning the first
    non-empty string value found.  Defaults to the login schema's
    ``identifier`` / ``username`` / ``email`` keys.

    Returns:
        The raw string value when present, otherwise ``None``.
    """
    try:
        payload = await request.json()
    except (TypeError, ValueError):
        return None

    if not isinstance(payload, dict):
        return None

    for field_name in identity_fields:
        value = payload.get(field_name)
        if isinstance(value, str) and value:
            return value
    return None
