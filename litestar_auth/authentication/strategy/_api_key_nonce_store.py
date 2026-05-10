"""Nonce stores for API-key request signing."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from litestar_auth._clock import Clock, read_clock
from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._redis_protocols import RedisConditionalSetClient

DEFAULT_API_KEY_NONCE_PREFIX = "litestar_auth:api_key:nonce:"


@dataclass(frozen=True, slots=True)
class ApiKeyNonceStoreResult:
    """Outcome of recording a request-signing nonce."""

    stored: bool
    rejected_as_replay: bool = False


@runtime_checkable
class ApiKeyNonceStore(Protocol):
    """Persistence contract for API-key signing nonces."""

    async def mark_used(self, *, key_id: str, nonce: str, ttl_seconds: int) -> ApiKeyNonceStoreResult:
        """Record ``nonce`` for ``key_id`` if it was not already seen."""


class RedisApiKeyNonceStoreClient(RedisConditionalSetClient, Protocol):
    """Minimal Redis client for API-key signing nonce storage."""


class RedisApiKeyNonceStore:
    """Redis-backed API-key signing nonce store."""

    def __init__(
        self,
        *,
        redis: RedisApiKeyNonceStoreClient,
        key_prefix: str = DEFAULT_API_KEY_NONCE_PREFIX,
    ) -> None:
        """Store the Redis client and key namespace."""
        _require_redis_asyncio(feature_name="RedisApiKeyNonceStore")
        self._redis = redis
        self._key_prefix = key_prefix

    @property
    def is_shared_across_workers(self) -> bool:
        """Redis state is shared across workers using the same server."""
        return True

    def _key(self, key_id: str, nonce: str) -> str:
        return f"{self._key_prefix}{key_id}:{nonce}"

    async def mark_used(self, *, key_id: str, nonce: str, ttl_seconds: int) -> ApiKeyNonceStoreResult:
        """Atomically record a nonce with ``SET NX PX``.

        Returns:
            Stored/replay outcome for the nonce insert.
        """
        result = await self._redis.set(self._key(key_id, nonce), "1", nx=True, px=max(ttl_seconds, 1) * 1000)
        if result is True:
            return ApiKeyNonceStoreResult(stored=True)
        return ApiKeyNonceStoreResult(stored=False, rejected_as_replay=True)


class InMemoryApiKeyNonceStore:
    """Async-safe process-local API-key signing nonce store."""

    def __init__(self, *, clock: Clock = time.monotonic, max_entries: int = 50_000) -> None:
        """Initialize an empty nonce cache.

        Raises:
            ValueError: If ``max_entries`` is less than one.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1."
            raise ValueError(msg)
        self._clock = clock
        self.max_entries = max_entries
        self._entries: dict[tuple[str, str], float] = {}
        self._lock = asyncio.Lock()

    @property
    def is_shared_across_workers(self) -> bool:
        """In-memory state is process-local."""
        return False

    async def mark_used(self, *, key_id: str, nonce: str, ttl_seconds: int) -> ApiKeyNonceStoreResult:
        """Record a nonce until TTL expiry, rejecting replays fail-closed.

        Returns:
            Stored/replay outcome for the nonce insert.
        """
        async with self._lock:
            now = read_clock(self._clock)
            self._prune(now)
            key = (key_id, nonce)
            if key in self._entries:
                return ApiKeyNonceStoreResult(stored=False, rejected_as_replay=True)
            if len(self._entries) >= self.max_entries:
                return ApiKeyNonceStoreResult(stored=False, rejected_as_replay=False)
            self._entries[key] = now + ttl_seconds
            return ApiKeyNonceStoreResult(stored=True)

    def _prune(self, now: float) -> None:
        for key in [key for key, expires_at in self._entries.items() if expires_at <= now]:
            del self._entries[key]


__all__ = (
    "ApiKeyNonceStore",
    "ApiKeyNonceStoreResult",
    "InMemoryApiKeyNonceStore",
    "RedisApiKeyNonceStore",
    "RedisApiKeyNonceStoreClient",
)
