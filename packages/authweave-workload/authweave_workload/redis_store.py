"""Optional Redis-backed introspection cache and DPoP replay/nonce stores."""

from __future__ import annotations

import secrets

from authweave_core import ReplayOutcome, validate_replay_key

_MAX_INTROSPECTION_CACHE_BYTES = 65_536


class RedisIntrospectionCache:
    """Thin Redis adapter for issuer-digested introspection snapshots."""

    __slots__ = ("_redis",)

    def __init__(self, redis: object) -> None:
        """Bind an async Redis client exposing ``get`` and ``set``."""
        self._redis = redis

    async def get(self, key: str) -> bytes | None:
        """Read one bounded claim snapshot.

        Returns:
            Cached bytes or ``None``.
        """
        try:
            value = await self._redis.get(key)  # ty: ignore[unresolved-attribute]
        except Exception as exc:
            msg = "introspection cache unavailable"
            raise RuntimeError(msg) from exc
        if value is None:
            return None
        if isinstance(value, str):
            value = value.encode()
        if not isinstance(value, bytes) or len(value) > _MAX_INTROSPECTION_CACHE_BYTES:
            msg = "introspection cache value is invalid"
            raise ValueError(msg)
        return value

    async def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
        """Store one bounded claim snapshot with an explicit TTL."""
        if not key.startswith("authweave:introspection:") or not 0 < len(value) <= _MAX_INTROSPECTION_CACHE_BYTES:
            msg = "introspection cache entry is invalid"
            raise ValueError(msg)
        if ttl_seconds < 1:
            msg = "introspection cache TTL must be positive"
            raise ValueError(msg)
        try:
            await self._redis.set(key, value, ex=ttl_seconds)  # ty: ignore[unresolved-attribute]
        except Exception as exc:
            msg = "introspection cache unavailable"
            raise RuntimeError(msg) from exc


class RedisDPoPReplayStore:
    """Thin Redis SET NX EX adapter for DPoP proof ``jti`` replay.

    Requires the ``authweave-workload[redis]`` extra. Connection failures map to
    ``Unavailable`` so protected routes fail closed.
    """

    __slots__ = ("_redis",)

    def __init__(self, redis: object) -> None:
        """Bind an async Redis client exposing ``set(name, value, nx=True, ex=...)``."""
        self._redis = redis

    async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
        """Atomically claim ``key`` with a TTL.

        Returns:
            The typed put-if-absent outcome.

        Raises:
            ValueError: If the key or TTL is invalid.
        """
        validate_replay_key(key)
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        try:
            created = await self._redis.set(  # ty: ignore[unresolved-attribute]
                key,
                "1",
                nx=True,
                ex=max(1, int(ttl_seconds)),
            )
        except Exception:  # ruff: ignore[blind-except] - any client/transport failure is Unavailable
            return ReplayOutcome.UNAVAILABLE
        return ReplayOutcome.STORED if created else ReplayOutcome.REPLAY


class RedisDPoPNonceStore:
    """Redis-backed opaque DPoP nonce issuer/consumer.

    Requires the ``authweave-workload[redis]`` extra.
    """

    __slots__ = ("_redis", "_ttl_seconds")

    def __init__(self, redis: object, *, ttl_seconds: int = 120) -> None:
        """Bind Redis and a bounded nonce lifetime.

        Raises:
            ValueError: If ``ttl_seconds`` is not positive.
        """
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        self._redis = redis
        self._ttl_seconds = ttl_seconds

    async def issue(self, *, origin: str, jkt: str) -> str:
        """Issue one opaque nonce scoped to an origin and proof key.

        Returns:
            The opaque nonce string.

        Raises:
            RuntimeError: If Redis cannot store the nonce.
        """
        nonce_text = secrets.token_urlsafe(32)
        key = f"dpop-nonce:{origin}:{jkt}:{nonce_text}"
        try:
            created = await self._redis.set(key, "1", nx=True, ex=self._ttl_seconds)  # ty: ignore[unresolved-attribute]
        except Exception as exc:
            msg = "nonce store unavailable"
            raise RuntimeError(msg) from exc
        if not created:
            msg = "nonce collision"
            raise RuntimeError(msg)
        return nonce_text

    async def consume(self, *, origin: str, jkt: str, nonce: str) -> ReplayOutcome:
        """Consume one previously issued nonce exactly once.

        Returns:
            The typed outcome for the nonce claim.
        """
        key = f"dpop-nonce:{origin}:{jkt}:{nonce}"
        try:
            deleted = await self._redis.delete(key)  # ty: ignore[unresolved-attribute]
        except Exception:  # ruff: ignore[blind-except] - any client/transport failure is Unavailable
            return ReplayOutcome.UNAVAILABLE
        return ReplayOutcome.STORED if deleted else ReplayOutcome.REPLAY


__all__ = ("RedisDPoPNonceStore", "RedisDPoPReplayStore", "RedisIntrospectionCache")
