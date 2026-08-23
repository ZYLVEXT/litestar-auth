"""Optional Redis-backed signature nonce replay store."""

from __future__ import annotations

from authweave_core import AsyncRedisSet, ReplayOutcome, validate_replay_key


class RedisHttpSignatureReplayStore:
    """Thin Redis SET NX EX adapter for HTTP signature nonces.

    Requires the ``authweave-http-signatures[redis]`` extra.
    """

    __slots__ = ("_redis",)

    def __init__(self, redis: AsyncRedisSet) -> None:
        """Bind an async Redis client exposing ``set(..., nx=True, ex=...)``."""
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
            created = await self._redis.set(
                key,
                "1",
                nx=True,
                ex=max(1, int(ttl_seconds)),
            )
        except Exception:
            return ReplayOutcome.UNAVAILABLE
        return ReplayOutcome.STORED if created else ReplayOutcome.REPLAY
