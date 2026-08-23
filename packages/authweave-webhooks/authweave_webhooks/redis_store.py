"""Optional Redis-backed webhook replay store."""

from __future__ import annotations

from authweave_core import AsyncRedisSet, ReplayOutcome, validate_replay_key


class RedisReplayStore:
    """Thin Redis SET NX EX adapter satisfying authweave-core ``ReplayStore``.

    Requires the ``authweave-webhooks[redis]`` extra. Connection failures map to
    ``Unavailable`` so webhook verification fails closed.
    """

    __slots__ = ("_redis",)

    def __init__(self, redis: AsyncRedisSet) -> None:
        """Bind an async Redis client exposing ``set(name, value, nx=True, ex=...)``."""
        self._redis = redis

    async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
        """Atomically claim ``key`` with a TTL.

        Returns:
            The typed put-if-absent outcome.

        Raises:
            ValueError: If the call cannot complete.
        """
        validate_replay_key(key)
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        try:
            created = await self._redis.set(key, "1", nx=True, ex=int(ttl_seconds))
        except Exception:
            return ReplayOutcome.UNAVAILABLE
        return ReplayOutcome.STORED if created else ReplayOutcome.REPLAY
