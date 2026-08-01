"""Account-token replay and JWT denylist storage helpers."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, ClassVar, Protocol

from litestar_auth._optional_deps import _require_redis_asyncio

if TYPE_CHECKING:
    from litestar_auth._redis_protocols import RedisExpiringValueStoreClient

_SECURITY_LOGGER = logging.getLogger("litestar_auth.security")


def denylist_ttl_seconds(exp: object, *, now: float | None = None) -> int:
    """Return the denylist TTL (>=1s) for a decoded JWT ``exp`` claim.

    Used by verify/reset account-token replay handling so a consumed ``jti`` is
    retained exactly until the token would have expired. Non-finite or non-numeric
    ``exp`` values fall back to one second.

    Returns:
        Seconds the ``jti`` should remain denied, never below 1.
    """
    if isinstance(exp, bool) or not isinstance(exp, int | float) or not math.isfinite(exp):
        return 1
    current_time = time.time() if now is None else now
    return max(math.ceil(exp - current_time), 1)


_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisJWTDenylistStore")


class JWTDenylistStore(Protocol):
    """Shared denylist storage for JWT `jti` revocation."""

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Mark a JTI as revoked for ``ttl_seconds``.

        Returns:
            ``True`` when the revocation was recorded or an existing JTI's TTL was refreshed.
            ``False`` when a **new** revocation could not be stored (for example, an
            in-memory store at capacity after pruning expired entries). Implementations
            that always persist (such as Redis) should return ``True``.
        """

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI is revoked."""


@dataclass(frozen=True, slots=True)
class JWTReplayStoreResult:
    """Outcome of atomically recording a JTI as consumed.

    Attributes:
        stored: ``True`` only when this call recorded a previously unseen JTI.
        rejected_as_replay: When ``stored`` is ``False``, ``True`` if the JTI was
            already present. ``False`` means the store rejected a new JTI for
            another reason, such as in-memory capacity pressure.
    """

    stored: bool
    rejected_as_replay: bool = False


class JWTReplayStore(JWTDenylistStore, Protocol):
    """JWT denylist that can also consume a JTI exactly once."""

    async def mark_used(self, jti: str, *, ttl_seconds: int) -> JWTReplayStoreResult:
        """Atomically record an unseen JTI and reject concurrent replays."""


class InMemoryJWTDenylistStore:
    """Process-local denylist store (best-effort).

    **Capacity:** Each :meth:`deny` call prunes expired JTIs first. When the map is already at
    ``max_entries`` and no expired entries remain, :meth:`deny` reports failure and does
    **not** insert the new JTI, preserving every existing active revocation.
    The store never evicts a still-valid revoked JTI to admit another (older releases dropped
    the soonest-expiring entry under pressure, which could revive a revoked token). Size
    ``max_entries`` for peak concurrent revocations or use :class:`RedisJWTDenylistStore` for
    shared, unbounded-by-process-memory semantics in production.
    """

    revocation_is_durable: ClassVar[bool] = False

    def __init__(self, *, max_entries: int = 10_000) -> None:
        """Initialize an empty denylist map with per-entry expiration.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self.max_entries = max_entries
        self._denylisted_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Record the revoked JTI (TTL is best-effort in memory).

        When the store is at capacity and no expired rows can be reclaimed, the new revocation
        is skipped and the caller is told it failed; existing entries are never dropped.

        Returns:
            ``False`` when a new JTI could not be inserted at capacity; ``True`` otherwise.
        """
        now = time.time()
        self._prune_expired(now)
        expires_at = now + max(ttl_seconds, 1)
        if jti in self._denylisted_until:
            self._denylisted_until[jti] = expires_at
            return True
        if len(self._denylisted_until) >= self.max_entries:
            _SECURITY_LOGGER.error(
                "Rejected in-memory JWT denylist insert: capacity reached with no expired "
                "entries to reclaim. Use RedisJWTDenylistStore or increase "
                "max_entries for high-volume deployments.",
                extra={"event": "jwt_denylist_capacity_exceeded", "max_entries": self.max_entries},
            )
            return False

        self._denylisted_until[jti] = expires_at
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI has been revoked in this process."""
        expires_at = self._denylisted_until.get(jti)
        if expires_at is None:
            return False
        if expires_at <= time.time():
            self._denylisted_until.pop(jti, None)
            return False
        return True

    async def mark_used(self, jti: str, *, ttl_seconds: int) -> JWTReplayStoreResult:
        """Atomically record a JTI only when it has not already been consumed.

        Returns:
            Stored, replay, or capacity-pressure outcome.
        """
        async with self._lock:
            now = time.time()
            self._prune_expired(now)
            if jti in self._denylisted_until:
                return JWTReplayStoreResult(stored=False, rejected_as_replay=True)
            if len(self._denylisted_until) >= self.max_entries:
                return JWTReplayStoreResult(stored=False, rejected_as_replay=False)
            self._denylisted_until[jti] = now + max(ttl_seconds, 1)
            return JWTReplayStoreResult(stored=True)

    def _prune_expired(self, now: float) -> None:
        """Remove all entries whose TTL has elapsed."""
        expired_jtis = [jti for jti, expires_at in self._denylisted_until.items() if expires_at <= now]
        for expired_jti in expired_jtis:
            self._denylisted_until.pop(expired_jti, None)


class RedisJWTDenylistStore:
    """Redis-backed denylist store keyed by `jti` with TTL."""

    # Read by startup durability checks without an isinstance() test, which is
    # fragile under module-reload-style test fixtures.
    revocation_is_durable: ClassVar[bool] = True

    def __init__(
        self,
        *,
        redis: RedisExpiringValueStoreClient,
        key_prefix: str = "litestar_auth:jwt:denylist:",
    ) -> None:
        """Initialize the store with a Redis client and key prefix.

        Args:
            redis: Async Redis client supporting ``get(name)`` plus
                ``set(name, value, ex=ttl_seconds)``. The same client may also
                be annotated as
                :class:`litestar_auth.contrib.redis.RedisAuthClientProtocol`
                when it backs the contrib preset or TOTP replay store.
            key_prefix: Prefix used to namespace denylist keys by JTI.
        """
        _load_redis_asyncio()
        self.redis = redis
        self.key_prefix = key_prefix

    def _key(self, jti: str) -> str:
        return f"{self.key_prefix}{jti}"

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Store the JTI key with an expiry aligned to token lifetime.

        Returns:
            ``True`` after the key is written (Redis denylist writes always succeed).
        """
        await self.redis.set(self._key(jti), "1", ex=max(ttl_seconds, 1))
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI key exists in Redis."""
        return await self.redis.get(self._key(jti)) is not None

    async def mark_used(self, jti: str, *, ttl_seconds: int) -> JWTReplayStoreResult:
        """Atomically record an unseen JTI using ``SET NX EX``.

        Returns:
            Stored or replay outcome for the JTI.
        """
        stored = await self.redis.set(self._key(jti), "1", nx=True, ex=max(ttl_seconds, 1))
        if stored is True:
            return JWTReplayStoreResult(stored=True)
        return JWTReplayStoreResult(stored=False, rejected_as_replay=True)
