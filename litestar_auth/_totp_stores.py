"""TOTP replay and enrollment store implementations."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from litestar_auth._clock import Clock, read_clock
from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._redis_protocols import (
    RedisConditionalSetClient,
    RedisDeleteClient,
    RedisExpiringValueWriteClient,
    RedisNullableScriptEvalClient,
)

if TYPE_CHECKING:
    from collections.abc import Hashable


DEFAULT_TOTP_USED_KEY_PREFIX = "litestar_auth:totp:used:"
DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX = "litestar_auth:totp:enroll:"
_TOTP_ENROLLMENT_VALUE_SEPARATOR = ":"
_REDIS_TOTP_ENROLLMENT_CONSUME_SCRIPT = """
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
local expected_prefix = ARGV[1] .. ":"
if string.sub(value, 1, string.len(expected_prefix)) ~= expected_prefix then
  return nil
end
redis.call("DEL", KEYS[1])
return string.sub(value, string.len(expected_prefix) + 1)
"""

logger = logging.getLogger(__name__)

_load_used_totp_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisUsedTotpCodeStore")
_load_enrollment_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisTotpEnrollmentStore")


@dataclass(frozen=True, slots=True)
class _TotpEnrollmentEntry:
    """Process-local pending TOTP enrollment record."""

    jti: str
    secret: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class UsedTotpMarkResult:
    """Outcome of attempting to record a used ``(user_id, counter)`` pair in a replay store.

    Attributes:
        stored: ``True`` when the pair was newly recorded.
        rejected_as_replay: When ``stored`` is ``False``, ``True`` if the pair was already
            recorded (replay). ``False`` when the store rejected the insert for another reason,
            such as in-memory capacity exhaustion (fail-closed).
    """

    stored: bool
    rejected_as_replay: bool = False


@runtime_checkable
class TotpEnrollmentStore(Protocol):
    """Short-TTL store for pending TOTP enrollment secrets keyed by user and token JTI.

    Implementations must make ``consume`` atomic: two concurrent consumers for the
    same ``user_id`` and ``jti`` must not both receive the secret. ``save`` replaces
    any previous pending enrollment for the same user so only the latest
    enrollment token can be confirmed.
    """

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Persist a pending enrollment secret, replacing any previous one for the user.

        Returns:
            ``True`` when the secret was stored; ``False`` when the store refused
            the insert under capacity pressure and callers should fail closed.
        """

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Atomically return and delete the latest matching secret, or ``None`` if absent or stale."""

    async def clear(self, *, user_id: str) -> None:
        """Delete any pending enrollment for the user."""


@runtime_checkable
class UsedTotpCodeStore(Protocol):
    """Persistence for used TOTP codes keyed by user and counter."""

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Atomically record a `(user_id, counter)` pair when unused.

        Returns:
            :class:`UsedTotpMarkResult` with ``stored=True`` when the pair was newly recorded.
            When ``stored`` is ``False``, set ``rejected_as_replay=True`` if the pair was already
            stored; otherwise callers such as :func:`verify_totp_with_store` can surface
            non-replay failures (for example in-memory capacity pressure) as distinct telemetry.
        """


@dataclass(frozen=True, slots=True)
class TotpReplayProtection:
    """Replay-protection settings for one TOTP verification attempt."""

    user_id: Hashable
    used_tokens_store: UsedTotpCodeStore | None = None
    require_replay_protection: bool = True
    unsafe_testing: bool = False


class RedisUsedTotpCodeStoreClient(RedisConditionalSetClient, Protocol):
    """Minimal Redis client interface for TOTP replay store (SET key value NX PX ttl_ms)."""


class RedisTotpEnrollmentStoreClient(
    RedisDeleteClient,
    RedisExpiringValueWriteClient,
    RedisNullableScriptEvalClient,
    Protocol,
):
    """Minimal Redis client interface for pending TOTP enrollment state."""


class RedisTotpEnrollmentStore:
    """Redis-backed pending-enrollment store; safe for multi-worker and multi-pod deployments."""

    def __init__(
        self,
        *,
        redis: RedisTotpEnrollmentStoreClient,
        key_prefix: str = DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX,
    ) -> None:
        """Store the Redis client and key prefix."""
        _load_enrollment_redis_asyncio()
        self._redis = redis
        self._key_prefix = key_prefix

    @property
    def is_shared_across_workers(self) -> bool:
        """Redis-backed enrollment state is visible across workers."""
        return True

    def _key(self, user_id: str) -> str:
        """Return the Redis key for a user's latest pending enrollment."""
        user_digest = hashlib.sha256(user_id.encode()).hexdigest()[:32]
        return f"{self._key_prefix}{user_digest}"

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Persist the latest pending enrollment secret for ``user_id`` with a TTL.

        Returns:
            ``True`` when Redis confirms the write; ``False`` when the
            underlying client signals refusal via a falsy return. Connection-level
            failures continue to raise so callers fail closed regardless.
        """
        value = f"{jti}{_TOTP_ENROLLMENT_VALUE_SEPARATOR}{secret}"
        result = await self._redis.setex(self._key(user_id), max(ttl_seconds, 1), value)
        return bool(result)

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Atomically consume the latest pending enrollment if its JTI matches.

        Returns:
            Stored secret value, or ``None`` if the state is absent or stale.
        """
        value = await self._redis.eval(_REDIS_TOTP_ENROLLMENT_CONSUME_SCRIPT, 1, self._key(user_id), jti)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode()
        return str(value)

    async def clear(self, *, user_id: str) -> None:
        """Delete any pending enrollment for ``user_id``."""
        await self._redis.delete(self._key(user_id))


class RedisUsedTotpCodeStore:
    """Redis-backed replay store for TOTP codes; safe for multi-worker and multi-pod deployments.

    For the higher-level shared-client Redis preset that can also derive
    ``AuthRateLimitConfig``, see ``litestar_auth.contrib.redis.RedisAuthPreset``.
    """

    def __init__(
        self,
        *,
        redis: RedisUsedTotpCodeStoreClient,
        key_prefix: str = DEFAULT_TOTP_USED_KEY_PREFIX,
    ) -> None:
        """Store the Redis client and key prefix.

        Args:
            redis: Async Redis client supporting ``set(name, value, nx=True, px=ttl_ms)``
                (e.g. ``redis.asyncio.Redis``).
            key_prefix: Prefix for replay keys; keys are ``{key_prefix}{user_id}:{counter}``.
        """
        _load_used_totp_redis_asyncio()
        self._redis = redis
        self._key_prefix = key_prefix

    def _key(self, user_id: Hashable, counter: int) -> str:
        """Return the Redis key for a (user_id, counter) pair."""
        return f"{self._key_prefix}{user_id!s}:{counter}"

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Atomically record a used (user_id, counter) pair via SET key 1 NX PX ttl_ms.

        Returns:
            ``UsedTotpMarkResult(stored=True)`` when the pair was newly stored, or
            ``UsedTotpMarkResult(stored=False, rejected_as_replay=True)`` when the key already
            existed (replay).
        """
        key = self._key(user_id, counter)
        ttl_ms = int(ttl_seconds * 1000)
        result = await self._redis.set(key, "1", nx=True, px=ttl_ms)
        if result is True:
            return UsedTotpMarkResult(stored=True)
        return UsedTotpMarkResult(stored=False, rejected_as_replay=True)


class InMemoryUsedTotpCodeStore:
    """Async-safe in-memory replay cache for successful TOTP verifications.

    Not safe for multi-process or multi-host deployments; use :class:`RedisUsedTotpCodeStore`
    for shared storage (e.g. multi-worker or multi-pod).

    **Capacity / replay protection:** When ``len(entries) >= max_entries`` after dropping
    expired rows, :meth:`mark_used` **fails closed** and returns a result with ``stored=False``
    (and ``rejected_as_replay=False``) instead of evicting
    still-valid replay records to make room. That avoids weakening replay protection under
    load (previously the store evicted the soonest-to-expire active entry). Operators
    should size ``max_entries`` for peak legitimate traffic or switch to Redis-backed storage.
    Prior releases evicted the soonest-to-expire active entry under pressure; that behavior
    was removed because it could widen replay windows.
    """

    def __init__(
        self,
        *,
        clock: Clock = time.monotonic,
        max_entries: int = 50_000,
    ) -> None:
        """Store the monotonic clock and initialize cache state.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self._clock: Clock = clock
        self.max_entries = max_entries
        self._entries: dict[tuple[Hashable, int], float] = {}
        self._lock = asyncio.Lock()

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Store a used code pair until its TTL elapses.

        Returns:
            ``UsedTotpMarkResult(stored=True)`` when the pair was newly stored.
            ``UsedTotpMarkResult(stored=False, rejected_as_replay=True)`` when the pair was
            already recorded (replay). ``UsedTotpMarkResult(stored=False, rejected_as_replay=False)``
            when the store is at ``max_entries`` and no expired entries remain to reclaim
            (fail-closed under capacity pressure; see class docs).
        """
        async with self._lock:
            now = read_clock(self._clock)
            self._prune(now)
            key = (user_id, counter)
            if key in self._entries:
                return UsedTotpMarkResult(stored=False, rejected_as_replay=True)

            if len(self._entries) >= self.max_entries:
                logger.error(
                    "Rejected in-memory TOTP replay-store insert: capacity %d reached with no "
                    "expired entries to reclaim (fail closed). Use RedisUsedTotpCodeStore or "
                    "increase max_entries for high-volume deployments.",
                    self.max_entries,
                )
                return UsedTotpMarkResult(stored=False, rejected_as_replay=False)

            self._entries[key] = now + ttl_seconds
            return UsedTotpMarkResult(stored=True)

    def _prune(self, now: float) -> None:
        """Drop expired replay-cache entries."""
        expired_keys = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired_keys:
            del self._entries[key]


class InMemoryTotpEnrollmentStore:
    """Async-safe process-local pending TOTP enrollment store.

    This store is suitable for tests and single-process development. Production
    deployments with multiple workers should use :class:`RedisTotpEnrollmentStore`
    or another shared implementation.
    """

    def __init__(
        self,
        *,
        clock: Clock = time.monotonic,
        max_entries: int = 50_000,
    ) -> None:
        """Initialize an empty enrollment store.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self._clock: Clock = clock
        self.max_entries = max_entries
        self._entries: dict[str, _TotpEnrollmentEntry] = {}
        self._lock = asyncio.Lock()

    @property
    def is_shared_across_workers(self) -> bool:
        """In-memory enrollment state is process-local."""
        return False

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Store the latest pending enrollment for ``user_id``.

        Returns:
            ``True`` when stored, or ``False`` when capacity pressure rejects a new user key.
        """
        async with self._lock:
            now = read_clock(self._clock)
            self._prune(now)
            if user_id not in self._entries and len(self._entries) >= self.max_entries:
                logger.error(
                    "Rejected in-memory TOTP enrollment insert: capacity %d reached with no "
                    "expired entries to reclaim (fail closed). Use RedisTotpEnrollmentStore or "
                    "increase max_entries for high-volume deployments.",
                    self.max_entries,
                    extra={"event": "totp_enrollment_store_capacity"},
                )
                return False

            self._entries[user_id] = _TotpEnrollmentEntry(
                jti=jti,
                secret=secret,
                expires_at=now + max(ttl_seconds, 1),
            )
            return True

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Consume the latest pending enrollment for ``user_id`` when ``jti`` matches.

        Returns:
            Stored secret value, or ``None`` if the state is absent, stale, or expired.
        """
        async with self._lock:
            now = read_clock(self._clock)
            self._prune(now)
            entry = self._entries.get(user_id)
            if entry is None or not hmac.compare_digest(entry.jti, jti):
                return None

            del self._entries[user_id]
            return entry.secret

    async def clear(self, *, user_id: str) -> None:
        """Clear any pending enrollment for ``user_id``."""
        async with self._lock:
            self._entries.pop(user_id, None)

    def _prune(self, now: float) -> None:
        """Drop expired pending-enrollment rows."""
        expired_user_ids = [user_id for user_id, entry in self._entries.items() if entry.expires_at <= now]
        for user_id in expired_user_ids:
            del self._entries[user_id]
