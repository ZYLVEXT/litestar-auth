"""JWT denylist storage helpers."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, ClassVar, Literal, Protocol, Self

from litestar_auth._optional_deps import _require_redis_asyncio

if TYPE_CHECKING:
    from litestar_auth._redis_protocols import RedisExpiringValueStoreClient

logger = logging.getLogger(__name__)

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisJWTDenylistStore")

_MISSING_JWT_DENYLIST_STORE_ERROR = (
    "JWTStrategy requires explicit JWT revocation storage. "
    "Configure denylist_store=RedisJWTDenylistStore(...) or another shared JWTDenylistStore for production. "
    "For single-process tests, development, or consciously single-process apps only, set "
    "allow_inmemory_denylist=True to construct InMemoryJWTDenylistStore explicitly."
)
_INMEMORY_JWT_DENYLIST_STARTUP_WARNING = (
    "JWTStrategy is configured with an explicit process-local in-memory denylist. "
    "Revoked tokens are not visible across workers; use RedisJWTDenylistStore or another shared "
    "JWTDenylistStore for production deployments that rely on revocation."
)

type JWTRevocationPostureKey = Literal["in_memory", "shared_store"]


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


class InMemoryJWTDenylistStore:
    """Process-local denylist store (best-effort).

    **Capacity:** Each :meth:`deny` call prunes expired JTIs first. When the map is already at
    ``max_entries`` and no expired entries remain, :meth:`deny` **fails closed**: it logs an
    error and does **not** insert the new JTI, preserving every existing active revocation.
    The store never evicts a still-valid revoked JTI to admit another (older releases dropped
    the soonest-expiring entry under pressure, which could revive a revoked token). Size
    ``max_entries`` for peak concurrent revocations or use :class:`RedisJWTDenylistStore` for
    shared, unbounded-by-process-memory semantics in production.
    """

    # Used by JWTRevocationPosture.from_denylist_store to derive durability without
    # an isinstance() check, which is fragile under module-reload-style test fixtures.
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

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Record the revoked JTI (TTL is best-effort in memory).

        When the store is at capacity and no expired rows can be reclaimed, the new revocation
        is skipped (fail-closed) so existing denylist entries are never dropped to make room.

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
            logger.error(
                "Rejected in-memory JWT denylist insert: capacity %d reached with no "
                "expired entries to reclaim (fail closed). Use RedisJWTDenylistStore or "
                "increase max_entries for high-volume deployments.",
                self.max_entries,
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

    def _prune_expired(self, now: float) -> None:
        """Remove all entries whose TTL has elapsed."""
        expired_jtis = [jti for jti, expires_at in self._denylisted_until.items() if expires_at <= now]
        for expired_jti in expired_jtis:
            self._denylisted_until.pop(expired_jti, None)


class RedisJWTDenylistStore:
    """Redis-backed denylist store keyed by `jti` with TTL."""

    # Used by JWTRevocationPosture.from_denylist_store to derive durability without
    # an isinstance() check, which is fragile under module-reload-style test fixtures.
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
                ``setex(name, ttl_seconds, value)``. The same client may also
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
        await self.redis.setex(self._key(jti), max(ttl_seconds, 1), "1")
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI key exists in Redis."""
        return await self.redis.get(self._key(jti)) is not None


@dataclass(slots=True, frozen=True)
class JWTRevocationPosture:
    """Explicit contract describing the durability semantics of JWT revocation."""

    key: JWTRevocationPostureKey
    denylist_store_type: str
    revocation_is_durable: bool
    requires_explicit_production_opt_in: bool

    @classmethod
    def from_denylist_store(cls, denylist_store: JWTDenylistStore) -> Self:
        """Build the posture contract for a concrete denylist backend.

        Durability is read from the store's ``revocation_is_durable`` class
        attribute (default ``True`` for unknown custom stores, matching the
        prior behavior where any non-``InMemoryJWTDenylistStore`` was treated
        as durable). Reading an attribute instead of branching on
        ``isinstance(...)`` keeps the posture stable when test fixtures reload
        modules and the in-memory store class identity drifts.

        Returns:
            The explicit revocation posture for ``denylist_store``.
        """
        store_type = type(denylist_store).__name__
        is_durable = bool(getattr(denylist_store, "revocation_is_durable", True))
        return cls(
            key="shared_store" if is_durable else "in_memory",
            denylist_store_type=store_type,
            revocation_is_durable=is_durable,
            requires_explicit_production_opt_in=False,
        )

    @property
    def production_validation_error(self) -> str | None:
        """Return the plugin validation error for this posture, if any.

        JWT revocation storage is validated at strategy construction time, so
        constructed postures do not require a second plugin-level compatibility
        override.
        """
        return None

    @property
    def startup_warning(self) -> str | None:
        """Return the startup warning for this posture, if any."""
        if self.revocation_is_durable:
            return None
        return _INMEMORY_JWT_DENYLIST_STARTUP_WARNING


def _resolve_jwt_revocation(
    denylist_store: JWTDenylistStore | None,
    *,
    allow_inmemory_denylist: bool,
) -> tuple[JWTDenylistStore, JWTRevocationPosture]:
    """Resolve the effective denylist backend and its explicit posture contract.

    Returns:
        Tuple of the denylist backend used at runtime and the posture it reports.

    Raises:
        ValueError: If no denylist store is configured or both configuration paths are supplied.
    """
    if denylist_store is not None:
        if allow_inmemory_denylist:
            msg = "allow_inmemory_denylist=True cannot be combined with denylist_store."
            raise ValueError(msg)
        return denylist_store, JWTRevocationPosture.from_denylist_store(denylist_store)

    if not allow_inmemory_denylist:
        raise ValueError(_MISSING_JWT_DENYLIST_STORE_ERROR)

    resolved_denylist_store = InMemoryJWTDenylistStore()
    return resolved_denylist_store, JWTRevocationPosture.from_denylist_store(resolved_denylist_store)
