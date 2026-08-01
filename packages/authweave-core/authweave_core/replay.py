"""Shared low-level replay/nonce contracts for sender-constrained protocols.

Each protocol adapter (DPoP proof, HTTP Message Signature nonce, webhook delivery
duplicate) owns its own key namespace and TTL and must never share a single
universal store across protocols. The only elements shared here are the neutral
atomic put-if-absent semantics and the typed outcomes so that every adapter maps
outages and capacity exhaustion to the same fail-closed decisions.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable

_MAX_KEY_LENGTH = 512


class ReplayOutcome(StrEnum):
    """Result of an atomic put-if-absent against a replay/nonce store."""

    STORED = "stored"
    REPLAY = "replay"
    UNAVAILABLE = "unavailable"
    CAPACITY_EXCEEDED = "capacity_exceeded"


@runtime_checkable
class ReplayStore(Protocol):
    """Atomic put-if-absent contract shared by protocol replay adapters.

    Implementations must be atomic: a concurrent first presentation of the same
    key returns :attr:`ReplayOutcome.STORED` for exactly one caller and
    :attr:`ReplayOutcome.REPLAY` for the others. Store outage maps to
    :attr:`ReplayOutcome.UNAVAILABLE` and capacity exhaustion to
    :attr:`ReplayOutcome.CAPACITY_EXCEEDED`; adapters translate both into a
    fail-closed ``Unavailable`` decision on protected routes.
    """

    async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
        """Record ``key`` if absent and report whether it was already present.

        Returns:
            The typed put-if-absent outcome.
        """
        ...


def validate_replay_key(key: str) -> None:
    """Reject empty or oversized replay keys before hitting the store.

    Raises:
        ValueError: If the key is empty or exceeds the bounded length.
    """
    if not key or len(key) > _MAX_KEY_LENGTH:
        msg = f"replay key must be non-empty and at most {_MAX_KEY_LENGTH} characters"
        raise ValueError(msg)


class InMemoryReplayStore:
    """Bounded single-process reference replay store for tests and single-worker use.

    This store is atomic only within one event loop and does not survive process
    restarts, so it is not a durable multi-worker replay defense. Production
    deployments must supply a shared durable store (for example Redis) that
    satisfies :class:`ReplayStore`.
    """

    __slots__ = ("_capacity", "_entries", "_time_source")

    def __init__(self, *, capacity: int, time_source: Callable[[], float]) -> None:
        """Bound the store capacity and inject a monotonic clock.

        Raises:
            ValueError: If the capacity is not positive.
        """
        if capacity <= 0:
            msg = "capacity must be positive"
            raise ValueError(msg)
        self._capacity = capacity
        self._entries: dict[str, float] = {}
        self._time_source = time_source

    async def check_and_store(self, key: str, *, ttl_seconds: float) -> ReplayOutcome:
        """Atomically record ``key`` with a bounded TTL if not already present.

        Returns:
            The typed put-if-absent outcome.

        Raises:
            ValueError: If the key is invalid or the TTL is not positive.
        """
        validate_replay_key(key)
        if ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        now = self._time_source()
        existing = self._entries.get(key)
        if existing is not None and existing > now:
            return ReplayOutcome.REPLAY
        if key not in self._entries and len(self._entries) >= self._capacity:
            self._purge_expired(now)
            if len(self._entries) >= self._capacity:
                return ReplayOutcome.CAPACITY_EXCEEDED
        self._entries[key] = now + ttl_seconds
        return ReplayOutcome.STORED

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]
