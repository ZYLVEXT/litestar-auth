"""Private async lock registry helpers."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _BoundedAsyncLockRegistry[K]:
    """Bound process-local async locks while preserving active entries."""

    def __init__(self, *, max_size: int) -> None:
        """Initialize a bounded lock registry.

        Args:
            max_size: Maximum number of idle and recently used locks to retain. When active concurrency exceeds this
                value, held locks are retained until they can be safely evicted after release.

        Raises:
            ValueError: If ``max_size`` is less than one.
        """
        if max_size < 1:
            msg = "max_size must be at least 1."
            raise ValueError(msg)
        self.max_size = max_size
        self._locks: OrderedDict[K, asyncio.Lock] = OrderedDict()

    def __len__(self) -> int:
        """Return the number of currently retained lock entries."""
        return len(self._locks)

    def __getitem__(self, key: K) -> asyncio.Lock:
        """Return a lock for ``key`` and evict oldest idle entries over the limit."""
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
            self._evict_idle_locks(exclude_key=key)
            return lock
        self._locks.move_to_end(key)
        return lock

    @asynccontextmanager
    async def lock(self, key: K) -> AsyncIterator[None]:
        """Hold the per-key lock and prune idle overflow after release."""
        lock = self[key]
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()
            self._evict_idle_locks()

    def _evict_idle_locks(self, *, exclude_key: K | None = None) -> None:
        """Evict oldest unlocked entries until the registry is within its idle bound."""
        while len(self._locks) > self.max_size:
            evicted_key = next(
                (key for key, lock in self._locks.items() if key != exclude_key and not lock.locked()),
                None,
            )
            if evicted_key is None:
                return
            del self._locks[evicted_key]
