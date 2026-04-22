"""In-memory rate-limiter backend."""

from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from typing import TYPE_CHECKING

from ._helpers import SlidingWindow, _validate_configuration, logger

if TYPE_CHECKING:
    from collections.abc import Callable


class InMemoryRateLimiter:
    """Async-safe in-memory sliding-window rate limiter.

    Not safe for multi-process or multi-host deployments; use :class:`RedisRateLimiter`
    for shared storage (e.g. multi-worker or multi-pod).
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        max_attempts: int,
        window_seconds: float,
        max_keys: int = 100_000,
        sweep_interval: int = 1_000,
        fail_closed_on_capacity: bool = True,
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
        self.fail_closed_on_capacity = fail_closed_on_capacity
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
                if self.fail_closed_on_capacity and self._is_at_capacity_after_prune(now):
                    self._log_capacity_rejection()
                    return False
                return True

            return len(timestamps) < self.max_attempts

    async def increment(self, key: str) -> None:
        """Record a new attempt for ``key`` in the current window."""
        async with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            timestamps = self._prune(key, now)
            if timestamps is None:
                if self.fail_closed_on_capacity and self._is_at_capacity_after_prune(now):
                    self._log_capacity_rejection()
                    return
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

    def _is_at_capacity_after_prune(self, now: float) -> bool:
        """Return whether the key cap still holds after reclaiming expired counters."""
        if len(self._windows) < self.max_keys:
            return False
        self._sweep_all(now)
        return len(self._windows) >= self.max_keys

    def _evict_oldest_keys(self) -> None:
        """Keep the tracked-key count below the configured cap in legacy eviction mode.

        Evicts the least-recently-active key (earliest last timestamp)
        rather than the first-inserted key, preventing attackers from
        resetting their own rate-limit window through eviction pressure.
        """
        while len(self._windows) >= self.max_keys:
            lru_key = min(self._windows, key=lambda k: self._windows[k][-1] if self._windows[k] else 0.0)
            del self._windows[lru_key]

    def _log_capacity_rejection(self) -> None:
        """Emit structured telemetry for fail-closed capacity pressure."""
        logger.warning(
            "In-memory rate limiter rejected a new key at capacity (fail closed). "
            "Use RedisRateLimiter or increase max_keys for high-volume deployments.",
            extra={"event": "rate_limit_memory_capacity", "max_keys": self.max_keys},
        )
