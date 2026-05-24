"""Shared sliding-window arithmetic for rate-limit backends."""

from __future__ import annotations

import math


def cutoff_for_now(now: float, window: float) -> float:
    """Return the oldest timestamp still inside the sliding window."""
    return now - window


def retry_seconds(now: float, window: float, oldest: float) -> int:
    """Return whole seconds until a full sliding window admits another attempt.

    Active entries are retained only when ``oldest > cutoff_for_now(now, window)``.
    For a full active window, retry-after is therefore at least one second so
    callers never report ``Retry-After: 0`` while the backend is still blocking.
    """
    remaining = window - (now - oldest)
    return max(math.ceil(remaining), 1)
