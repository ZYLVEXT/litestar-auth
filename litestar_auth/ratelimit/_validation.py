"""Shared rate-limiter validation helpers."""

from __future__ import annotations

from collections import deque

type SlidingWindow = deque[float]
type RedisScriptResult = bytes | str | int | float


def _validate_configuration(*, max_attempts: int, window_seconds: float) -> None:
    """Validate shared rate-limiter settings.

    Raises:
        ValueError: If ``max_attempts`` or ``window_seconds`` is invalid.
    """
    if max_attempts < 1:
        msg = "max_attempts must be at least 1"
        raise ValueError(msg)
    if window_seconds <= 0:
        msg = "window_seconds must be greater than 0"
        raise ValueError(msg)
