"""Private response-timing helpers for enumeration-resistant controllers."""

from __future__ import annotations

import asyncio
import math
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

DEFAULT_MINIMUM_RESPONSE_SECONDS = 0.4


def validate_minimum_response_seconds(value: float, *, field_name: str) -> float:
    """Return a non-negative response timing floor.

    Raises:
        ValueError: If ``value`` is negative or non-finite.
    """
    if math.isfinite(value) and value >= 0:
        return value

    msg = f"{field_name} must be non-negative and finite."
    raise ValueError(msg)


async def await_minimum_response_seconds[T](
    *,
    minimum_seconds: float,
    work: Callable[[], Awaitable[T]],
) -> T:
    """Run async work and pad the response to a configured minimum duration.

    Returns:
        The wrapped work result.
    """
    deadline = time.perf_counter() + minimum_seconds
    try:
        return await work()
    finally:
        # asyncio.sleep() may return early; loop to enforce the security timing floor.
        while (remaining_seconds := deadline - time.perf_counter()) > 0:  # ruff: ignore[async-busy-wait]
            await asyncio.sleep(remaining_seconds)
