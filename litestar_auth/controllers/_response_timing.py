"""Private response-timing helpers for enumeration-resistant controllers."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

DEFAULT_MINIMUM_RESPONSE_SECONDS = 0.4


async def await_minimum_response_seconds[T](
    *,
    minimum_seconds: float,
    work: Callable[[], Awaitable[T]],
) -> T:
    """Run async work and pad the response to a configured minimum duration.

    Returns:
        The wrapped work result.
    """
    started_at = time.perf_counter()
    try:
        return await work()
    finally:
        remaining_seconds = minimum_seconds - (time.perf_counter() - started_at)
        if remaining_seconds > 0:
            await asyncio.sleep(remaining_seconds)
