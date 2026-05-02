"""Shared clock protocol for injectable time sources."""

from __future__ import annotations

from collections.abc import Callable

type Clock = Callable[[], float]


def read_clock(clock: Clock) -> float:
    """Return a timestamp from ``clock`` after validating it is callable.

    Returns:
        Current clock timestamp in seconds.

    Raises:
        TypeError: If a non-callable object was configured as a clock.
    """
    if not callable(clock):
        msg = "clock must be callable"
        raise TypeError(msg)
    return clock()
