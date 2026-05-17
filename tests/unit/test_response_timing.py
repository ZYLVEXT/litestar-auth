"""Unit tests for private response timing helpers."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

import litestar_auth.controllers._response_timing as response_timing

pytestmark = pytest.mark.unit
FAST_FLOOR_SECONDS = 0.01
SLOW_WORK_SECONDS = 0.02


async def test_minimum_response_helper_pads_fast_work_to_floor() -> None:
    """Work that finishes quickly is padded to the configured minimum."""

    async def work() -> str:
        await asyncio.sleep(0)
        return "ok"

    started_at = time.perf_counter()
    result = await response_timing.await_minimum_response_seconds(minimum_seconds=FAST_FLOOR_SECONDS, work=work)
    elapsed = time.perf_counter() - started_at

    assert result == "ok"
    assert elapsed >= FAST_FLOOR_SECONDS


async def test_minimum_response_helper_does_not_pad_slow_work(monkeypatch: pytest.MonkeyPatch) -> None:
    """Work that already exceeds the floor returns without additional padding."""
    real_sleep = asyncio.sleep
    padding_sleep = AsyncMock()
    monkeypatch.setattr(response_timing.asyncio, "sleep", padding_sleep)

    async def work() -> str:
        await real_sleep(SLOW_WORK_SECONDS)
        return "ok"

    started_at = time.perf_counter()
    result = await response_timing.await_minimum_response_seconds(minimum_seconds=FAST_FLOOR_SECONDS, work=work)
    elapsed = time.perf_counter() - started_at

    assert result == "ok"
    assert elapsed >= SLOW_WORK_SECONDS
    padding_sleep.assert_not_awaited()


async def test_minimum_response_helper_propagates_work_exceptions() -> None:
    """Wrapped work exceptions propagate unchanged after the timing floor."""
    error = RuntimeError("work failed")

    async def work() -> str:
        await asyncio.sleep(0)
        raise error

    started_at = time.perf_counter()
    with pytest.raises(RuntimeError) as exc_info:
        await response_timing.await_minimum_response_seconds(minimum_seconds=FAST_FLOOR_SECONDS, work=work)
    elapsed = time.perf_counter() - started_at

    assert exc_info.value is error
    assert elapsed >= FAST_FLOOR_SECONDS
