"""Tests for shared authentication concurrency helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio.lowlevel
import pytest

from litestar_auth import _concurrency
from litestar_auth.exceptions import ConfigurationError

EXPECTED_DEFAULT_PASSWORD_WORKER_LIMIT = 8
OVERRIDDEN_PASSWORD_WORKER_LIMIT = 3

if TYPE_CHECKING:
    from collections.abc import Callable


def test_password_worker_thread_limit_defaults_to_eight() -> None:
    """Missing env input keeps the historical eight-operation cap."""
    assert _concurrency._resolve_password_worker_thread_limit(None) == EXPECTED_DEFAULT_PASSWORD_WORKER_LIMIT


def test_password_worker_thread_limit_honors_positive_override() -> None:
    """A positive env override becomes the process-local password worker cap."""
    assert (
        _concurrency._resolve_password_worker_thread_limit(str(OVERRIDDEN_PASSWORD_WORKER_LIMIT))
        == OVERRIDDEN_PASSWORD_WORKER_LIMIT
    )


@pytest.mark.parametrize("raw_limit", ["", "not-an-int", "0", "-1"])
def test_password_worker_thread_limit_rejects_invalid_override(raw_limit: str) -> None:
    """Invalid env overrides fail with an actionable configuration error."""
    with pytest.raises(
        ConfigurationError,
        match=r"LITESTAR_AUTH_PASSWORD_WORKER_THREAD_LIMIT must be a positive integer",
    ):
        _concurrency._resolve_password_worker_thread_limit(raw_limit)


async def test_password_worker_thread_seam_passes_dedicated_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Password offloads pass the loop-scoped limiter to AnyIO's worker-thread API."""
    limiters: list[object] = []

    async def run_sync_spy(func: Callable[..., object], *args: object, limiter: object | None = None) -> object:
        limiters.append(limiter)
        await anyio.lowlevel.checkpoint()
        return func(*args)

    monkeypatch.setattr(_concurrency, "_run_sync_in_worker_thread", run_sync_spy)

    first_result = await _concurrency.run_password_op_in_worker_thread(str.upper, "secret")
    second_result = await _concurrency.run_password_op_in_worker_thread(str.lower, "SECRET")

    assert first_result == "SECRET"
    assert second_result == "secret"
    loop_limiter = _concurrency._password_op_limiter()
    assert limiters == [loop_limiter, loop_limiter]
    assert loop_limiter.total_tokens == _concurrency.PASSWORD_WORKER_THREAD_LIMIT


def test_password_op_limiter_is_created_per_event_loop() -> None:
    """Each event loop gets its own limiter; one loop reuses a single instance."""

    async def collect_limiter() -> tuple[object, object]:
        await anyio.lowlevel.checkpoint()
        return _concurrency._password_op_limiter(), _concurrency._password_op_limiter()

    first_a, first_b = anyio.run(collect_limiter)
    second_a, _second_b = anyio.run(collect_limiter)

    assert first_a is first_b
    assert second_a is not first_a
