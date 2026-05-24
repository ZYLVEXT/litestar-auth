"""Unit tests for private async lock helpers."""

from __future__ import annotations

import asyncio

import pytest

from litestar_auth._locks import _BoundedAsyncLockRegistry

pytestmark = pytest.mark.unit


def test_bounded_async_lock_registry_rejects_empty_bound() -> None:
    """The bounded async lock registry requires at least one retained lock."""
    with pytest.raises(ValueError, match="max_size must be at least 1"):
        _BoundedAsyncLockRegistry[str](max_size=0)


def test_bounded_async_lock_registry_evicts_oldest_idle_entries() -> None:
    """The registry retains the most recent idle locks up to the configured bound."""
    registry = _BoundedAsyncLockRegistry[str](max_size=2)

    registry["first"]
    registry["second"]
    registry["third"]

    assert list(registry._locks) == ["second", "third"]
    assert len(registry) == registry.max_size


def test_bounded_async_lock_registry_refreshes_existing_key_recency() -> None:
    """Accessing an existing lock makes it the newest eviction candidate."""
    registry = _BoundedAsyncLockRegistry[str](max_size=2)

    registry["first"]
    registry["second"]
    registry["first"]
    registry["third"]

    assert list(registry._locks) == ["first", "third"]


async def test_bounded_async_lock_registry_excludes_new_key_when_eviction_runs() -> None:
    """A new key is not evicted immediately when older retained locks are held."""
    registry = _BoundedAsyncLockRegistry[str](max_size=1)
    first_lock = registry["first"]

    await first_lock.acquire()
    try:
        second_lock = registry["second"]

        assert list(registry._locks) == ["first", "second"]
        assert second_lock is registry._locks["second"]
    finally:
        first_lock.release()


async def test_bounded_async_lock_registry_prunes_held_overflow_after_release() -> None:
    """Held overflow entries are retained while active and pruned after release."""
    registry = _BoundedAsyncLockRegistry[str](max_size=1)
    entered_first_lock = asyncio.Event()
    release_first_lock = asyncio.Event()

    async def hold_first_lock() -> None:
        async with registry.lock("first"):
            entered_first_lock.set()
            await release_first_lock.wait()

    first_task = asyncio.create_task(hold_first_lock())
    try:
        await entered_first_lock.wait()
        async with registry.lock("second"):
            pass

        assert list(registry._locks) == ["first"]
    finally:
        release_first_lock.set()
        await first_task

    assert list(registry._locks) == ["first"]
