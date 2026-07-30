"""Tests for single-use account-token replay storage."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from litestar_auth._redis_protocols import RedisExpiringValueStoreClient
from litestar_auth.authentication.strategy._jwt_denylist import (
    InMemoryJWTDenylistStore,
    JWTReplayStoreResult,
    RedisJWTDenylistStore,
)
from tests._helpers import cast_fakeredis

pytestmark = pytest.mark.unit


async def test_in_memory_store_allows_one_concurrent_consumer() -> None:
    """Only one concurrent consumer records a single-use token."""
    store = InMemoryJWTDenylistStore()

    results = await asyncio.gather(
        store.mark_used("single-use", ttl_seconds=60),
        store.mark_used("single-use", ttl_seconds=60),
    )

    assert results.count(JWTReplayStoreResult(stored=True)) == 1
    assert results.count(JWTReplayStoreResult(stored=False, rejected_as_replay=True)) == 1


async def test_in_memory_store_fails_closed_at_capacity() -> None:
    """Capacity pressure cannot evict a still-active replay marker."""
    store = InMemoryJWTDenylistStore(max_entries=1)

    assert await store.mark_used("first", ttl_seconds=60) == JWTReplayStoreResult(stored=True)
    assert await store.mark_used("second", ttl_seconds=60) == JWTReplayStoreResult(stored=False)


async def test_redis_store_atomically_rejects_replay(async_fakeredis: Any) -> None:  # ruff: ignore[any-type]
    """Redis SET NX gives shared atomic replay rejection."""
    store = RedisJWTDenylistStore(
        redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient),
    )

    assert await store.mark_used("single-use", ttl_seconds=60) == JWTReplayStoreResult(stored=True)
    assert await store.mark_used("single-use", ttl_seconds=60) == JWTReplayStoreResult(
        stored=False,
        rejected_as_replay=True,
    )
