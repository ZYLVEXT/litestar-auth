"""Tests for single-use account-token replay storage."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import litestar_auth.authentication.strategy._jwt_denylist as jwt_denylist_module
from litestar_auth._redis_protocols import RedisExpiringValueStoreClient
from litestar_auth.authentication.strategy._jwt_denylist import (
    InMemoryJWTDenylistStore,
    JWTReplayStoreResult,
    RedisJWTDenylistStore,
    denylist_ttl_seconds,
)
from tests._helpers import cast_fakeredis

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("expiration", [True, "tomorrow", float("inf"), float("nan")])
def test_denylist_ttl_falls_back_for_invalid_expiration(expiration: object) -> None:
    """Malformed JWT expiration claims retain the deny marker for the safe minimum."""
    assert denylist_ttl_seconds(expiration, now=0) == 1


def test_in_memory_store_rejects_nonpositive_capacity() -> None:
    """An in-memory denylist must retain at least one revocation."""
    with pytest.raises(ValueError, match="at least 1"):
        InMemoryJWTDenylistStore(max_entries=0)


async def test_in_memory_store_refreshes_existing_denial_and_fails_closed_at_capacity() -> None:
    """Existing revocations refresh while new ones are rejected at capacity."""
    store = InMemoryJWTDenylistStore(max_entries=1)

    assert await store.deny("first", ttl_seconds=1)
    assert await store.deny("first", ttl_seconds=60)
    assert not await store.deny("second", ttl_seconds=60)


async def test_in_memory_store_discards_expired_denials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expired entries are removed both on lookup and during pruning."""
    store = InMemoryJWTDenylistStore()
    store._denylisted_until.update({"lookup": 1.0, "prune": 1.0})
    monkeypatch.setattr(jwt_denylist_module.time, "time", lambda: 2.0)

    assert not await store.is_denied("lookup")
    store._prune_expired(2.0)
    assert store._denylisted_until == {}


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
