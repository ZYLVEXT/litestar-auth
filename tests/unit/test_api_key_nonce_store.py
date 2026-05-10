"""Tests for API-key signing nonce stores."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from litestar_auth.authentication.strategy._api_key_nonce_store import (
    InMemoryApiKeyNonceStore,
    RedisApiKeyNonceStore,
    RedisApiKeyNonceStoreClient,
)
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis
else:
    AsyncFakeRedis = Any

pytestmark = pytest.mark.unit


async def test_in_memory_api_key_nonce_store_rejects_replay_and_expires() -> None:
    """In-memory nonce storage rejects duplicates until the TTL passes."""
    current_time = 10.0

    def clock() -> float:
        return current_time

    store = InMemoryApiKeyNonceStore(clock=clock)

    first = await store.mark_used(key_id="key", nonce="nonce", ttl_seconds=2)
    replay = await store.mark_used(key_id="key", nonce="nonce", ttl_seconds=2)
    current_time = 13.0
    after_expiry = await store.mark_used(key_id="key", nonce="nonce", ttl_seconds=2)

    assert first.stored
    assert not replay.stored
    assert replay.rejected_as_replay
    assert after_expiry.stored


async def test_in_memory_api_key_nonce_store_fails_closed_at_capacity() -> None:
    """Capacity pressure rejects new nonces without evicting active entries."""
    store = InMemoryApiKeyNonceStore(max_entries=1)

    first = await store.mark_used(key_id="key", nonce="first", ttl_seconds=60)
    second = await store.mark_used(key_id="key", nonce="second", ttl_seconds=60)

    assert first.stored
    assert not second.stored
    assert not second.rejected_as_replay
    assert store.is_shared_across_workers is False


def test_in_memory_api_key_nonce_store_rejects_invalid_capacity() -> None:
    """In-memory nonce storage requires a positive capacity."""
    with pytest.raises(ValueError, match="max_entries"):
        InMemoryApiKeyNonceStore(max_entries=0)


async def test_redis_api_key_nonce_store_uses_atomic_set_nx(async_fakeredis: AsyncFakeRedis) -> None:
    """Redis nonce storage rejects replays and sets an expiring key."""
    store = RedisApiKeyNonceStore(redis=cast_fakeredis(async_fakeredis, RedisApiKeyNonceStoreClient))

    first = await store.mark_used(key_id="key", nonce="nonce", ttl_seconds=60)
    replay = await store.mark_used(key_id="key", nonce="nonce", ttl_seconds=60)

    assert first.stored
    assert not replay.stored
    assert replay.rejected_as_replay
    assert store.is_shared_across_workers is True
    assert await async_fakeredis.pttl("litestar_auth:api_key:nonce:key:nonce") > 0
