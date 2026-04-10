"""Smoke tests for the shared fakeredis baseline fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis, AsyncFakeRedisFactory, FakeRedisServerFactory

pytestmark = pytest.mark.unit


async def test_async_fakeredis_supports_async_commands_and_lua(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The shared fakeredis fixture supports async Redis commands and Lua scripts."""
    assert await async_fakeredis.ping() is True  # ty: ignore[invalid-await]
    assert await async_fakeredis.set("fixture:key", "fixture-value") is True
    assert await async_fakeredis.get("fixture:key") == b"fixture-value"
    assert await async_fakeredis.eval("return redis.call('GET', KEYS[1])", 1, "fixture:key") == b"fixture-value"  # ty: ignore[invalid-await]


async def test_async_fakeredis_factory_shares_default_state_and_isolates_servers(
    async_fakeredis_factory: AsyncFakeRedisFactory,
    fakeredis_server_factory: FakeRedisServerFactory,
) -> None:
    """Clients on one fake server share state while different servers stay isolated."""
    shared_client = async_fakeredis_factory()
    shared_peer = async_fakeredis_factory()
    isolated_client = async_fakeredis_factory(server=fakeredis_server_factory())

    assert await shared_client.set("shared:key", "shared-value") is True
    assert await shared_peer.get("shared:key") == b"shared-value"
    assert await isolated_client.get("shared:key") is None
