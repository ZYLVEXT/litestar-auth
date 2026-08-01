"""Behavior tests for the shared replay/nonce contracts."""

from __future__ import annotations

import pytest
from authweave_core import InMemoryReplayStore, ReplayOutcome, ReplayStore, validate_replay_key

pytestmark = pytest.mark.unit


class _Clock:
    """Deterministic monotonic clock."""

    def __init__(self) -> None:
        """Start at zero."""
        self.now = 0.0

    def __call__(self) -> float:
        """Return the current time.

        Returns:
            The current monotonic time.
        """
        return self.now


def test_in_memory_store_satisfies_protocol() -> None:
    store = InMemoryReplayStore(capacity=4, time_source=_Clock())

    assert isinstance(store, ReplayStore)


async def test_first_presentation_stored_then_replay() -> None:
    store = InMemoryReplayStore(capacity=4, time_source=_Clock())

    assert await store.check_and_store("issuer|jkt|jti", ttl_seconds=30) is ReplayOutcome.STORED
    assert await store.check_and_store("issuer|jkt|jti", ttl_seconds=30) is ReplayOutcome.REPLAY


async def test_expired_key_can_be_stored_again() -> None:
    clock = _Clock()
    store = InMemoryReplayStore(capacity=4, time_source=clock)
    await store.check_and_store("nonce", ttl_seconds=30)

    clock.now = 31
    assert await store.check_and_store("nonce", ttl_seconds=30) is ReplayOutcome.STORED


async def test_capacity_exhaustion_after_purge_is_reported() -> None:
    clock = _Clock()
    store = InMemoryReplayStore(capacity=2, time_source=clock)
    await store.check_and_store("a", ttl_seconds=30)
    await store.check_and_store("b", ttl_seconds=30)

    assert await store.check_and_store("c", ttl_seconds=30) is ReplayOutcome.CAPACITY_EXCEEDED


async def test_capacity_reclaimed_by_purging_expired_entries() -> None:
    clock = _Clock()
    store = InMemoryReplayStore(capacity=2, time_source=clock)
    await store.check_and_store("a", ttl_seconds=10)
    await store.check_and_store("b", ttl_seconds=30)

    clock.now = 11
    assert await store.check_and_store("c", ttl_seconds=30) is ReplayOutcome.STORED


def test_store_rejects_nonpositive_capacity() -> None:
    with pytest.raises(ValueError, match="capacity"):
        InMemoryReplayStore(capacity=0, time_source=_Clock())


@pytest.mark.parametrize("key", ["", "x" * 513])
def test_validate_replay_key_rejects_unbounded_keys(key: str) -> None:
    with pytest.raises(ValueError, match="replay key"):
        validate_replay_key(key)


async def test_store_rejects_nonpositive_ttl() -> None:
    store = InMemoryReplayStore(capacity=4, time_source=_Clock())

    with pytest.raises(ValueError, match="ttl_seconds"):
        await store.check_and_store("nonce", ttl_seconds=0)
