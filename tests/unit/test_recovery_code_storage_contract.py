"""Unit coverage for the TOTP recovery-code storage contract."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tests._helpers import ExampleUser
from tests.integration.conftest import InMemoryUserDatabase

pytestmark = pytest.mark.unit


async def test_in_memory_user_database_round_trips_recovery_code_hashes() -> None:
    """The shared in-memory store preserves hashed recovery-code values only."""
    user = ExampleUser(id=uuid4(), email="recovery@example.com")
    database = InMemoryUserDatabase([user])

    updated_user = await database.set_recovery_code_hashes(user, ("hash-1", "hash-2"))

    assert updated_user is user
    assert await database.read_recovery_code_hashes(user) == ("hash-1", "hash-2")


async def test_in_memory_user_database_consumes_recovery_code_hash_once() -> None:
    """The shared in-memory store consumes a matched hash at most once."""
    user = ExampleUser(id=uuid4(), email="consume@example.com", recovery_codes_hashes=["hash-1", "hash-2"])
    database = InMemoryUserDatabase([user])

    assert await database.consume_recovery_code_hash(user, "hash-1") is True
    assert await database.consume_recovery_code_hash(user, "hash-1") is False
    assert await database.read_recovery_code_hashes(user) == ("hash-2",)
