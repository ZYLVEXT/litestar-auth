"""Unit coverage for the TOTP recovery-code storage contract."""

from __future__ import annotations

from uuid import uuid4

import pytest

from litestar_auth._totp_stores import RedisUsedTotpCodeStore, UsedTotpCodeStore
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.totp import TotpRecoveryCodeUserManager
from tests._helpers import ExampleUser
from tests.integration.conftest import InMemoryUserDatabase

pytestmark = pytest.mark.unit

ATOMIC_CONCURRENCY_CLAUSE = "MUST observe exactly one success and N-1 failures"


async def test_in_memory_user_database_round_trips_recovery_code_hashes() -> None:
    """The shared in-memory store preserves recovery-code lookup indexes."""
    user = ExampleUser(id=uuid4(), email="recovery@example.com")
    database = InMemoryUserDatabase([user])

    updated_user = await database.set_recovery_code_hashes(user, {"lookup-1": "hash-1", "lookup-2": "hash-2"})

    assert updated_user is user
    assert await database.find_recovery_code_hash_by_lookup(user, "lookup-2") == "hash-2"


async def test_in_memory_user_database_consumes_recovery_code_hash_once() -> None:
    """The shared in-memory store consumes a matched lookup entry at most once."""
    user = ExampleUser(
        id=uuid4(),
        email="consume@example.com",
        recovery_codes={"lookup-1": "hash-1", "lookup-2": "hash-2"},
    )
    database = InMemoryUserDatabase([user])

    assert await database.consume_recovery_code_by_lookup(user, "lookup-1") is True
    assert await database.consume_recovery_code_by_lookup(user, "lookup-1") is False
    assert user.recovery_codes == {"lookup-2": "hash-2"}


@pytest.mark.parametrize(
    "method",
    [
        TotpRecoveryCodeUserManager.consume_recovery_code_by_lookup,
        SQLAlchemyUserDatabase.consume_recovery_code_by_lookup,
        UsedTotpCodeStore.mark_used,
        RedisUsedTotpCodeStore.mark_used,
    ],
)
def test_recovery_code_consume_contract_documents_atomic_concurrency(method: object) -> None:
    """Store contracts keep the atomic concurrent-consume guarantee visible."""
    normalized_docstring = " ".join(getattr(method, "__doc__", "").split())
    assert ATOMIC_CONCURRENCY_CLAUSE in normalized_docstring
