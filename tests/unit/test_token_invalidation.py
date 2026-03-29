"""Unit tests for token invalidation on credential changes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.strategy.db import AsyncSessionT, DatabaseTokenStrategy
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy
from litestar_auth.manager import BaseUserManager
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import UserUpdate

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"

pytestmark = pytest.mark.unit


@dataclass(slots=True)
class _User:
    id: UUID
    email: str
    hashed_password: str
    is_active: bool = True
    is_verified: bool = True


@dataclass(slots=True)
class _Backend:
    strategy: object


@dataclass(slots=True)
class _Strategy:
    invalidate_all_tokens: AsyncMock


@pytest.mark.unit
async def test_manager_reset_password_invalidates_tokens_when_supported() -> None:
    """reset_password() calls invalidate_all_tokens on configured backend strategies."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-secret-1234567890-1234567890",
        id_parser=UUID,
    )
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("old-password"))
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))

    user_db.get.return_value = user
    user_db.update.return_value = updated_user

    invalidate = AsyncMock()
    cast("object", manager).backends = [_Backend(strategy=_Strategy(invalidate_all_tokens=invalidate))]  # ty: ignore[unresolved-attribute]

    token = manager._write_token(
        user,
        secret=manager.reset_password_token_secret.get_secret_value(),
        audience="litestar-auth:reset-password",
        lifetime=manager.reset_password_token_lifetime,
    )

    result = await manager.reset_password(token, "new-password")

    assert result is updated_user
    invalidate.assert_awaited_once_with(updated_user)


@pytest.mark.unit
async def test_manager_update_invalidates_tokens_only_on_email_or_password_change() -> None:
    """update() invalidates tokens only when email or password changes."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-secret-1234567890-1234567890",
        id_parser=UUID,
    )
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("old-password"))

    invalidate = AsyncMock()
    cast("object", manager).backends = [_Backend(strategy=_Strategy(invalidate_all_tokens=invalidate))]  # ty: ignore[unresolved-attribute]

    # Non-credential update does not invalidate.
    user_db.update.return_value = user
    await manager.update(UserUpdate(is_active=False), user)
    invalidate.assert_not_awaited()

    # Email change invalidates once.
    updated_email_user = replace(user, email="new@example.com", is_verified=False)
    user_db.get_by_email.return_value = None
    user_db.update.return_value = updated_email_user
    await manager.update(UserUpdate(email="new@example.com"), user)
    invalidate.assert_awaited_once_with(updated_email_user)

    invalidate.reset_mock()

    # Password change invalidates once.
    updated_password_user = replace(user, hashed_password=password_helper.hash("new-password"))
    user_db.update.return_value = updated_password_user
    await manager.update(UserUpdate(password="new-password"), user)
    invalidate.assert_awaited_once_with(updated_password_user)


class _FakeRedis:
    """Minimal async Redis double with scan support."""

    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.sets: dict[str, set[str]] = {}
        self.deleted: list[str] = []

    async def get(self, name: str, /) -> bytes | str | None:
        return self.values.get(name)

    async def setex(self, name: str, time: int, value: str, /) -> object:
        del time
        self.values[name] = value.encode()
        return object()

    async def delete(self, *names: str) -> int:
        for name in names:
            self.deleted.append(name)
            self.values.pop(name, None)
            self.sets.pop(name, None)
        return len(names)

    async def sadd(self, name: str, *values: str) -> int:
        bucket = self.sets.setdefault(name, set())
        before = len(bucket)
        bucket.update(values)
        return len(bucket) - before

    async def srem(self, name: str, *values: str) -> int:
        bucket = self.sets.get(name)
        if not bucket:
            return 0
        before = len(bucket)
        for value in values:
            bucket.discard(value)
        return before - len(bucket)

    async def smembers(self, name: str) -> set[bytes]:
        return {member.encode() for member in self.sets.get(name, set())}

    async def expire(self, name: str, time: int) -> bool:
        del name, time
        return True

    def scan_iter(
        self,
        match: object | None = None,
        count: int | None = None,
        _type: str | None = None,
        **kwargs: object,
    ) -> AsyncIterator[str]:
        del count
        del _type
        del kwargs

        async def iterator() -> AsyncIterator[str]:  # noqa: RUF029
            if not isinstance(match, str):
                return

            prefix = match.removesuffix("*")
            for key in list(self.values):
                if key.startswith(prefix):
                    yield key

        return iterator()


@pytest.mark.unit
async def test_redis_strategy_invalidate_all_tokens_deletes_only_matching_subjects() -> None:
    """Redis invalidation scans keys and removes those belonging to the user."""
    redis = _FakeRedis()
    strategy = RedisTokenStrategy(
        redis=redis,
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        key_prefix="litestar_auth:token:",
    )

    user = _User(id=uuid4(), email="user@example.com", hashed_password="hashed")

    other_user = _User(id=uuid4(), email="other@example.com", hashed_password="hashed")

    await redis.setex("litestar_auth:token:token-a", 10, str(user.id))
    await redis.setex("litestar_auth:token:token-b", 10, str(other_user.id))
    await redis.setex("litestar_auth:token:token-c", 10, str(user.id))
    await redis.setex("other-prefix:token-d", 10, str(user.id))

    await strategy.invalidate_all_tokens(user)

    assert sorted(redis.deleted) == sorted(
        [
            "litestar_auth:token:token-a",
            "litestar_auth:token:token-c",
        ],
    )


@pytest.mark.unit
async def test_database_strategy_invalidate_all_tokens_deletes_by_user_id() -> None:
    """Database invalidation deletes both access and refresh tokens."""
    repo = AsyncMock()
    refresh_repo = AsyncMock()
    session = cast("AsyncSessionT", AsyncMock())
    strategy = DatabaseTokenStrategy(
        session=session,
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    db_user = User(id=uuid4(), email="user@example.com", hashed_password="hashed")

    with (
        patch.object(DatabaseTokenStrategy, "_repository", return_value=repo),
        patch.object(DatabaseTokenStrategy, "_refresh_repository", return_value=refresh_repo),
    ):
        await strategy.invalidate_all_tokens(db_user)

    repo.delete_where.assert_awaited_once_with(user_id=db_user.id, auto_commit=False)
    refresh_repo.delete_where.assert_awaited_once_with(user_id=db_user.id, auto_commit=False)
