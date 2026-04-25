"""Unit tests for token invalidation on credential changes."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.strategy.db import AsyncSessionT, DatabaseTokenStrategy
from litestar_auth.authentication.strategy.redis import RedisClientProtocol, RedisTokenStrategy
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import AdminUserUpdate, UserUpdate
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
INDEXED_TOKEN_COUNT = 2

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
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        ),
    )
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("old-password"))
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))

    user_db.get.return_value = user
    user_db.update.return_value = updated_user

    invalidate = AsyncMock()
    cast("object", manager).backends = [_Backend(strategy=_Strategy(invalidate_all_tokens=invalidate))]  # ty: ignore[unresolved-attribute]

    token = manager.tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())

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
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            id_parser=UUID,
        ),
    )
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("old-password"))

    invalidate = AsyncMock()
    cast("object", manager).backends = [_Backend(strategy=_Strategy(invalidate_all_tokens=invalidate))]  # ty: ignore[unresolved-attribute]

    # Non-credential, non-privileged update does not invalidate.
    user_db.update.return_value = user
    await manager.update({"bio": "updated"}, user)
    user_db.update.assert_awaited_once_with(user, {"bio": "updated"})
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
    await manager.update(AdminUserUpdate(password="new-password"), user)
    invalidate.assert_awaited_once_with(updated_password_user)


@pytest.mark.unit
async def test_redis_strategy_invalidate_all_tokens_deletes_only_matching_subjects(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis invalidation removes keys recorded in the user's token index."""
    strategy = RedisTokenStrategy(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        key_prefix="litestar_auth:token:",
    )

    user = _User(id=uuid4(), email="user@example.com", hashed_password="hashed")
    other_user = _User(id=uuid4(), email="other@example.com", hashed_password="hashed")

    assert await async_fakeredis.setex("litestar_auth:token:token-a", 10, str(user.id)) is True
    assert await async_fakeredis.setex("litestar_auth:token:token-b", 10, str(other_user.id)) is True
    assert await async_fakeredis.setex("litestar_auth:token:token-c", 10, str(user.id)) is True
    assert await async_fakeredis.setex("other-prefix:token-d", 10, str(user.id)) is True
    indexed_token_count = await async_fakeredis.sadd(  # ty: ignore[invalid-await]
        strategy._user_index_key(str(user.id)),
        "litestar_auth:token:token-a",
        "litestar_auth:token:token-c",
    )
    assert indexed_token_count == INDEXED_TOKEN_COUNT

    await strategy.invalidate_all_tokens(user)

    assert await async_fakeredis.get("litestar_auth:token:token-a") is None
    assert await async_fakeredis.get("litestar_auth:token:token-c") is None
    assert await async_fakeredis.get("litestar_auth:token:token-b") == str(other_user.id).encode()
    assert await async_fakeredis.get("other-prefix:token-d") == str(user.id).encode()
    assert await async_fakeredis.exists(strategy._user_index_key(str(user.id))) == 0


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
