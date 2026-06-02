"""Regression: built-in Redis stores stay on redis-py 8 command surface (no SETEX)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest

from litestar_auth._totp_stores import RedisTotpEnrollmentStore, RedisUsedTotpCodeStore
from litestar_auth.authentication.strategy import redis as redis_strategy_module
from litestar_auth.authentication.strategy._jwt_denylist import RedisJWTDenylistStore
from litestar_auth.authentication.strategy.redis import (
    RedisClientProtocol,
    RedisTokenStrategy,
    RedisTokenStrategyConfig,
)
from litestar_auth.contrib.redis import RedisAuthClientProtocol
from litestar_auth.ratelimit import RedisRateLimiter
from litestar_auth.ratelimit import _redis as ratelimit_redis_module
from tests._helpers import ExampleUser, cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit

TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"


@pytest.fixture
def patch_redis_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid optional redis import during rate limiter construction."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_redis_module, "_load_redis_asyncio", load_redis)
    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)


async def test_builtin_redis_surface_uses_non_deprecated_commands(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """Built-in Redis stores must not hit redis-py 8 deprecations (pytest treats them as errors)."""
    redis = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    denylist = RedisJWTDenylistStore(redis=redis)
    await denylist.deny("jti-smoke", ttl_seconds=60)
    assert await denylist.is_denied("jti-smoke") is True

    enrollment = RedisTotpEnrollmentStore(redis=redis)
    user_id = str(uuid4())
    await enrollment.save(user_id=user_id, jti="pending-jti", secret="BASE32SECRET", ttl_seconds=120)

    used_codes = RedisUsedTotpCodeStore(redis=redis)
    await used_codes.mark_used(user_id=user_id, counter=42, ttl_seconds=30.0)

    limiter = RedisRateLimiter(redis=redis, max_attempts=2, window_seconds=60)
    key = "redis-py8:rate"
    await limiter.increment(key)
    await limiter.increment(key)
    assert await limiter.check(key) is False
    assert await limiter.retry_after(key) >= 0

    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, object](
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
            token_hash_secret=TOKEN_HASH_SECRET,
            lifetime=timedelta(minutes=5),
            token_bytes=16,
        ),
    )
    token = await strategy.write_token(user)
    await strategy.destroy_token(token, user)


def test_migration_doc_documents_redis_py8_upgrade() -> None:
    """Migration guide names the redis-py 8 pin and SET EX contract."""
    content = Path("docs/migration.md").read_text(encoding="utf-8")

    assert "## redis-py 8 (`litestar-auth[redis]`)" in content
    assert "redis>=8.0.0,<9.0.0" in content
    assert "SET ... EX=" in content
    assert "setex" in content.lower()


def test_redis_configuration_doc_documents_py8_client_requirements() -> None:
    """Redis configuration doc lists redis-py 8 client requirements."""
    content = Path("docs/configuration/redis.md").read_text(encoding="utf-8")

    assert "### redis-py 8 client requirements" in content
    assert "setex" in content.lower()
    assert "migration.md#redis-py-8-litestar-authredis" in content
