"""Extra tests for DB/Redis auth strategies to close remaining coverage."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import SessionBindable
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.models import User
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryUserDatabase,
    PluginUserManager,
)

REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"

pytestmark = pytest.mark.unit


@dataclass(slots=True)
class _DummyUser:
    """Minimal user object with an ``id`` attribute used by strategies."""

    id: UUID


class _DummyUserManager:
    async def get(self, user_id: Any) -> _DummyUser | None:  # noqa: ANN401
        return _DummyUser(UUID(str(user_id)))


class _FakeSession:
    """Async-session double used to exercise DatabaseTokenStrategy helpers."""

    def __init__(self) -> None:
        self.executed: list[Any] = []
        self.committed = False

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        del args, kwargs
        self.executed.append(statement)

        class _Result:
            rowcount = 1

        return _Result()

    async def commit(self) -> None:
        self.committed = True


class _FakeRedisClient:
    """Redis client double implementing the small protocol RedisTokenStrategy relies on."""

    def __init__(self) -> None:
        self.values: dict[str, str | bytes | None] = {}
        self.sets: dict[str, set[str]] = {}
        self.deleted: list[str] = []

    async def get(self, name: str, /) -> bytes | str | None:
        value = self.values.get(name)
        if isinstance(value, str):
            return value.encode()
        return value

    async def setex(self, name: str, time: int, value: str, /) -> object:
        del time
        self.values[name] = value
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
        match: Any | None = None,  # noqa: ANN401
        count: int | None = None,
        _type: str | None = None,
        **kwargs: Any,  # noqa: ANN401
    ) -> object:
        del count, _type, kwargs
        pattern = str(match or "*")
        prefix = pattern.removesuffix("*")

        async def _gen() -> object:  # noqa: RUF029
            for key in list(self.values):
                if key.startswith(prefix):
                    yield key

        return _gen()


def _minimal_plugin_config(
    *,
    backend: AuthenticationBackend[ExampleUser, UUID],
    allow_legacy_plaintext_tokens: bool = False,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase([])
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
        allow_legacy_plaintext_tokens=allow_legacy_plaintext_tokens,
    )


def test_database_token_strategy_with_session_clones_configuration() -> None:
    """with_session() should return a new instance bound to the provided session."""
    base_session = _FakeSession()
    strategy = DatabaseTokenStrategy(
        session=cast("Any", base_session),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    other_session = _FakeSession()
    cloned = strategy.with_session(cast("Any", other_session))

    assert cloned is not strategy
    assert isinstance(cloned, DatabaseTokenStrategy)
    assert cloned.session is other_session
    assert cloned.max_age == strategy.max_age
    assert cloned.refresh_max_age == strategy.refresh_max_age
    assert cloned.token_bytes == strategy.token_bytes


def test_database_token_strategy_is_session_bindable() -> None:
    """DatabaseTokenStrategy should satisfy the runtime session-binding protocol."""
    strategy = DatabaseTokenStrategy(
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    assert isinstance(strategy, SessionBindable)


def test_database_token_strategy_accepts_user_uuid_type_parameters() -> None:
    """`DatabaseTokenStrategy[UP, ID]` specializes cleanly to the bundled ORM user and id."""
    strategy = DatabaseTokenStrategy[User, UUID](
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )
    assert isinstance(strategy, SessionBindable)
    assert isinstance(strategy, DatabaseTokenStrategy)


def test_database_token_strategy_warns_when_accepting_legacy_plaintext_tokens(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """accept_legacy_plaintext_tokens should emit a warning outside testing mode."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    caplog.clear()
    with caplog.at_level("WARNING"):
        DatabaseTokenStrategy(
            session=cast("Any", _FakeSession()),
            token_hash_secret="test-token-hash-secret-1234567890-1234567890",
            accept_legacy_plaintext_tokens=True,
        )
    assert any(
        "accept legacy plaintext tokens" in record.getMessage().lower()
        for record in caplog.records
        if record.levelname == "WARNING"
    )


def test_plugin_rejects_legacy_plaintext_tokens_without_explicit_rollout_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin config fails fast when legacy plaintext mode is enabled without explicit opt-in."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    strategy = DatabaseTokenStrategy(
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
        accept_legacy_plaintext_tokens=True,
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="db",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_plugin_config(backend=backend)

    with pytest.raises(ValueError, match=r"allow_legacy_plaintext_tokens=True"):
        LitestarAuth(config)


def test_plugin_allows_legacy_plaintext_tokens_with_explicit_rollout_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plugin config allows migration mode only when explicitly acknowledged."""
    monkeypatch.delenv("LITESTAR_AUTH_TESTING", raising=False)
    strategy = DatabaseTokenStrategy(
        session=cast("Any", _FakeSession()),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
        accept_legacy_plaintext_tokens=True,
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="db",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_plugin_config(
        backend=backend,
        allow_legacy_plaintext_tokens=True,
    )

    plugin = LitestarAuth(config)
    assert plugin is not None


@pytest.mark.asyncio
async def test_database_token_strategy_cleanup_expired_tokens_uses_rowcount_and_commit() -> None:
    """cleanup_expired_tokens() should execute deletes for both models and commit once."""
    session = _FakeSession()
    strategy = DatabaseTokenStrategy(
        session=cast("Any", session),
        token_hash_secret="test-token-hash-secret-1234567890-1234567890",
    )

    deleted = await strategy.cleanup_expired_tokens(cast("Any", session))

    expected_deleted = 2
    assert deleted == expected_deleted
    assert session.committed is True
    # Ensure both AccessToken and RefreshToken DELETEs were executed (matches ``delete(Model).where(...)``).
    stmt_text = " ".join(str(stmt).lower() for stmt in session.executed)
    assert "access_token" in stmt_text
    assert "refresh_token" in stmt_text


@pytest.mark.asyncio
async def test_redis_token_strategy_read_token_none_and_invalidate_all_tokens() -> None:
    """RedisTokenStrategy.read_token(None) and invalidate_all_tokens should cover remaining branches."""
    redis_client = _FakeRedisClient()
    strategy = RedisTokenStrategy(redis=cast("Any", redis_client), token_hash_secret=REDIS_TOKEN_HASH_SECRET)
    user_manager = _DummyUserManager()

    # read_token(None, ...) early-return branch.
    assert await strategy.read_token(None, user_manager) is None

    user = _DummyUser(uuid4())
    token = await strategy.write_token(user)
    redis_client.sets.clear()

    # Add a key with no stored user id to hit the "stored_user_id is None" continue branch.
    redis_client.values[strategy._key("orphan")] = None

    await strategy.invalidate_all_tokens(user)

    # The user's token key should be deleted; the orphan remains untouched.
    assert strategy._key(token) not in redis_client.values
    assert strategy._key("orphan") in redis_client.values


@pytest.mark.asyncio
async def test_redis_token_strategy_invalidate_all_tokens_uses_index_when_present() -> None:
    """invalidate_all_tokens() should prefer the per-user index when it exists."""
    redis_client = _FakeRedisClient()
    strategy = RedisTokenStrategy(redis=cast("Any", redis_client), token_hash_secret=REDIS_TOKEN_HASH_SECRET)
    user = _DummyUser(uuid4())
    token = await strategy.write_token(user)

    await strategy.invalidate_all_tokens(user)

    assert strategy._key(token) not in redis_client.values
    assert strategy._user_index_key(str(user.id)) not in redis_client.sets


@pytest.mark.asyncio
async def test_redis_token_strategy_invalidate_all_tokens_scan_skips_foreign_keys() -> None:
    """Fallback scanning should ignore keys that belong to other users."""
    redis_client = _FakeRedisClient()
    strategy = RedisTokenStrategy(redis=cast("Any", redis_client), token_hash_secret=REDIS_TOKEN_HASH_SECRET)
    user = _DummyUser(uuid4())
    other_user = _DummyUser(uuid4())
    token = await strategy.write_token(other_user)
    redis_client.sets.clear()

    await strategy.invalidate_all_tokens(user)

    assert strategy._key(token) in redis_client.values
