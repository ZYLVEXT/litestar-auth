"""Unit tests for JWT revocation behavior and posture contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import jwt
import pytest

from litestar_auth._redis_protocols import RedisExpiringValueStoreClient
from litestar_auth.authentication.strategy.jwt import (
    InMemoryJWTDenylistStore,
    JWTStrategy,
    RedisJWTDenylistStore,
)
from litestar_auth.password import PasswordHelper
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

DENYLIST_CAP = 2

pytestmark = pytest.mark.unit


@dataclass(slots=True)
class _User:
    id: UUID
    email: str
    hashed_password: str


class _UserManager:
    def __init__(self, user: _User) -> None:
        self.user = user

    async def get(self, user_id: Any) -> _User | None:  # noqa: ANN401
        return self.user if str(user_id) == str(self.user.id) else None


class _RecordingDenylistStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def deny(self, jti: str, *, ttl_seconds: int) -> None:
        self.calls.append((jti, ttl_seconds))

    async def is_denied(self, jti: str) -> bool:
        del jti
        return False


class _MissingUserManager:
    async def get(self, user_id: Any) -> _User | None:  # noqa: ANN401
        del user_id
        return None


@pytest.mark.unit
async def test_jwt_revocation_is_durable_across_strategy_instances(async_fakeredis: AsyncFakeRedis) -> None:
    """Revoking a token in one instance is enforced in another when using Redis denylist."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    user_manager = _UserManager(user)

    store = RedisJWTDenylistStore(redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient))

    strategy_a = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)
    strategy_b = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)

    token = await strategy_a.write_token(cast("Any", user))
    assert await strategy_b.read_token(token, cast("Any", user_manager)) is user

    await strategy_a.destroy_token(token, cast("Any", user))
    assert await strategy_b.read_token(token, cast("Any", user_manager)) is None


@pytest.mark.unit
async def test_jwt_session_fingerprint_invalidates_after_email_change() -> None:
    """Tokens minted with a session fingerprint must be rejected after email changes."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    user_manager = _UserManager(user)

    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890")
    token = await strategy.write_token(cast("Any", user))
    assert await strategy.read_token(token, cast("Any", user_manager)) is user

    user.email = "new@example.com"
    assert await strategy.read_token(token, cast("Any", user_manager)) is None


@pytest.mark.unit
async def test_jwt_without_fingerprint_claim_is_rejected_when_user_fingerprint_is_available() -> None:
    """Tokens without a fingerprint claim must fail closed for fingerprint-aware users."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    user_manager = _UserManager(user)

    secret = "secret-1234567890-1234567890-1234567890"
    strategy = JWTStrategy(secret=secret)

    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user.id),
        "aud": "litestar-auth:access",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "jti": "deadbeef",
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert await strategy.read_token(token, cast("Any", user_manager)) is None


@pytest.mark.unit
async def test_jwt_with_non_string_fingerprint_claim_is_rejected_when_user_fingerprint_is_available() -> None:
    """Non-string fingerprint claims must fail closed for fingerprint-aware users."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    user_manager = _UserManager(user)

    secret = "secret-1234567890-1234567890-1234567890"
    strategy = JWTStrategy(secret=secret)

    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user.id),
        "aud": "litestar-auth:access",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "jti": "deadbeef",
        "sfp": 123,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert await strategy.read_token(token, cast("Any", user_manager)) is None


@pytest.mark.unit
async def test_jwt_without_fingerprint_claim_keeps_graceful_degradation_when_user_fingerprint_is_unavailable() -> None:
    """Missing fingerprint claims are still allowed when the server cannot compute one."""
    user = _User(id=uuid4(), email="user@example.com", hashed_password="hashed")
    user_manager = _UserManager(user)
    secret = "secret-1234567890-1234567890-1234567890"
    strategy = JWTStrategy(secret=secret, session_fingerprint_getter=lambda _: None)

    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user.id),
        "aud": "litestar-auth:access",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "jti": "deadbeef",
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert await strategy.read_token(token, cast("Any", user_manager)) is user


@pytest.mark.unit
async def test_in_memory_jwt_denylist_honors_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-memory denylist entries expire after their configured TTL."""
    fake_now = 1_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt.time.time", fake_time)
    store = InMemoryJWTDenylistStore()
    await store.deny("jti-1", ttl_seconds=2)
    assert await store.is_denied("jti-1") is True

    fake_now += 3.0
    assert await store.is_denied("jti-1") is False


@pytest.mark.unit
async def test_in_memory_jwt_denylist_caps_entries_with_fifo_eviction() -> None:
    """Cap enforcement should evict the oldest active JTI before adding a new one."""
    store = InMemoryJWTDenylistStore(max_entries=DENYLIST_CAP)

    await store.deny("jti-1", ttl_seconds=60)
    await store.deny("jti-2", ttl_seconds=60)
    await store.deny("jti-3", ttl_seconds=60)

    assert len(store._denylisted_until) == DENYLIST_CAP
    assert "jti-1" not in store._denylisted_until
    assert set(store._denylisted_until) == {"jti-2", "jti-3"}


@pytest.mark.unit
async def test_in_memory_jwt_denylist_prunes_expired_entries_before_cap_eviction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cap enforcement should full-sweep expired entries before evicting active ones."""
    fake_now = 1_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt.time.time", fake_time)
    store = InMemoryJWTDenylistStore(max_entries=DENYLIST_CAP)

    await store.deny("expired", ttl_seconds=1)
    await store.deny("active", ttl_seconds=10)

    fake_now += 2.0
    await store.deny("fresh", ttl_seconds=10)

    assert len(store._denylisted_until) == DENYLIST_CAP
    assert "expired" not in store._denylisted_until
    assert set(store._denylisted_until) == {"active", "fresh"}


@pytest.mark.unit
def test_in_memory_jwt_denylist_rejects_non_positive_max_entries() -> None:
    """The in-memory denylist cap must be configured with a positive size."""
    with pytest.raises(ValueError, match="max_entries must be at least 1"):
        InMemoryJWTDenylistStore(max_entries=0)


@pytest.mark.unit
async def test_jwt_strategy_read_token_returns_none_when_user_manager_cannot_resolve_user() -> None:
    """A valid token should still be rejected when the subject no longer resolves to a user."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", subject_decoder=UUID)

    token = await strategy.write_token(cast("Any", user))

    assert await strategy.read_token(token, cast("Any", _MissingUserManager())) is None


@pytest.mark.unit
async def test_jwt_strategy_destroy_token_ignores_tokens_without_jti() -> None:
    """destroy_token() should skip denylist writes when the token has no JTI claim."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)

    now = datetime.now(tz=UTC)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": "litestar-auth:access",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        strategy.secret,
        algorithm=strategy.algorithm,
    )

    await strategy.destroy_token(token, cast("Any", user))

    assert store.calls == []


@pytest.mark.unit
async def test_jwt_strategy_destroy_token_uses_numeric_expiry_for_denylist_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """destroy_token() should derive the denylist TTL from the decoded integer exp claim."""
    fake_now = 1_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt.time.time", fake_time)
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": "litestar-auth:access",
            "iat": datetime.fromtimestamp(fake_now, tz=UTC),
            "nbf": datetime.fromtimestamp(fake_now, tz=UTC),
            "exp": int(fake_now) + 120,
            "jti": "ttl-claim-jti",
        },
        strategy.secret,
        algorithm=strategy.algorithm,
    )

    await strategy.destroy_token(token, cast("Any", user))

    assert store.calls == [("ttl-claim-jti", 120)]


@pytest.mark.unit
async def test_jwt_strategy_destroy_token_uses_minimum_ttl_when_exp_is_not_numeric() -> None:
    """destroy_token() should fall back to the minimum TTL when exp is absent or non-numeric."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": "litestar-auth:access",
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": "not-a-timestamp",
            "jti": "minimum-ttl-jti",
        },
        strategy.secret,
        algorithm=strategy.algorithm,
    )

    await strategy.destroy_token(token, cast("Any", user))

    assert store.calls == [("minimum-ttl-jti", 1)]


@pytest.mark.unit
async def test_jwt_strategy_read_token_returns_none_for_missing_input() -> None:
    """read_token() should return None immediately when no token is provided."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890")

    assert await strategy.read_token(None, cast("Any", _UserManager(user))) is None


@pytest.mark.unit
def test_jwt_strategy_revocation_posture_distinguishes_default_and_shared_store_modes(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Direct JWTStrategy wiring exposes explicit compatibility and shared-store branches."""
    default_strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890")
    shared_strategy = JWTStrategy(
        secret="secret-1234567890-1234567890-1234567890",
        denylist_store=RedisJWTDenylistStore(redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient)),
    )

    default_posture = default_strategy.revocation_posture
    assert default_posture.key == "compatibility_in_memory"
    assert default_posture.denylist_store_type == "InMemoryJWTDenylistStore"
    assert default_posture.revocation_is_durable is False
    assert default_strategy.revocation_is_durable is default_posture.revocation_is_durable
    assert default_posture.requires_explicit_production_opt_in is True
    assert default_posture.production_validation_error is not None
    assert default_posture.startup_warning is not None

    shared_posture = shared_strategy.revocation_posture
    assert shared_posture.key == "shared_store"
    assert shared_posture.denylist_store_type == "RedisJWTDenylistStore"
    assert shared_posture.revocation_is_durable is True
    assert shared_strategy.revocation_is_durable is shared_posture.revocation_is_durable
    assert shared_posture.requires_explicit_production_opt_in is False
    assert shared_posture.production_validation_error is None
    assert shared_posture.startup_warning is None


@pytest.mark.unit
async def test_jwt_redis_denylist_protocol_stubs_are_callable() -> None:
    """The minimal Redis protocol stub methods remain awaitable placeholders."""
    protocol_client = cast("RedisExpiringValueStoreClient", object())

    assert await RedisExpiringValueStoreClient.get(protocol_client, "jti-key") is None
    assert await RedisExpiringValueStoreClient.setex(protocol_client, "jti-key", 60, "1") is None


@pytest.mark.unit
async def test_jwt_strategy_is_token_denied_false_without_string_jti() -> None:
    """Denylist lookup runs only when ``jti`` is a string."""
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890")
    assert await strategy._is_token_denied({}) is False
    non_string_jti: dict[str, object] = {"jti": 123}
    assert await strategy._is_token_denied(non_string_jti) is False


@pytest.mark.unit
async def test_jwt_strategy_is_token_denied_delegates_to_store() -> None:
    """``_is_token_denied`` mirrors the configured denylist store."""
    store = InMemoryJWTDenylistStore()
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890", denylist_store=store)
    await store.deny("revoked-jti", ttl_seconds=3600)
    assert await strategy._is_token_denied({"jti": "revoked-jti"}) is True
    assert await strategy._is_token_denied({"jti": "active-jti"}) is False


@pytest.mark.unit
def test_jwt_strategy_validate_fingerprint_accepts_when_getter_returns_none() -> None:
    """When no server fingerprint exists, tokens are not rejected for missing claims."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    strategy = JWTStrategy(
        secret="secret-1234567890-1234567890-1234567890",
        session_fingerprint_getter=lambda _: None,
    )
    assert strategy._validate_fingerprint({}, cast("Any", user)) is True


@pytest.mark.unit
def test_jwt_strategy_validate_fingerprint_compares_digest() -> None:
    """Fingerprint helper enforces constant-time equality when both sides are present."""
    password_helper = PasswordHelper()
    user = _User(id=uuid4(), email="user@example.com", hashed_password=password_helper.hash("pw"))
    strategy = JWTStrategy(secret="secret-1234567890-1234567890-1234567890")
    current = strategy.session_fingerprint_getter(cast("Any", user))
    assert current is not None
    claim = strategy.session_fingerprint_claim
    assert strategy._validate_fingerprint({claim: current}, cast("Any", user)) is True
    assert strategy._validate_fingerprint({claim: "not-the-same"}, cast("Any", user)) is False
