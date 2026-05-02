"""Tests for :class:`~litestar_auth.authentication.strategy.jwt.JWTStrategy`."""

from __future__ import annotations

import hashlib
import hmac
import importlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest

from litestar_auth import _jwt_headers as jwt_headers_module
from litestar_auth._jwt_headers import jwt_encode_headers
from litestar_auth._redis_protocols import RedisExpiringValueStoreClient
from litestar_auth.authentication.strategy import _jwt_denylist as jwt_denylist_module
from litestar_auth.authentication.strategy import jwt as jwt_strategy_module
from litestar_auth.authentication.strategy.jwt import (
    JWT_ACCESS_TOKEN_AUDIENCE,
    InMemoryJWTDenylistStore,
    JWTStrategy,
    RedisJWTDenylistStore,
    _default_session_fingerprint,
)
from tests._helpers import ExampleUser, cast_fakeredis
from tests.unit.test_strategy import DEFAULT_SECRET, ExampleUserManager

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import ModuleType

    from litestar_auth.types import ID
    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit
REDIS_DENYLIST_TTL_SECONDS = 30
REDIS_DENYLIST_TTL_FLOOR = REDIS_DENYLIST_TTL_SECONDS - 1
MINIMUM_TTL_SECONDS = 1
MINIMUM_TTL_FLOOR = 0


def _jwt_module() -> ModuleType:
    """Import the JWT strategy module lazily so coverage records module execution.

    Returns:
        The runtime JWT strategy module object.
    """
    return importlib.import_module("litestar_auth.authentication.strategy.jwt")


class _RecordingDenylistStore:
    """Record denylist writes and membership checks."""

    def __init__(self) -> None:
        """Initialize the in-memory call recorder."""
        self.calls: list[tuple[str, int]] = []
        self.denied: set[str] = set()

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Store the denylist write call.

        Returns:
            ``True`` (test double always records successfully).
        """
        self.calls.append((jti, ttl_seconds))
        self.denied.add(jti)
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the given JTI has been recorded."""
        return jti in self.denied


class _MissingUserManager:
    """User manager that never resolves a user."""

    async def get(self, user_id: object) -> None:
        """Always return ``None`` to simulate a deleted user."""
        del user_id


def _subject_decoder_returns_none(_: str) -> None:
    """Misbehaving decoder: returns ``None`` instead of a user id or :exc:`ValueError`."""
    return


def _subject_decoder_raises_value_error(_: str) -> UUID:
    """Decoder that raises ``ValueError`` for invalid subject claims.

    Raises:
        ValueError: Always, to simulate a decoding failure.
    """
    msg = "invalid subject"
    raise ValueError(msg)


def _make_token(
    *,
    secret: str = DEFAULT_SECRET,
    payload: Mapping[str, object],
    algorithm: str = "HS256",
    headers: Mapping[str, object] | None = None,
) -> str:
    """Encode a JWT payload for strategy tests.

    Returns:
        Signed JWT string.
    """
    return jwt.encode(dict(payload), secret, algorithm=algorithm, headers=dict(headers or jwt_encode_headers()))


def test_jwt_module_executes_under_coverage() -> None:
    """Reload the JWT strategy module in-test so coverage records class-body execution."""
    reloaded_headers_module = importlib.reload(jwt_headers_module)
    reloaded_denylist_module = importlib.reload(jwt_denylist_module)
    reloaded_module = importlib.reload(jwt_strategy_module)

    assert reloaded_headers_module.jwt_encode_headers() == jwt_encode_headers()
    assert reloaded_module.JWTStrategy is _jwt_module().JWTStrategy
    assert reloaded_module.InMemoryJWTDenylistStore is reloaded_denylist_module.InMemoryJWTDenylistStore
    assert reloaded_module.RedisJWTDenylistStore is reloaded_denylist_module.RedisJWTDenylistStore


def test_in_memory_jwt_denylist_store_rejects_invalid_capacity() -> None:
    """The in-memory denylist requires a positive capacity."""
    with pytest.raises(ValueError, match="max_entries must be at least 1"):
        InMemoryJWTDenylistStore(max_entries=0)


async def test_in_memory_jwt_denylist_store_prunes_expired_entries_before_insert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired entries are swept so a new JTI can be admitted without hitting capacity."""
    fake_now = 1_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist.time.time", fake_time)
    store = InMemoryJWTDenylistStore(max_entries=2)
    await store.deny("expired", ttl_seconds=1)
    await store.deny("active", ttl_seconds=10)

    fake_now += 2.0
    await store.deny("fresh", ttl_seconds=10)

    assert set(store._denylisted_until) == {"active", "fresh"}


async def test_in_memory_jwt_denylist_store_fails_closed_under_capacity_pressure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At capacity with no reclaimable expired rows, a new deny is skipped; prior JTIs stay denied."""
    fake_now = 2_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist.time.time", fake_time)
    store = InMemoryJWTDenylistStore(max_entries=2)
    await store.deny("short", ttl_seconds=5)
    await store.deny("long", ttl_seconds=10)

    fake_now += 1.0
    await store.deny("new", ttl_seconds=20)

    assert set(store._denylisted_until) == {"short", "long"}
    assert await store.is_denied("short") is True
    assert await store.is_denied("long") is True
    assert await store.is_denied("new") is False


async def test_in_memory_jwt_denylist_store_expires_entries_during_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``is_denied`` drops stale entries after their TTL elapses."""
    fake_now = 3_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist.time.time", fake_time)
    store = InMemoryJWTDenylistStore()
    await store.deny("soon-expired", ttl_seconds=1)

    assert await store.is_denied("soon-expired") is True

    fake_now += 2.0
    assert await store.is_denied("soon-expired") is False
    assert "soon-expired" not in store._denylisted_until


async def test_in_memory_jwt_denylist_store_returns_false_for_unknown_jti() -> None:
    """Lookups for absent JTIs do not mutate the store and return ``False``."""
    store = InMemoryJWTDenylistStore()

    assert await store.is_denied("missing-jti") is False
    assert store._denylisted_until == {}


def test_in_memory_jwt_denylist_store_prunes_expired_entries_helper() -> None:
    """The explicit prune helper removes only entries already past their deadline."""
    store = InMemoryJWTDenylistStore()
    store._denylisted_until = {
        "expired": 10.0,
        "active": 20.0,
    }

    store._prune_expired(15.0)

    assert store._denylisted_until == {"active": 20.0}


def test_default_session_fingerprint_returns_digest_for_complete_user_model() -> None:
    """The default fingerprint getter hashes user id, normalized email, and password."""
    getter = _default_session_fingerprint(DEFAULT_SECRET.encode())
    user = ExampleUser(
        id=uuid4(),
        email="USER@example.com",
        hashed_password="hashed-password",
    )

    expected = hmac.new(
        DEFAULT_SECRET.encode(),
        f"{user.id}\x1fuser@example.com\x1f{user.hashed_password}".encode(),
        hashlib.sha256,
    ).hexdigest()

    assert getter(user) == expected


def test_default_session_fingerprint_returns_none_when_required_fields_are_missing() -> None:
    """The default fingerprint getter refuses incomplete user-like objects."""
    getter = _default_session_fingerprint(DEFAULT_SECRET.encode())
    incomplete_user = object()

    assert getter(incomplete_user) is None


async def test_redis_jwt_denylist_store_round_trips_keys(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis-backed denylist storage uses the configured prefix and TTL."""
    store = RedisJWTDenylistStore(
        redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient),
        key_prefix="test:",
    )

    await store.deny("revoked-jti", ttl_seconds=REDIS_DENYLIST_TTL_SECONDS)

    assert await async_fakeredis.get("test:revoked-jti") == b"1"
    assert REDIS_DENYLIST_TTL_FLOOR <= await async_fakeredis.ttl("test:revoked-jti") <= REDIS_DENYLIST_TTL_SECONDS
    assert await store.is_denied("revoked-jti") is True
    assert await store.is_denied("active-jti") is False


async def test_jwt_redis_denylist_protocol_stubs_are_callable() -> None:
    """The protocol placeholder methods remain awaitable no-ops."""
    protocol_client = cast("RedisExpiringValueStoreClient", object())

    assert await RedisExpiringValueStoreClient.get(protocol_client, "jti-key") is None
    assert await RedisExpiringValueStoreClient.setex(protocol_client, "jti-key", 60, "1") is None


async def test_redis_jwt_denylist_store_enforces_minimum_ttl(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis denylist writes clamp non-positive TTLs to one second."""
    store = RedisJWTDenylistStore(redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient))

    await store.deny("revoked-jti", ttl_seconds=0)

    key = "litestar_auth:jwt:denylist:revoked-jti"
    assert await async_fakeredis.get(key) == b"1"
    assert MINIMUM_TTL_FLOOR <= await async_fakeredis.ttl(key) <= MINIMUM_TTL_SECONDS


def test_jwt_strategy_rejects_unsupported_algorithms() -> None:
    """Initialization fails fast for algorithms outside the allow list."""
    with pytest.raises(ValueError, match="Unsupported JWT algorithm 'none'"):
        JWTStrategy(secret=DEFAULT_SECRET, algorithm="none", allow_inmemory_denylist=True)


def test_jwt_strategy_requires_explicit_revocation_store_or_inmemory_opt_in() -> None:
    """Constructing JWTStrategy without revocation storage fails closed."""
    with pytest.raises(ValueError, match="requires explicit JWT revocation storage"):
        JWTStrategy(secret=DEFAULT_SECRET)


def test_jwt_strategy_rejects_conflicting_revocation_configuration() -> None:
    """Callers must pick one JWT revocation configuration path."""
    with pytest.raises(ValueError, match="cannot be combined with denylist_store"):
        JWTStrategy(
            secret=DEFAULT_SECRET,
            denylist_store=_RecordingDenylistStore(),
            allow_inmemory_denylist=True,
        )


def test_jwt_strategy_revocation_posture_reports_explicit_inmemory_mode() -> None:
    """Explicit in-memory opt-in reports the process-local revocation contract."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)

    assert strategy.revocation_posture.key == "in_memory"
    assert strategy.revocation_posture.denylist_store_type == "InMemoryJWTDenylistStore"
    assert strategy.revocation_posture.revocation_is_durable is False
    assert strategy.revocation_posture.requires_explicit_production_opt_in is False
    assert strategy.revocation_posture.production_validation_error is None
    assert strategy.revocation_posture.startup_warning is not None


def test_jwt_strategy_revocation_posture_reports_shared_store_mode(async_fakeredis: AsyncFakeRedis) -> None:
    """Shared denylist backends expose the durable shared-store posture."""
    shared_store = RedisJWTDenylistStore(redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient))
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=shared_store)

    assert strategy.revocation_posture.key == "shared_store"
    assert strategy.revocation_posture.denylist_store_type == "RedisJWTDenylistStore"
    assert strategy.revocation_posture.revocation_is_durable is True
    assert strategy.revocation_posture.requires_explicit_production_opt_in is False
    assert strategy.revocation_posture.production_validation_error is None
    assert strategy.revocation_posture.startup_warning is None


def test_jwt_strategy_revocation_is_durable_reflects_store_backend(async_fakeredis: AsyncFakeRedis) -> None:
    """Shared denylist backends report durable revocation."""
    shared_store = RedisJWTDenylistStore(redis=cast_fakeredis(async_fakeredis, RedisExpiringValueStoreClient))

    assert JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True).revocation_is_durable is False
    assert JWTStrategy(secret=DEFAULT_SECRET, denylist_store=shared_store).revocation_is_durable is True


async def test_jwt_strategy_is_token_denied_ignores_non_string_jti() -> None:
    """Only string JTI claims trigger denylist lookups."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=_RecordingDenylistStore())

    assert await strategy._is_token_denied({}) is False
    assert await strategy._is_token_denied({"jti": 123}) is False


async def test_jwt_strategy_is_token_denied_delegates_to_store() -> None:
    """Denylist lookups are delegated to the configured store."""
    store = _RecordingDenylistStore()
    store.denied.add("blocked")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)

    assert await strategy._is_token_denied({"jti": "blocked"}) is True
    assert await strategy._is_token_denied({"jti": "allowed"}) is False


def test_jwt_strategy_validate_fingerprint_handles_missing_and_mismatched_claims() -> None:
    """Fingerprint validation rejects missing claims and mismatches for fingerprinted users."""
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)
    current = strategy.session_fingerprint_getter(user)

    assert current is not None
    claim = strategy.session_fingerprint_claim
    assert strategy._validate_fingerprint({claim: current}, user) is True
    assert strategy._validate_fingerprint({}, user) is False
    assert strategy._validate_fingerprint({claim: "other"}, user) is False


def test_jwt_strategy_validate_fingerprint_accepts_missing_server_fingerprint_without_claim() -> None:
    """Fingerprint validation is skipped only when both sides are absent."""
    strategy = JWTStrategy(
        secret=DEFAULT_SECRET,
        session_fingerprint_getter=lambda _: None,
        allow_inmemory_denylist=True,
    )
    user = ExampleUser(id=uuid4())

    assert strategy._validate_fingerprint({}, cast("Any", user)) is True
    assert strategy._validate_fingerprint({"sfp": "token-value"}, cast("Any", user)) is False


def test_jwt_strategy_validate_fingerprint_rejects_missing_token_claim_for_known_fingerprint() -> None:
    """A user fingerprint that exists server-side must also be present in the token."""
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)

    assert strategy._validate_fingerprint({}, user) is False


def test_jwt_strategy_decodes_verified_tokens_with_and_without_issuer() -> None:
    """Verified token decoding enforces issuer only when configured."""
    user = ExampleUser(id=uuid4())
    now = datetime.now(tz=UTC)
    base_payload = {
        "sub": str(user.id),
        "aud": JWT_ACCESS_TOKEN_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": "decode-jti",
    }
    strategy_without_issuer = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)
    strategy_with_issuer = JWTStrategy(secret=DEFAULT_SECRET, issuer="litestar-auth", allow_inmemory_denylist=True)

    assert strategy_without_issuer._decode_verified_access_token(_make_token(payload=base_payload)) is not None
    assert (
        strategy_with_issuer._decode_verified_access_token(
            _make_token(payload={**base_payload, "iss": "litestar-auth"}),
        )
        is not None
    )
    assert strategy_with_issuer._decode_verified_access_token(_make_token(payload=base_payload)) is None


@pytest.mark.parametrize("issuer", [None, "litestar-auth"])
def test_jwt_strategy_rejects_verified_access_token_with_unexpected_type_header(issuer: str | None) -> None:
    """Verified access-token decoding rejects signed JWTs with the wrong JOSE type."""
    user = ExampleUser(id=uuid4())
    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user.id),
        "aud": JWT_ACCESS_TOKEN_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": "wrong-typ-jti",
    }
    if issuer is not None:
        payload["iss"] = issuer
    strategy = JWTStrategy(secret=DEFAULT_SECRET, issuer=issuer, allow_inmemory_denylist=True)
    token = _make_token(payload=payload, headers={"typ": "not-jwt"})

    assert strategy._decode_verified_access_token(token) is None


def test_jwt_strategy_applies_bounded_clock_skew_leeway() -> None:
    """Verified token decoding tolerates small skew while still rejecting stale/future tokens."""
    user = ExampleUser(id=uuid4())
    now = datetime.now(tz=UTC)
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)

    slightly_expired = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now - timedelta(seconds=15),
            "nbf": now - timedelta(seconds=15),
            "exp": now - timedelta(seconds=5),
            "jti": "slightly-expired-jti",
        },
    )
    slightly_early = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now + timedelta(seconds=5),
            "exp": now + timedelta(minutes=5),
            "jti": "slightly-early-jti",
        },
    )
    stale = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now - timedelta(minutes=2),
            "nbf": now - timedelta(minutes=2),
            "exp": now - timedelta(seconds=45),
            "jti": "stale-jti",
        },
    )
    too_early = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now + timedelta(seconds=45),
            "exp": now + timedelta(minutes=5),
            "jti": "too-early-jti",
        },
    )

    assert strategy._decode_verified_access_token(slightly_expired) is not None
    assert strategy._decode_verified_access_token(slightly_early) is not None
    assert strategy._decode_verified_access_token(stale) is None
    assert strategy._decode_verified_access_token(too_early) is None


def test_jwt_strategy_decodes_invalid_token_as_none() -> None:
    """Invalid JWT payloads are rejected during verified decode."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)

    assert strategy._decode_verified_access_token("not-a-jwt") is None


async def test_jwt_strategy_read_token_returns_none_when_subject_decoder_returns_none() -> None:
    """A misbehaving decoder returning ``None`` prevents user-manager lookup."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(
        secret=DEFAULT_SECRET,
        subject_decoder=cast("Callable[[str], ID]", _subject_decoder_returns_none),
        allow_inmemory_denylist=True,
    )
    user_manager = ExampleUserManager(user)

    token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "jti": "decoder-none",
        },
    )

    assert await strategy.read_token(token, user_manager) is None
    assert user_manager.seen_user_ids == []


async def test_jwt_strategy_read_token_returns_none_when_token_is_missing() -> None:
    """Missing transport tokens short-circuit before decode or user lookup."""
    user_manager = AsyncMock()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)

    assert await strategy.read_token(None, user_manager) is None
    user_manager.get.assert_not_awaited()


@pytest.mark.parametrize(
    ("payload", "subject_decoder"),
    [
        pytest.param(
            {
                "aud": JWT_ACCESS_TOKEN_AUDIENCE,
                "iat": datetime.now(tz=UTC),
                "nbf": datetime.now(tz=UTC),
                "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
                "jti": "missing-sub",
            },
            UUID,
            id="missing-subject",
        ),
        pytest.param(
            {
                "sub": "",
                "aud": JWT_ACCESS_TOKEN_AUDIENCE,
                "iat": datetime.now(tz=UTC),
                "nbf": datetime.now(tz=UTC),
                "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
                "jti": "empty-sub",
            },
            UUID,
            id="empty-subject",
        ),
    ],
)
async def test_jwt_strategy_read_token_rejects_missing_or_empty_subject(
    payload: dict[str, object],
    subject_decoder: Callable[[str], object],
) -> None:
    """Missing or empty ``sub`` claims are rejected before user resolution."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=subject_decoder, allow_inmemory_denylist=True)
    user_manager = AsyncMock()

    assert await strategy.read_token(_make_token(payload=payload), user_manager) is None
    user_manager.get.assert_not_awaited()


async def test_jwt_strategy_read_token_rejects_invalid_decoder_and_denied_token() -> None:
    """Decoder failures and denylisted JTIs both reject the token."""
    user = ExampleUser(id=uuid4())
    now = datetime.now(tz=UTC)
    denylist_store = _RecordingDenylistStore()
    denylist_store.denied.add("revoked-jti")
    denied_strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID, denylist_store=denylist_store)
    user_manager = ExampleUserManager(user)
    denied_token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
            "jti": "revoked-jti",
        },
    )
    decoder_error_strategy = JWTStrategy(
        secret=DEFAULT_SECRET,
        subject_decoder=cast("Callable[[str], ID]", _subject_decoder_raises_value_error),
        allow_inmemory_denylist=True,
    )
    decoder_error_token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
            "jti": "decoder-error",
        },
    )

    assert await denied_strategy.read_token(denied_token, user_manager) is None
    assert await decoder_error_strategy.read_token(decoder_error_token, user_manager) is None


async def test_jwt_strategy_read_token_returns_none_when_user_manager_cannot_resolve_user() -> None:
    """Valid tokens are rejected when the subject no longer resolves to a user."""
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID, allow_inmemory_denylist=True)

    token = await strategy.write_token(cast("Any", user))

    assert await strategy.read_token(token, cast("Any", _MissingUserManager())) is None


async def test_jwt_strategy_read_token_rejects_fingerprint_mismatch() -> None:
    """Tokens become unreadable when the user's current fingerprint has changed."""
    original_user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="original-hash")
    current_user = ExampleUser(id=original_user.id, email=original_user.email, hashed_password="new-hash")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID, allow_inmemory_denylist=True)
    user_manager = ExampleUserManager(current_user)

    token = await strategy.write_token(original_user)

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_read_token_returns_user_when_subject_is_used_directly() -> None:
    """Without a subject decoder, the raw ``sub`` value is passed to the user manager."""
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, allow_inmemory_denylist=True)
    user_manager = AsyncMock()
    user_manager.get.return_value = user

    token = await strategy.write_token(user)

    assert await strategy.read_token(token, user_manager) is user
    user_manager.get.assert_awaited_once_with(str(user.id))


async def test_jwt_strategy_write_token_includes_issuer_and_fingerprint_claims() -> None:
    """Issued access tokens include issuer and session fingerprint when available."""
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed-password")
    strategy = JWTStrategy(secret=DEFAULT_SECRET, issuer="litestar-auth", allow_inmemory_denylist=True)

    token = await strategy.write_token(user)
    payload = jwt.decode(
        token,
        DEFAULT_SECRET,
        algorithms=["HS256"],
        audience=JWT_ACCESS_TOKEN_AUDIENCE,
        issuer="litestar-auth",
    )

    assert payload["iss"] == "litestar-auth"
    assert payload[strategy.session_fingerprint_claim] == strategy.session_fingerprint_getter(user)


async def test_jwt_strategy_write_token_skips_fingerprint_when_getter_returns_none() -> None:
    """Tokens omit the fingerprint claim when the configured getter yields ``None``."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy[ExampleUser, str](
        secret=DEFAULT_SECRET,
        session_fingerprint_getter=lambda _: None,
        allow_inmemory_denylist=True,
    )

    token = await strategy.write_token(user)
    payload = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    assert strategy.session_fingerprint_claim not in payload


async def test_jwt_strategy_destroy_token_ignores_invalid_and_missing_jti_tokens() -> None:
    """Invalid JWTs and decoded payloads without JTI claims do not write to the denylist."""
    user = ExampleUser(id=uuid4())
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)
    now = datetime.now(tz=UTC)
    token_without_jti = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
        },
    )

    await strategy.destroy_token("not-a-jwt", user)
    await strategy.destroy_token(token_without_jti, user)

    assert store.calls == []


async def test_jwt_strategy_destroy_token_ignores_unexpected_type_header() -> None:
    """Destroying a signed token with the wrong JOSE type does not write a revocation."""
    user = ExampleUser(id=uuid4())
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)
    now = datetime.now(tz=UTC)
    token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=5),
            "jti": "wrong-typ-destroy-jti",
        },
        headers={"typ": "not-jwt"},
    )

    await strategy.destroy_token(token, user)

    assert store.calls == []


async def test_jwt_strategy_destroy_token_derives_ttl_from_numeric_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Destroying a token uses integer ``exp`` when computing the denylist TTL."""
    fake_now = 4_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt.time.time", fake_time)
    user = ExampleUser(id=uuid4())
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)
    token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.fromtimestamp(fake_now, tz=UTC),
            "nbf": datetime.fromtimestamp(fake_now, tz=UTC),
            "exp": int(fake_now) + 120,
            "jti": "ttl-jti",
        },
    )

    await strategy.destroy_token(token, user)

    assert store.calls == [("ttl-jti", 120)]


async def test_jwt_strategy_destroy_token_uses_minimum_ttl_for_non_numeric_expiry() -> None:
    """Non-integer ``exp`` claims fall back to the minimum denylist TTL."""
    user = ExampleUser(id=uuid4())
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)
    token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": "not-a-timestamp",
            "jti": "minimum-ttl-jti",
        },
    )

    await strategy.destroy_token(token, user)

    assert store.calls == [("minimum-ttl-jti", 1)]


async def test_jwt_strategy_destroy_token_clamps_expired_numeric_ttl_to_minimum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired numeric ``exp`` claims still produce the minimum denylist TTL."""
    fake_now = 9_000.0

    def fake_time() -> float:
        return fake_now

    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt.time.time", fake_time)
    user = ExampleUser(id=uuid4())
    store = _RecordingDenylistStore()
    strategy = JWTStrategy(secret=DEFAULT_SECRET, denylist_store=store)
    token = _make_token(
        payload={
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.fromtimestamp(fake_now, tz=UTC),
            "nbf": datetime.fromtimestamp(fake_now, tz=UTC),
            "exp": int(fake_now) - 30,
            "jti": "expired-jti",
        },
    )

    await strategy.destroy_token(token, user)

    assert store.calls == [("expired-jti", 1)]
