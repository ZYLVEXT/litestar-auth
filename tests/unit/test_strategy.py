"""Tests for authentication strategies."""

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

from litestar_auth.authentication.strategy import base as strategy_base_module
from litestar_auth.authentication.strategy import redis as redis_strategy_module
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key
from litestar_auth.authentication.strategy.base import Strategy
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.jwt import JWT_ACCESS_TOKEN_AUDIENCE, JWTStrategy
from litestar_auth.authentication.strategy.redis import DEFAULT_KEY_PREFIX, RedisTokenStrategy
from litestar_auth.config import validate_secret_length
from litestar_auth.exceptions import ConfigurationError
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit
DEFAULT_SECRET = "a" * 32
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
HS512_SECRET = "b" * 64
JTI_HEX_LENGTH = 32
RSA_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3K1ozO4WRwj7u
NR0edcAn3S/wAjSIHnCUjNlyboWhicbIUpO57kVJw4VEls2s7UQ4yxAZU1DoUxxm
FeglLSs74APougvSQWfDJEFHK4zaCLIqGAeKzwDyHuWuDKPU1mj7g6rlzRz2Jubq
oN6zTckoNVydptu6vF9HYEpDXsEmLRMSQyG2IzIi/oADU5VK9hMpjK7sqal5N2Uz
qAT6FJUXwl6y0UjwfRfSarDzDWDFD8iqCSoUW1OPEmFZfmMrqB7PcKTBP+BKZ+Sy
aPTUsNXWxI6obcw+WYK/qFHFjq9/yTdn+w5Yzlf3neb/N0fljCyWZpCrZBbMArlT
7ut/9tbhAgMBAAECggEABu5tC2NFOq7PEtSPtYdfLiMAnWR3+G6uc/CgieQEyogc
LZhyXqbVmGT9tgq+3bxcyIlmoo60kRYUDQjnMAD1kd54R2ZC7EHtW0UT802Clv2d
QFqIbohG0OK6bkusJ3G1p07kOK36WpY+RsKvqrlW016xkoWt6vMV5+2M4d/ED120
wI4K8ZNmaU7yBq6t96dTY2LpSCVzJGN4evf3Fmwr3gFV2oxPM+eO/KodAEq004Zv
6kJujQQLDSVb4BPl2WpQHLG5JATO6XD1p407BVINo6GK80MnnOqYdQKvd56N1i/A
ItxLWKqvhcbq2nNE1XncvEnxr0SccO1ytkDj8EZpwQKBgQD4ITk8EcJWvYidLfuy
d2m5UK/y1USrN2zTGMqgf9HXolwL/7xF3/oy8olnQlcFgHpGWtdA/tzg/YGnNHbZ
IOuUydKmLKD/kRXkQVsSC7mvMaqj9q/JNSBw+WQMX4wWIE1I4D/d5B+5iPrv6dlK
g1kwTG7LT2unTK3gXuB5vArqqwKBgQC8+qjqouXQLMCwtDz68mHrvCJyR2wWA/++
3A66hyMfgT/wBxdPBECH8sKPorQtNI6MJamRmwG+a4kwf+Q+WFh1erE2JIXNFdLr
vmHaQ3ygRwsy3ogJophO7MFU2dPKbpkCFHyc8zvP7swwv61XUdFP4uDbh+oDkiFF
lOQaHApEowKBgFmC0rziwzK7aP8ayYPWJCOgAfkeComhkvaMKPzBX5fkkEQb23Vx
mTar2/mOKwpnELU0rBZcWp4nlZAWExG9GH8yV3VvAB1x323aTdoytKeIyUAhC8UQ
D0XyEa+NAGIzAO5bR27qjq9FxRCrUaHZxGDyEb3yRqmxtcANOflwZpfFAoGBAKPU
6vv/nRyMr8CBgRxNZXbo8zP/l0S+0si0HlC3N0vo0XVVsG9gUFGLtACyHWHTXoFB
ZXBF4Y0jzRuuxEEIdifi5h76KsVRVjnqIwsF1tVcwein42f2/fPubO0SqvmkSCH1
gNLQS9pIO91HTw+UbtHC7w1jFw1hclbQba/0/zHhAoGAJDl13tiQbyAJ8qSEBghk
rPY1eiGmYDuoXvtTHYcHzOhPKRxVhAoXCgSTeS3bQSZsPiU2w9CdSa1oxcjGnDVI
dqoGkeG0GrQrn4NYC9KuExV/0xE/HKCpk91wXDMdM2P/Ovy9SHULjf/FUH1iLykR
dNS5n+YC+AGjSu2sXtyAemc=
-----END PRIVATE KEY-----"""
RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtytaMzuFkcI+7jUdHnXA
J90v8AI0iB5wlIzZcm6FoYnGyFKTue5FScOFRJbNrO1EOMsQGVNQ6FMcZhXoJS0r
O+AD6LoL0kFnwyRBRyuM2giyKhgHis8A8h7lrgyj1NZo+4Oq5c0c9ibm6qDes03J
KDVcnabburxfR2BKQ17BJi0TEkMhtiMyIv6AA1OVSvYTKYyu7KmpeTdlM6gE+hSV
F8JestFI8H0X0mqw8w1gxQ/IqgkqFFtTjxJhWX5jK6gez3CkwT/gSmfksmj01LDV
1sSOqG3MPlmCv6hRxY6vf8k3Z/sOWM5X953m/zdH5YwslmaQq2QWzAK5U+7rf/bW
4QIDAQAB
-----END PUBLIC KEY-----"""

if TYPE_CHECKING:
    from collections.abc import Callable


def _redis_token_key(token: str) -> str:
    return build_opaque_token_key(
        key_prefix=DEFAULT_KEY_PREFIX,
        token_hash_secret=REDIS_TOKEN_HASH_SECRET.encode(),
        token=token,
    )


class ExampleUserManager:
    """Simple async user manager for JWT strategy tests."""

    def __init__(self, user: ExampleUser) -> None:
        """Store a single user for lookup assertions."""
        self.user = user
        self.seen_user_ids: list[object] = []

    async def get(self, user_id: object) -> ExampleUser | None:
        """Return the stored user when the identifiers match."""
        self.seen_user_ids.append(user_id)
        return self.user if user_id == self.user.id else None


def _invalid_token(_: str) -> str:
    """Return a deliberately malformed JWT string."""
    return "not-a-jwt"


def test_strategy_base_keeps_single_token_invalidation_protocol() -> None:
    """Strategy base exposes only the canonical runtime-checkable invalidation protocol."""
    assert hasattr(strategy_base_module, "TokenInvalidationCapable")
    assert not hasattr(strategy_base_module, "RefreshRevocationStrategy")


async def test_jwt_strategy_writes_token_with_subject_and_expiry() -> None:
    """JWTStrategy encodes the user id and expiration claim."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy[ExampleUser, str](secret=DEFAULT_SECRET)

    assert isinstance(strategy, Strategy)

    token = await strategy.write_token(user)
    payload = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    assert payload["sub"] == str(user.id)
    assert datetime.fromtimestamp(payload["exp"], tz=UTC) > datetime.now(tz=UTC)
    assert payload["aud"] == JWT_ACCESS_TOKEN_AUDIENCE
    assert datetime.fromtimestamp(payload["iat"], tz=UTC) <= datetime.now(tz=UTC)
    assert datetime.fromtimestamp(payload["nbf"], tz=UTC) <= datetime.now(tz=UTC)
    assert isinstance(payload["jti"], str)
    assert len(payload["jti"]) == JTI_HEX_LENGTH
    # Check that jti looks like hex without enforcing a specific generator.
    int(payload["jti"], 16)


async def test_jwt_strategy_reads_valid_token_via_user_manager() -> None:
    """JWTStrategy decodes a token and resolves the user through the manager."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = await strategy.write_token(user)
    resolved_user = await strategy.read_token(token, user_manager)

    assert resolved_user == user
    assert user_manager.seen_user_ids == [user.id]


@pytest.mark.parametrize(
    ("token_factory", "subject_decoder"),
    [
        pytest.param(
            lambda secret: jwt.encode(
                {"sub": "user-1", "exp": datetime.now(tz=UTC) - timedelta(seconds=1)},
                secret,
                algorithm="HS256",
            ),
            None,
            id="expired",
        ),
        pytest.param(
            lambda secret: jwt.encode(
                {"sub": "user-1", "exp": datetime.now(tz=UTC) + timedelta(minutes=5)},
                secret,
                algorithm="HS256",
            ),
            UUID,
            id="invalid-subject-decoder",
        ),
        pytest.param(
            _invalid_token,
            None,
            id="malformed",
        ),
        pytest.param(
            lambda secret: jwt.encode({"sub": "user-1"}, secret, algorithm="HS256"),
            None,
            id="missing-exp",
        ),
    ],
)
async def test_jwt_strategy_returns_none_for_invalid_or_expired_tokens(
    token_factory: Callable[[str], str],
    subject_decoder: Callable[[str], object] | None,
) -> None:
    """JWTStrategy rejects malformed, expired, and undecodable tokens."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=subject_decoder)
    user_manager = ExampleUserManager(user)

    token = token_factory(DEFAULT_SECRET)

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_returns_none_for_wrong_issuer_when_issuer_configured() -> None:
    """JWTStrategy rejects tokens whose issuer does not match the configured issuer."""
    user = ExampleUser(id=uuid4())
    issuer = "litestar-auth"
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID, issuer=issuer)
    user_manager = ExampleUserManager(user)

    # Token signed with same secret but different issuer.
    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "iss": "other-issuer",
        },
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


def _subject_decoder_raises_value_error(_: str) -> object:
    """Subject decoder that raises ValueError to simulate invalid sub.

    Raises:
        ValueError: Always, to test strategy handling.
    """
    msg = "invalid subject"
    raise ValueError(msg)


async def test_jwt_strategy_read_token_returns_none_when_subject_decoder_raises() -> None:
    """JWTStrategy.read_token returns None when subject_decoder raises ValueError."""
    user = ExampleUser(id=uuid4())
    calls: list[str] = []

    def decoder(value: str) -> object:
        calls.append(value)
        return _subject_decoder_raises_value_error(value)

    strategy = JWTStrategy(
        secret=DEFAULT_SECRET,
        subject_decoder=decoder,
    )
    user_manager = ExampleUserManager(user)

    token = jwt.encode(
        _make_valid_jwt_payload(sub="123", jti=str(uuid4())),
        DEFAULT_SECRET,
        algorithm="HS256",
    )
    result = await strategy.read_token(token, user_manager)

    assert calls == ["123"]
    assert result is None


def _make_valid_jwt_payload(**overrides: object) -> dict[str, object]:
    """Build a minimal payload that passes decode (aud, iat, exp) and optional sub.

    Returns:
        Payload dict suitable for jwt.encode with required claims.
    """
    base: dict[str, object] = {
        "aud": JWT_ACCESS_TOKEN_AUDIENCE,
        "iat": datetime.now(tz=UTC),
        "nbf": datetime.now(tz=UTC),
        "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
    }
    base.update(overrides)
    return base


async def test_jwt_strategy_read_token_returns_none_when_sub_missing() -> None:
    """JWTStrategy.read_token returns None when payload has no sub claim."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET)
    user_manager = ExampleUserManager(ExampleUser(id=uuid4()))

    token = jwt.encode(
        _make_valid_jwt_payload(),
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_read_token_returns_none_when_sub_empty() -> None:
    """JWTStrategy.read_token returns None when sub is empty string."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET)
    user_manager = ExampleUserManager(ExampleUser(id=uuid4()))

    token = jwt.encode(
        _make_valid_jwt_payload(sub=""),
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_read_token_returns_none_when_sub_not_string() -> None:
    """JWTStrategy.read_token returns None when sub is not a string (e.g. int)."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET)
    user_manager = ExampleUserManager(ExampleUser(id=uuid4()))

    token = jwt.encode(
        _make_valid_jwt_payload(sub=123),
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_destroy_token_handles_invalid_token() -> None:
    """JWTStrategy.destroy_token ignores tokens that cannot be decoded."""
    strategy = JWTStrategy(secret=DEFAULT_SECRET)

    await strategy.destroy_token("not-a-jwt", ExampleUser(id=uuid4()))


def test_validate_secret_length_raises_for_short_secret() -> None:
    """validate_secret_length raises ConfigurationError for too-short secrets."""
    with pytest.raises(ConfigurationError, match="must be at least"):
        validate_secret_length("short", label="test secret", minimum_length=10)


def test_database_token_strategy_re_raises_secret_validation_error() -> None:
    """DatabaseTokenStrategy re-raises secret validation failures as ConfigurationError."""
    with pytest.raises(ConfigurationError, match="DatabaseTokenStrategy token_hash_secret"):
        DatabaseTokenStrategy(session=cast("Any", object()), token_hash_secret="short")


async def test_jwt_strategy_supports_custom_algorithm_and_lifetime() -> None:
    """JWTStrategy accepts non-default algorithms and custom lifetimes."""
    user = ExampleUser(id=uuid4())
    lifetime = timedelta(minutes=10)
    strategy = JWTStrategy[ExampleUser, str](
        secret=HS512_SECRET,
        algorithm="HS512",
        lifetime=lifetime,
    )

    token = await strategy.write_token(user)
    payload = jwt.decode(token, HS512_SECRET, algorithms=["HS512"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    remaining_seconds = datetime.fromtimestamp(payload["exp"], tz=UTC) - datetime.now(tz=UTC)

    assert remaining_seconds <= lifetime
    assert remaining_seconds > timedelta(minutes=9)


async def test_jwt_strategy_uses_default_15_minute_lifetime() -> None:
    """JWTStrategy default lifetime is approximately 15 minutes."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy[ExampleUser, str](secret=DEFAULT_SECRET)

    token = await strategy.write_token(user)
    payload = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    remaining = datetime.fromtimestamp(payload["exp"], tz=UTC) - datetime.now(tz=UTC)
    # Allow a small delta for execution time while asserting it's roughly 15 minutes.
    assert timedelta(minutes=14) <= remaining <= timedelta(minutes=15)


async def test_jwt_strategy_supports_rs256_with_separate_verify_key() -> None:
    """JWTStrategy signs with a private key and verifies with a public key."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy[ExampleUser, UUID](
        secret=RSA_PRIVATE_KEY,
        verify_key=RSA_PUBLIC_KEY,
        algorithm="RS256",
        subject_decoder=UUID,
    )
    user_manager = ExampleUserManager(user)

    token = await strategy.write_token(user)
    payload = jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)
    resolved_user = await strategy.read_token(token, user_manager)

    assert payload["sub"] == str(user.id)
    assert resolved_user == user
    assert user_manager.seen_user_ids == [user.id]


async def test_jwt_strategy_uses_secret_key_for_default_session_fingerprint() -> None:
    """Default fingerprints are keyed with the JWT secret for symmetric algorithms."""
    password = "hashed-password"
    user = type("FingerprintUser", (), {"id": uuid4(), "email": "user@example.com", "hashed_password": password})()
    strategy = JWTStrategy(secret=DEFAULT_SECRET)

    token = await strategy.write_token(user)
    payload = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    material = f"{user.id}\x1f{user.email.casefold()}\x1f{password}".encode()
    expected = hmac.new(DEFAULT_SECRET.encode(), material, hashlib.sha256).hexdigest()
    assert payload["sfp"] == expected


async def test_jwt_strategy_uses_signing_secret_for_default_session_fingerprint_with_rs256() -> None:
    """Default fingerprints always use the signing secret, even for asymmetric algorithms."""
    password = "hashed-password"
    user = type("FingerprintUser", (), {"id": uuid4(), "email": "user@example.com", "hashed_password": password})()
    strategy = JWTStrategy(
        secret=RSA_PRIVATE_KEY,
        verify_key=RSA_PUBLIC_KEY,
        algorithm="RS256",
    )

    token = await strategy.write_token(user)
    payload = jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    material = f"{user.id}\x1f{user.email.casefold()}\x1f{password}".encode()
    expected = hmac.new(RSA_PRIVATE_KEY.encode(), material, hashlib.sha256).hexdigest()
    assert payload["sfp"] == expected


async def test_jwt_strategy_preserves_custom_session_fingerprint_getter() -> None:
    """Custom fingerprint getters are used directly instead of being wrapped."""
    user = type("FingerprintUser", (), {"id": uuid4()})()

    def custom_getter(candidate: object) -> str | None:
        return f"custom:{getattr(candidate, 'id', 'missing')}"

    strategy = JWTStrategy(secret=DEFAULT_SECRET, session_fingerprint_getter=custom_getter)
    token = await strategy.write_token(user)
    payload = jwt.decode(token, DEFAULT_SECRET, algorithms=["HS256"], audience=JWT_ACCESS_TOKEN_AUDIENCE)

    assert strategy.session_fingerprint_getter is custom_getter
    assert payload["sfp"] == custom_getter(user)


async def test_jwt_strategy_includes_jti_and_iss_when_issuer_set() -> None:
    """JWTStrategy emits jti and iss claims when issuer is configured."""
    user = ExampleUser(id=uuid4())
    issuer = "litestar-auth"
    strategy = JWTStrategy[ExampleUser, str](secret=DEFAULT_SECRET, issuer=issuer)

    token = await strategy.write_token(user)
    payload = jwt.decode(
        token,
        DEFAULT_SECRET,
        algorithms=["HS256"],
        audience=JWT_ACCESS_TOKEN_AUDIENCE,
        issuer=issuer,
    )

    assert payload["sub"] == str(user.id)
    assert payload["iss"] == issuer
    assert datetime.fromtimestamp(payload["nbf"], tz=UTC) <= datetime.now(tz=UTC)
    assert isinstance(payload["jti"], str)
    assert len(payload["jti"]) == JTI_HEX_LENGTH
    int(payload["jti"], 16)


async def test_jwt_strategy_destroy_token_revokes_token_via_denylist() -> None:
    """JWTStrategy destroy_token adds the token's jti to an in-memory denylist."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = await strategy.write_token(user)
    assert await strategy.read_token(token, user_manager) == user

    await strategy.destroy_token(token, user)

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_returns_none_when_audience_claim_missing() -> None:
    """JWTStrategy rejects tokens that do not include an audience."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = jwt.encode(
        {
            "sub": str(user.id),
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
        },
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_returns_none_when_iat_claim_missing() -> None:
    """JWTStrategy rejects tokens that do not include an issued-at timestamp."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = jwt.encode(
        {"sub": str(user.id), "aud": JWT_ACCESS_TOKEN_AUDIENCE, "exp": datetime.now(tz=UTC) + timedelta(minutes=5)},
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_returns_none_when_nbf_claim_missing() -> None:
    """JWTStrategy rejects tokens that do not include a not-before timestamp."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
        },
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


async def test_jwt_strategy_returns_none_when_nbf_claim_is_in_future() -> None:
    """JWTStrategy rejects tokens whose not-before timestamp is in the future."""
    user = ExampleUser(id=uuid4())
    strategy = JWTStrategy(secret=DEFAULT_SECRET, subject_decoder=UUID)
    user_manager = ExampleUserManager(user)

    token = jwt.encode(
        {
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC) + timedelta(minutes=1),
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
        },
        DEFAULT_SECRET,
        algorithm="HS256",
    )

    assert await strategy.read_token(token, user_manager) is None


def test_jwt_strategy_rejects_disallowed_algorithm() -> None:
    """JWTStrategy refuses insecure or unknown algorithms at construction time."""
    with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
        JWTStrategy(secret=DEFAULT_SECRET, algorithm="none")


async def test_redis_strategy_writes_token_with_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy stores a token with the configured TTL."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)
    redis_client = AsyncMock()
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis_client,
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        lifetime=timedelta(minutes=5),
        token_bytes=16,
    )

    token = await strategy.write_token(user)

    assert isinstance(strategy, Strategy)
    assert token
    redis_client.setex.assert_awaited_once_with(
        _redis_token_key(token),
        300,
        str(user.id),
    )


async def test_redis_strategy_reads_token_via_user_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy resolves users from stored Redis values."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis_client = AsyncMock()
    redis_client.get.return_value = str(user.id).encode()
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis_client,
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    resolved_user = await strategy.read_token("token-1", user_manager)

    assert resolved_user == user
    redis_client.get.assert_awaited_once_with(_redis_token_key("token-1"))
    assert user_manager.seen_user_ids == [user.id]


@pytest.mark.parametrize("stored_value", [None, "not-a-uuid"])
async def test_redis_strategy_returns_none_for_missing_or_invalid_user_id(
    monkeypatch: pytest.MonkeyPatch,
    stored_value: str | None,
) -> None:
    """RedisTokenStrategy rejects missing or undecodable Redis payloads."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)
    user = ExampleUser(id=uuid4())
    user_manager = ExampleUserManager(user)
    redis_client = AsyncMock()
    redis_client.get.return_value = stored_value
    strategy = RedisTokenStrategy[ExampleUser, UUID](
        redis=redis_client,
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        subject_decoder=UUID,
    )

    assert await strategy.read_token("token-2", user_manager) is None


async def test_redis_strategy_destroy_token_deletes_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy removes the token key on logout."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(redis_strategy_module, "_load_redis_asyncio", load_redis)
    redis_client = AsyncMock()
    user = ExampleUser(id=uuid4())
    strategy = RedisTokenStrategy[ExampleUser, UUID](redis=redis_client, token_hash_secret=REDIS_TOKEN_HASH_SECRET)

    assert await strategy.destroy_token("token-3", user) is None
    redis_client.delete.assert_awaited_once_with(_redis_token_key("token-3"))


def test_redis_strategy_lazy_import_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisTokenStrategy explains how to install the optional dependency."""

    def fail_import(name: str) -> None:
        raise ImportError(name)

    monkeypatch.setattr(importlib, "import_module", fail_import)

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTokenStrategy"):
        RedisTokenStrategy(redis=AsyncMock(), token_hash_secret=REDIS_TOKEN_HASH_SECRET)
