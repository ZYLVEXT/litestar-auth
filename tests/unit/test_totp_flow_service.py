"""Unit tests for TOTP pending-login flow orchestration."""

from __future__ import annotations

import asyncio
import importlib
from datetime import UTC, datetime, timedelta, tzinfo
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest

import litestar_auth.totp_flow as totp_flow_module
from litestar_auth.exceptions import TokenError
from litestar_auth.totp import SecurityWarning
from litestar_auth.totp_flow import (
    TOTP_PENDING_AUDIENCE,
    PendingTotpLogin,
    TotpLoginFlowService,
)
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit

TOTP_PENDING_SECRET = "test-totp-pending-secret-thirty-two!"


def test_totp_flow_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    reloaded_module = importlib.reload(totp_flow_module)

    assert reloaded_module.TotpLoginFlowService.__name__ == TotpLoginFlowService.__name__
    assert reloaded_module.PendingTotpLogin.__name__ == PendingTotpLogin.__name__


def _build_manager(*, user: ExampleUser | None = None, read_secret: str | None = "plain-secret") -> AsyncMock:
    """Return an async mock manager with the TOTP-flow contract attached."""
    manager = AsyncMock()
    manager.get.return_value = user
    manager.read_totp_secret.return_value = read_secret
    return manager


def _pending_payload(
    user: ExampleUser,
    *,
    exp: datetime | int | None = None,
    jti: str = "a" * 32,
    sub: str | None = None,
) -> dict[str, object]:
    """Build a decoded pending-token payload for targeted negative-path tests.

    Returns:
        JWT payload shaped like the decoded pending-login token contract.
    """
    issued_at = datetime.now(tz=UTC)
    return {
        "sub": str(user.id) if sub is None else sub,
        "aud": TOTP_PENDING_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": exp if exp is not None else issued_at + timedelta(minutes=5),
        "jti": jti,
    }


async def test_issue_pending_token_returns_none_when_totp_is_not_enabled() -> None:
    """Users without a stored TOTP secret do not receive pending-login tokens."""
    user = ExampleUser(id=uuid4(), email="user@example.com", totp_secret=None)
    manager = _build_manager(user=user, read_secret=None)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    pending_token = await service.issue_pending_token(user)

    assert pending_token is None


async def test_issue_pending_token_mints_expected_jwt_claims() -> None:
    """Issued pending-login tokens keep the stable audience and subject contract."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    pending_token = await service.issue_pending_token(user)

    assert isinstance(pending_token, str)
    payload = jwt.decode(pending_token, TOTP_PENDING_SECRET, algorithms=["HS256"], audience=TOTP_PENDING_AUDIENCE)
    assert payload["sub"] == str(user.id)
    assert isinstance(payload["jti"], str)


async def test_authenticate_pending_login_returns_user_and_denies_verified_jti() -> None:
    """Successful verification returns the user and records the pending JTI as spent."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    used_tokens_store = AsyncMock()
    pending_jti_store = AsyncMock()
    pending_jti_store.is_denied.return_value = False
    pending_jti_store.deny.return_value = True
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        used_tokens_store=used_tokens_store,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    pending_token = await service.issue_pending_token(user)
    assert pending_token is not None

    async def validate_user(current_user: ExampleUser) -> None:
        assert current_user is user
        await asyncio.sleep(0)

    verify_totp_with_store = AsyncMock(return_value=True)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", verify_totp_with_store)
        verified_user = await service.authenticate_pending_login(
            pending_token=pending_token,
            code="123456",
            validate_user=validate_user,
        )

    assert verified_user is user
    verify_totp_with_store.assert_awaited_once_with(
        "plain-secret",
        "123456",
        user_id=user.id,
        used_tokens_store=used_tokens_store,
        algorithm="SHA256",
        require_replay_protection=True,
        unsafe_testing=False,
    )
    pending_jti_store.is_denied.assert_awaited_once()
    pending_jti_store.deny.assert_awaited_once()
    deny_kwargs = pending_jti_store.deny.await_args.kwargs
    assert deny_kwargs["ttl_seconds"] >= 1


async def test_authenticate_pending_login_rejects_replayed_jti() -> None:
    """Already-denied pending JTIs are treated as invalid pending tokens."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    pending_jti_store = AsyncMock()
    pending_jti_store.is_denied.return_value = True
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    pending_token = await service.issue_pending_token(user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.authenticate_pending_login(pending_token=pending_token, code="123456")


async def test_authenticate_pending_login_rejects_invalid_totp_code() -> None:
    """Failed TOTP verification preserves the dedicated invalid-code signal."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await service.issue_pending_token(user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=False))
        with pytest.raises(totp_flow_module.InvalidTotpCodeError):
            await service.authenticate_pending_login(pending_token=pending_token, code="000000")


async def test_authenticate_pending_login_rejects_missing_secret_after_pending_token_issue() -> None:
    """A pending token cannot complete if the user's TOTP secret is unavailable later."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    manager.read_totp_secret.side_effect = ["plain-secret", None]
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await service.issue_pending_token(user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpCodeError):
        await service.authenticate_pending_login(pending_token=pending_token, code="123456")


@pytest.mark.parametrize(
    ("decode_error", "expected_cause"),
    [
        (jwt.ExpiredSignatureError("expired"), jwt.ExpiredSignatureError),
        (jwt.InvalidTokenError("invalid"), jwt.InvalidTokenError),
    ],
)
async def test_resolve_pending_login_wraps_jwt_decode_errors(
    monkeypatch: pytest.MonkeyPatch,
    decode_error: Exception,
    expected_cause: type[Exception],
) -> None:
    """JWT decode failures are normalized to the pending-token domain error."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )

    def _raise_decode_error(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise decode_error

    monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", _raise_decode_error)

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError) as exc_info:
        await service._resolve_pending_login("ignored")

    assert isinstance(exc_info.value.__cause__, expected_cause)


@pytest.mark.parametrize(
    "payload",
    [
        {"sub": ""},
        {"sub": None},
        {"jti": "short"},
        {"jti": "g" * 32},
        {"exp": "not-a-datetime"},
    ],
)
async def test_resolve_pending_login_rejects_invalid_payload_shapes(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    """Malformed decoded payload values are rejected before user lookup."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    monkeypatch.setattr(
        "litestar_auth.totp_flow.jwt.decode",
        lambda *_args, **_kwargs: _pending_payload(user) | payload,
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login("ignored")

    manager.get.assert_not_awaited()


async def test_resolve_pending_login_rejects_missing_user() -> None:
    """Pending tokens fail closed when their subject no longer resolves to a user."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=None)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = jwt.encode(_pending_payload(user), TOTP_PENDING_SECRET, algorithm="HS256")

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login(pending_token)


async def test_authenticate_pending_login_rejects_unparseable_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    """A decoded payload with an invalid expiration shape is rejected."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )

    monkeypatch.setattr(
        "litestar_auth.totp_flow.jwt.decode",
        lambda *_args, **_kwargs: {
            "sub": str(user.id),
            "aud": TOTP_PENDING_AUDIENCE,
            "iat": datetime.now(tz=UTC),
            "exp": "not-a-datetime",
            "jti": "a" * 32,
        },
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.authenticate_pending_login(pending_token="ignored", code="123456")


async def test_deny_pending_login_records_pending_jti_with_remaining_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pending JTIs are denylisted for the remaining token lifetime."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
    )
    frozen_now = datetime(2026, 3, 28, 14, 0, tzinfo=UTC)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            return frozen_now if tz is None else frozen_now.astimezone(tz)

    monkeypatch.setattr("litestar_auth.totp_flow.datetime", FrozenDateTime)

    await service._deny_pending_login(
        PendingTotpLogin(
            user=user,
            pending_jti="b" * 32,
            expires_at=frozen_now + timedelta(seconds=45),
        ),
    )

    pending_jti_store.deny.assert_awaited_once_with("b" * 32, ttl_seconds=45)


async def test_deny_pending_login_raises_token_error_when_denylist_returns_false() -> None:
    """Spent pending-login JTIs must not be treated as recorded when the store rejects the write."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    pending_jti_store.deny.return_value = False
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
    )

    with pytest.raises(TokenError, match="Could not record pending-login JTI"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="e" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )


async def test_deny_pending_login_warns_in_unsafe_testing_without_denylist_store() -> None:
    """Unsafe testing allows pending-login verification without a denylist backend."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        unsafe_testing=True,
    )

    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="c" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )


async def test_deny_pending_login_raises_without_store_outside_unsafe_testing() -> None:
    """Production mode requires a pending-token denylist store."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    with pytest.raises(totp_flow_module.ConfigurationError, match="Configure a JWTDenylistStore"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="d" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )


def test_parse_user_id_uses_configured_parser_when_present() -> None:
    """Configured ID parsers are applied to JWT subjects."""
    service = TotpLoginFlowService[ExampleUser, UUID](
        user_manager=_build_manager(),
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    subject = str(uuid4())

    parsed = service._parse_user_id(subject)

    assert parsed == UUID(subject)


def test_parse_user_id_returns_subject_without_parser() -> None:
    """Without an ID parser, the subject is forwarded as-is."""
    service = TotpLoginFlowService[ExampleUser, str](
        user_manager=_build_manager(),
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    assert service._parse_user_id("plain-subject") == "plain-subject"


@pytest.mark.parametrize(
    ("jti", "is_valid"),
    [
        ("a" * 32, True),
        ("short", False),
        ("g" * 32, False),
        (123, False),
    ],
)
def test_is_structurally_valid_jti_requires_32_char_hex_strings(jti: object, is_valid: object) -> None:
    """Only 32-character hexadecimal JTIs are accepted."""
    assert TotpLoginFlowService._is_structurally_valid_jti(jti) is is_valid


def test_parse_pending_expiration_normalizes_datetime_and_integer_values() -> None:
    """Expiration values support aware datetimes, naive datetimes, and JWT timestamps."""
    aware_expiration = datetime(2026, 3, 28, 14, 15, tzinfo=UTC)
    naive_expiration = aware_expiration.replace(minute=16, tzinfo=None)
    timestamp_expiration = int(aware_expiration.timestamp())

    assert TotpLoginFlowService._parse_pending_expiration(aware_expiration) == aware_expiration
    assert TotpLoginFlowService._parse_pending_expiration(naive_expiration) == naive_expiration.replace(tzinfo=UTC)
    assert TotpLoginFlowService._parse_pending_expiration(timestamp_expiration) == aware_expiration
    assert TotpLoginFlowService._parse_pending_expiration("invalid") is None
