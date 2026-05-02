"""Unit tests for TOTP pending-login flow orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import logging
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest

import litestar_auth.totp_flow as totp_flow_module
from litestar_auth.exceptions import TokenError
from litestar_auth.password import PasswordHelper
from litestar_auth.totp import SecurityWarning
from litestar_auth.totp_flow import (
    TOTP_PENDING_AUDIENCE,
    PendingTotpClientBinding,
    PendingTotpLogin,
    TotpLoginFlowConfig,
    TotpLoginFlowService,
    _fingerprint_client_binding_value,
)
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit

TOTP_PENDING_SECRET = "test-totp-pending-secret-thirty-two!"
CLIENT_BINDING = PendingTotpClientBinding(
    client_ip_fingerprint="client-ip-fingerprint",
    user_agent_fingerprint="user-agent-fingerprint",
)


def _service(
    user_manager: object,
    **config_kwargs: Any,  # noqa: ANN401
) -> TotpLoginFlowService[ExampleUser, UUID]:
    return TotpLoginFlowService[ExampleUser, UUID](
        user_manager=cast("Any", user_manager),
        config=TotpLoginFlowConfig[UUID](**config_kwargs),
    )


def _service_str(
    user_manager: object,
    **config_kwargs: Any,  # noqa: ANN401
) -> TotpLoginFlowService[ExampleUser, str]:
    return TotpLoginFlowService[ExampleUser, str](
        user_manager=cast("Any", user_manager),
        config=TotpLoginFlowConfig[str](**config_kwargs),
    )


def test_totp_flow_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    reloaded_module = importlib.reload(totp_flow_module)

    assert reloaded_module.TotpLoginFlowService.__name__ == TotpLoginFlowService.__name__
    assert reloaded_module.PendingTotpLogin.__name__ == PendingTotpLogin.__name__


def _build_manager(
    *,
    user: ExampleUser | None = None,
    read_secret: str | None = "plain-secret",
    recovery_code_hashes: tuple[str, ...] = (),
) -> AsyncMock:
    """Return an async mock manager with the TOTP-flow contract attached."""
    manager = AsyncMock()
    manager.get.return_value = user
    manager.read_totp_secret.return_value = read_secret
    manager.read_recovery_code_hashes.return_value = recovery_code_hashes
    manager.consume_recovery_code_hash.return_value = True
    return manager


class _RecordingPasswordHelper(PasswordHelper):
    """Password-helper stub that records every recovery-code hash verification."""

    def __init__(self, *, matching_hash: str | None) -> None:
        self.matching_hash = matching_hash
        self.seen_hashes: list[str] = []

    def verify(self, password: str, hashed: str) -> bool:
        del password
        self.seen_hashes.append(hashed)
        return hashed == self.matching_hash


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
        "cip": CLIENT_BINDING.client_ip_fingerprint,
        "uaf": CLIENT_BINDING.user_agent_fingerprint,
    }


async def _issue_pending_token(service: TotpLoginFlowService[ExampleUser, UUID], user: ExampleUser) -> str | None:
    """Issue a pending token with the unit-test client binding.

    Returns:
        The encoded pending token, or ``None`` when TOTP is not enabled.
    """
    return await service.issue_pending_token(user, client_binding=CLIENT_BINDING)


async def test_issue_pending_token_returns_none_when_totp_is_not_enabled() -> None:
    """Users without a stored TOTP secret do not receive pending-login tokens."""
    user = ExampleUser(id=uuid4(), email="user@example.com", totp_secret=None)
    manager = _build_manager(user=user, read_secret=None)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    pending_token = await _issue_pending_token(service, user)

    assert pending_token is None


async def test_issue_pending_token_mints_expected_jwt_claims() -> None:
    """Issued pending-login tokens keep the stable audience and subject contract."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    pending_token = await _issue_pending_token(service, user)

    assert isinstance(pending_token, str)
    payload = jwt.decode(pending_token, TOTP_PENDING_SECRET, algorithms=["HS256"], audience=TOTP_PENDING_AUDIENCE)
    assert payload["sub"] == str(user.id)
    assert isinstance(payload["jti"], str)
    assert payload["cip"] == CLIENT_BINDING.client_ip_fingerprint
    assert payload["uaf"] == CLIENT_BINDING.user_agent_fingerprint


def test_fingerprint_client_binding_value_returns_sha256_hex_digest() -> None:
    """Client-binding values are hashed before being written to pending tokens."""
    assert _fingerprint_client_binding_value("203.0.113.10") == hashlib.sha256(b"203.0.113.10").hexdigest()


async def test_issue_pending_token_omits_binding_claims_when_disabled() -> None:
    """The opt-out mode does not write empty binding claims into pending tokens."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        require_client_binding=False,
    )

    pending_token = await service.issue_pending_token(user)

    assert isinstance(pending_token, str)
    payload = jwt.decode(pending_token, TOTP_PENDING_SECRET, algorithms=["HS256"], audience=TOTP_PENDING_AUDIENCE)
    assert "cip" not in payload
    assert "uaf" not in payload


async def test_issue_pending_token_requires_client_binding_by_default() -> None:
    """The service fails closed if the caller omits required client-binding evidence."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.issue_pending_token(user)


async def test_authenticate_pending_login_rejects_mismatched_client_binding() -> None:
    """Pending-token client-binding mismatches use the invalid pending-token signal."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.authenticate_pending_login(
            client_binding=PendingTotpClientBinding(
                client_ip_fingerprint="other-client-ip",
                user_agent_fingerprint=CLIENT_BINDING.user_agent_fingerprint,
            ),
            pending_token=pending_token,
            code="123456",
        )

    manager.get.assert_not_awaited()


async def test_resolve_pending_login_rejects_missing_current_client_binding() -> None:
    """A bound pending token cannot be resolved without current client-binding evidence."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login(pending_token)

    manager.get.assert_not_awaited()


async def test_authenticate_pending_login_returns_user_and_denies_verified_jti() -> None:
    """Successful verification returns the user and records the pending JTI as spent."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    used_tokens_store = AsyncMock()
    pending_jti_store = AsyncMock()
    pending_jti_store.is_denied.return_value = False
    pending_jti_store.deny.return_value = True
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        used_tokens_store=used_tokens_store,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    async def validate_user(current_user: ExampleUser) -> None:
        assert current_user is user
        await asyncio.sleep(0)

    verify_totp_with_store = AsyncMock(return_value=True)
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", verify_totp_with_store)
        verified_user = await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="123456",
            validate_user=validate_user,
        )

    assert verified_user is user
    verify_totp_with_store.assert_awaited_once_with(
        "plain-secret",
        "123456",
        replay=totp_flow_module.TotpReplayProtection(
            user_id=user.id,
            used_tokens_store=used_tokens_store,
            require_replay_protection=True,
            unsafe_testing=False,
        ),
        algorithm="SHA256",
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
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="123456",
        )


async def test_authenticate_pending_login_rejects_invalid_totp_code() -> None:
    """Failed TOTP verification preserves the dedicated invalid-code signal."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=False))
        with pytest.raises(totp_flow_module.InvalidTotpCodeError):
            await service.authenticate_pending_login(
                client_binding=CLIENT_BINDING,
                pending_token=pending_token,
                code="000000",
            )


async def test_authenticate_pending_login_accepts_matching_recovery_code_after_totp_failure() -> None:
    """A valid unused recovery code completes the pending login after TOTP rejects the code."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user, recovery_code_hashes=("hash-1", "hash-2", "hash-3"))
    pending_jti_store = AsyncMock()
    pending_jti_store.is_denied.return_value = False
    pending_jti_store.deny.return_value = True
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    password_helper = _RecordingPasswordHelper(matching_hash="hash-2")
    service._password_helper = password_helper
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=False))
        verified_user = await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="recovery-code",
        )

    assert verified_user is user
    assert password_helper.seen_hashes == ["hash-1", "hash-2", "hash-3"]
    manager.consume_recovery_code_hash.assert_awaited_once_with(user, "hash-2")
    pending_jti_store.deny.assert_awaited_once()


async def test_authenticate_pending_login_rejects_consumed_matching_recovery_code() -> None:
    """Atomic consume failure keeps the same invalid-code signal as a wrong TOTP."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user, recovery_code_hashes=("hash-1",))
    manager.consume_recovery_code_hash.return_value = False
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    service._password_helper = _RecordingPasswordHelper(matching_hash="hash-1")
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=False))
        with pytest.raises(totp_flow_module.InvalidTotpCodeError):
            await service.authenticate_pending_login(
                client_binding=CLIENT_BINDING,
                pending_token=pending_token,
                code="recovery-code",
            )

    manager.consume_recovery_code_hash.assert_awaited_once_with(user, "hash-1")


async def test_authenticate_pending_login_traverses_every_recovery_hash_before_consuming() -> None:
    """Recovery-code lookup does not short-circuit when an earlier hash matches."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user, recovery_code_hashes=("hash-1", "hash-2", "hash-3", "hash-4"))
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
        unsafe_testing=True,
    )
    password_helper = _RecordingPasswordHelper(matching_hash="hash-1")
    service._password_helper = password_helper
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=False))
        with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
            await service.authenticate_pending_login(
                client_binding=CLIENT_BINDING,
                pending_token=pending_token,
                code="recovery-code",
            )

    assert password_helper.seen_hashes == ["hash-1", "hash-2", "hash-3", "hash-4"]


async def test_authenticate_pending_login_rejects_missing_secret_after_pending_token_issue() -> None:
    """A pending token cannot complete if the user's TOTP secret is unavailable later."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    manager.read_totp_secret.side_effect = ["plain-secret", None]
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.raises(totp_flow_module.InvalidTotpCodeError):
        await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="123456",
        )


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
    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )

    def _raise_decode_error(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise decode_error

    monkeypatch.setattr("litestar_auth.totp_flow.jwt.decode", _raise_decode_error)

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError) as exc_info:
        await service._resolve_pending_login("ignored", client_binding=CLIENT_BINDING)

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
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    monkeypatch.setattr(
        "litestar_auth.totp_flow.jwt.decode",
        lambda *_args, **_kwargs: _pending_payload(user) | payload,
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login("ignored", client_binding=CLIENT_BINDING)

    manager.get.assert_not_awaited()


async def test_resolve_pending_login_rejects_missing_user() -> None:
    """Pending tokens fail closed when their subject no longer resolves to a user."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=None)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = jwt.encode(_pending_payload(user), TOTP_PENDING_SECRET, algorithm="HS256")

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login(pending_token, client_binding=CLIENT_BINDING)


async def test_authenticate_pending_login_rejects_unparseable_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    """A decoded payload with an invalid expiration shape is rejected."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
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
        await service.authenticate_pending_login(client_binding=CLIENT_BINDING, pending_token="ignored", code="123456")


async def test_deny_pending_login_records_pending_jti_with_remaining_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pending JTIs are denylisted for the remaining token lifetime."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    service = _service(
        _build_manager(user=user),
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
    service = _service(
        _build_manager(user=user),
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


async def test_deny_pending_login_warns_in_unsafe_testing_without_denylist_store(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unsafe testing logs the missing denylist backend once per service instance."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        unsafe_testing=True,
    )
    service._reset_pending_jti_warning_state()
    caplog.set_level(logging.CRITICAL, logger=totp_flow_module.logger.name)

    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="c" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )
    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="f" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )

    warning_records = [
        record
        for record in caplog.records
        if (
            getattr(record, "event", None) == "totp_pending_jti_dedup_disabled"
            and getattr(record, "unsafe_testing", None) is True
        )
    ]
    assert len(warning_records) == 1

    service._reset_pending_jti_warning_state()
    caplog.clear()

    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._deny_pending_login(
            PendingTotpLogin(
                user=user,
                pending_jti="a" * 32,
                expires_at=datetime.now(tz=UTC) + timedelta(seconds=30),
            ),
        )

    assert any(
        getattr(record, "event", None) == "totp_pending_jti_dedup_disabled"
        and getattr(record, "unsafe_testing", None) is True
        for record in caplog.records
    )


async def test_deny_pending_login_raises_without_store_outside_unsafe_testing() -> None:
    """Production mode requires a pending-token denylist store."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = _service(
        _build_manager(user=user),
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
    service = _service(
        _build_manager(),
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    subject = str(uuid4())

    parsed = service._parse_user_id(subject)

    assert parsed == UUID(subject)


def test_parse_user_id_returns_subject_without_parser() -> None:
    """Without an ID parser, the subject is forwarded as-is."""
    service = _service_str(
        _build_manager(),
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
