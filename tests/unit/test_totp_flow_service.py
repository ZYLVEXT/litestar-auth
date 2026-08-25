"""Unit tests for TOTP pending-login flow orchestration."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta, tzinfo
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import jwt
import pytest
from litestar import Request

import litestar_auth.totp_flow as totp_flow_module
from litestar_auth import totp
from litestar_auth._jwt_headers import jwt_encode_headers
from litestar_auth.authentication.strategy._jwt_denylist import (
    InMemoryJWTDenylistStore,
    JWTReplayStoreResult,
)
from litestar_auth.config import JWT_TIME_CLAIM_LEEWAY_SECONDS
from litestar_auth.exceptions import TokenError
from litestar_auth.password import PasswordHelper
from litestar_auth.totp import SecurityWarning
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.types import HTTPScope

TOTP_PENDING_AUDIENCE = totp_flow_module.TOTP_PENDING_AUDIENCE
PendingTotpClientBinding = totp_flow_module.PendingTotpClientBinding
PendingTotpLogin = totp_flow_module.PendingTotpLogin
TotpLoginFlowConfig = totp_flow_module.TotpLoginFlowConfig
TotpLoginFlowService = totp_flow_module.TotpLoginFlowService
_fingerprint_client_binding_value = totp_flow_module._fingerprint_client_binding_value
_USER_AGENT_FINGERPRINT_MAX_BYTES = totp_flow_module._USER_AGENT_FINGERPRINT_MAX_BYTES
build_pending_totp_client_binding = totp_flow_module.build_pending_totp_client_binding

pytestmark = pytest.mark.unit

TOTP_PENDING_SECRET = "2b101e06ab63b75e08f84e82a86e5d1d5f6bd92b8645ed3769a10b867bc10f44"
RECOVERY_LOOKUP_SECRET = b"test-recovery-code-lookup-secret"
CLIENT_BINDING = PendingTotpClientBinding(
    client_ip_fingerprint="client-ip-fingerprint",
    user_agent_fingerprint="user-agent-fingerprint",
)


def _service(
    user_manager: object,
    **config_kwargs: Any,  # ruff: ignore[any-type]
) -> TotpLoginFlowService[ExampleUser, UUID]:
    return TotpLoginFlowService[ExampleUser, UUID](
        user_manager=cast("Any", user_manager),
        config=TotpLoginFlowConfig[UUID](**config_kwargs),
    )


def _service_str(
    user_manager: object,
    **config_kwargs: Any,  # ruff: ignore[any-type]
) -> TotpLoginFlowService[ExampleUser, str]:
    return TotpLoginFlowService[ExampleUser, str](
        user_manager=cast("Any", user_manager),
        config=TotpLoginFlowConfig[str](**config_kwargs),
    )


def _build_manager(
    *,
    user: ExampleUser | None = None,
    read_secret: str | None = "plain-secret",
    recovery_code_index: dict[str, str] | None = None,
) -> AsyncMock:
    """Return an async mock manager with the TOTP-flow contract attached."""
    manager = AsyncMock()
    manager.get.return_value = user
    manager.read_totp_secret.return_value = read_secret
    manager.recovery_code_lookup_secret = RECOVERY_LOOKUP_SECRET
    active_index = {} if recovery_code_index is None else dict(recovery_code_index)
    manager.find_recovery_code_hash_by_lookup.side_effect = lambda _user, lookup_hex: active_index.get(lookup_hex)
    manager.consume_recovery_code_by_lookup.return_value = True
    return manager


class _RecordingPasswordHelper(PasswordHelper):
    """Password-helper stub that records every recovery-code hash verification."""

    def __init__(self, *, matching_hash: str | None) -> None:
        super().__init__()
        self.matching_hash = matching_hash
        self.seen_hashes: list[str] = []

    def verify(self, password: str, hashed: str) -> bool:
        self.seen_hashes.append(hashed)
        return hashed == self.matching_hash


def _pending_payload(
    user: ExampleUser,
    *,
    exp: datetime | int | None = None,
    jti: str = "0123456789abcdef" * 2,
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


def _build_binding_request(*, user_agent: bytes) -> Request[Any, Any, Any]:
    """Construct a minimal request carrying a User-Agent for fingerprint tests.

    Returns:
        Minimal request whose only inspected header is ``User-Agent``.
    """
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/login",
            "raw_path": b"/auth/login",
            "root_path": "",
            "query_string": b"",
            "headers": [(b"user-agent", user_agent)],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "path_params": {},
            "app": object(),
        },
    )
    return Request(scope=scope)


def test_build_pending_totp_client_binding_caps_user_agent_length() -> None:
    """Oversized User-Agent values are truncated before keyed fingerprinting to bound CPU cost."""
    oversized_ua = "A" * (_USER_AGENT_FINGERPRINT_MAX_BYTES * 4)
    binding = build_pending_totp_client_binding(
        _build_binding_request(user_agent=oversized_ua.encode()),
        pending_secret=TOTP_PENDING_SECRET,
    )

    truncated_ua = oversized_ua[:_USER_AGENT_FINGERPRINT_MAX_BYTES]
    expected = _fingerprint_client_binding_value(truncated_ua, key=TOTP_PENDING_SECRET.encode())
    assert binding.user_agent_fingerprint == expected


def _build_forwarded_request(*, forwarded_for: bytes, client_host: str = "10.0.0.1") -> Request[Any, Any, Any]:
    """Construct a request carrying an X-Forwarded-For header and a direct client host.

    Returns:
        Minimal request with the proxy header and direct client both populated.
    """
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/login",
            "raw_path": b"/auth/login",
            "root_path": "",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", forwarded_for)],
            "client": (client_host, 12345),
            "server": ("testserver", 80),
            "path_params": {},
            "app": object(),
        },
    )
    return Request(scope=scope)


def _expected_ip_fingerprint(client_ip: str) -> str:
    """Return the keyed fingerprint a binding should carry for ``client_ip``."""
    return _fingerprint_client_binding_value(client_ip, key=TOTP_PENDING_SECRET.encode())


def test_build_pending_totp_client_binding_multi_hop_selects_correct_hop() -> None:
    """With trusted_proxy_hops=2 the binding fingerprints the second-from-right XFF entry."""
    request = _build_forwarded_request(forwarded_for=b"203.0.113.7, 198.51.100.4, 198.51.100.5")
    binding = build_pending_totp_client_binding(
        request,
        pending_secret=TOTP_PENDING_SECRET,
        trusted_proxy=True,
        trusted_proxy_hops=2,
    )

    assert binding.client_ip_fingerprint == _expected_ip_fingerprint("198.51.100.4")
    # Default hops=1 would instead bind the rightmost (inner-proxy) entry.
    assert binding.client_ip_fingerprint != _expected_ip_fingerprint("198.51.100.5")


def test_build_pending_totp_client_binding_fails_closed_on_short_xff() -> None:
    """A header with fewer entries than the hop count falls back to the direct client host."""
    request = _build_forwarded_request(forwarded_for=b"203.0.113.7", client_host="10.0.0.1")
    binding = build_pending_totp_client_binding(
        request,
        pending_secret=TOTP_PENDING_SECRET,
        trusted_proxy=True,
        trusted_proxy_hops=2,
    )

    assert binding.client_ip_fingerprint == _expected_ip_fingerprint("10.0.0.1")


def test_build_pending_totp_client_binding_default_hops_preserves_rightmost() -> None:
    """The default hops=1 keeps binding to the rightmost XFF entry (existing behavior)."""
    request = _build_forwarded_request(forwarded_for=b"203.0.113.7, 198.51.100.4, 198.51.100.5")
    binding = build_pending_totp_client_binding(
        request,
        pending_secret=TOTP_PENDING_SECRET,
        trusted_proxy=True,
    )

    assert binding.client_ip_fingerprint == _expected_ip_fingerprint("198.51.100.5")


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
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=True)
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
    pending_jti_store.mark_used.assert_awaited_once()
    claim_kwargs = pending_jti_store.mark_used.await_args.kwargs
    assert claim_kwargs["ttl_seconds"] >= JWT_TIME_CLAIM_LEEWAY_SECONDS


async def test_authenticate_pending_login_rejects_replayed_jti() -> None:
    """Already-denied pending JTIs are treated as invalid pending tokens."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=False, rejected_as_replay=True)
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
        pending_jti_store=InMemoryJWTDenylistStore(),
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
    password_helper = PasswordHelper.from_defaults()
    recovery_code_index = totp.build_recovery_code_index(
        ("recovery-code",),
        password_helper=password_helper,
        lookup_secret=RECOVERY_LOOKUP_SECRET,
    )
    manager = _build_manager(user=user, recovery_code_index=recovery_code_index)
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=True)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
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
    manager.consume_recovery_code_by_lookup.assert_awaited_once()
    pending_jti_store.mark_used.assert_awaited_once()


async def test_authenticate_pending_login_rejects_consumed_matching_recovery_code() -> None:
    """Atomic consume failure keeps the same invalid-code signal as a wrong TOTP."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    password_helper = PasswordHelper.from_defaults()
    recovery_code_index = totp.build_recovery_code_index(
        ("recovery-code",),
        password_helper=password_helper,
        lookup_secret=RECOVERY_LOOKUP_SECRET,
    )
    manager = _build_manager(user=user, recovery_code_index=recovery_code_index)
    manager.consume_recovery_code_by_lookup.return_value = False
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=InMemoryJWTDenylistStore(),
        id_parser=UUID,
    )
    service._password_helper = password_helper
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

    manager.consume_recovery_code_by_lookup.assert_awaited_once()


async def test_authenticate_pending_login_uses_one_indexed_recovery_hash_before_consuming() -> None:
    """Recovery-code lookup verifies the single hash addressed by the keyed index."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user, recovery_code_index={"lookup": "hash-1"})
    manager.find_recovery_code_hash_by_lookup.side_effect = None
    manager.find_recovery_code_hash_by_lookup.return_value = "hash-1"
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

    assert password_helper.seen_hashes == ["hash-1"]


async def test_authenticate_pending_login_rejects_missing_secret_after_pending_token_issue() -> None:
    """A pending token cannot complete if the user's TOTP secret is unavailable later."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    manager.read_totp_secret.side_effect = ["plain-secret", None]
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=InMemoryJWTDenylistStore(),
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

    monkeypatch.setattr("litestar_auth._jwt_headers.jwt.decode", _raise_decode_error)
    pending_token = jwt.encode(
        _pending_payload(user),
        TOTP_PENDING_SECRET,
        algorithm="HS256",
        headers=jwt_encode_headers(),
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError) as exc_info:
        await service._resolve_pending_login(pending_token, client_binding=CLIENT_BINDING)

    assert isinstance(exc_info.value.__cause__, expected_cause)


@pytest.mark.parametrize(
    "payload",
    [
        {"sub": ""},
        {"sub": None},
        {"jti": "short"},
        {"jti": "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"},
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
        "litestar_auth._jwt_headers.jwt.decode",
        lambda *_args, **_kwargs: _pending_payload(user) | payload,
    )
    pending_token = jwt.encode(
        _pending_payload(user),
        TOTP_PENDING_SECRET,
        algorithm="HS256",
        headers=jwt_encode_headers(),
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login(pending_token, client_binding=CLIENT_BINDING)

    manager.get.assert_not_awaited()


async def test_resolve_pending_login_rejects_missing_user() -> None:
    """Pending tokens fail closed when their subject no longer resolves to a user."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=None)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=InMemoryJWTDenylistStore(),
        id_parser=UUID,
    )
    pending_token = jwt.encode(
        _pending_payload(user),
        TOTP_PENDING_SECRET,
        algorithm="HS256",
        headers=jwt_encode_headers(),
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._resolve_pending_login(pending_token, client_binding=CLIENT_BINDING)


async def test_authenticate_pending_login_rejects_unparseable_expiration() -> None:
    """A decoded payload with an invalid expiration shape is rejected."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        id_parser=UUID,
    )
    pending_token = jwt.encode(
        _pending_payload(user) | {"exp": "not-a-datetime"},
        TOTP_PENDING_SECRET,
        algorithm="HS256",
        headers=jwt_encode_headers(),
    )

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="123456",
        )


async def test_claim_pending_jti_ttl_covers_remaining_lifetime_plus_leeway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claim TTL spans the remaining token lifetime plus the JWT decode leeway."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=True)
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

    await service._claim_pending_jti(
        "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe", frozen_now + timedelta(seconds=45)
    )

    pending_jti_store.mark_used.assert_awaited_once_with(
        "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
        ttl_seconds=45 + JWT_TIME_CLAIM_LEEWAY_SECONDS,
    )


async def test_claim_pending_jti_ttl_never_below_leeway_for_past_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token past ``exp`` but inside decode leeway is still claimed for the leeway window."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=True)
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

    await service._claim_pending_jti(
        "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe", frozen_now - timedelta(seconds=10)
    )

    pending_jti_store.mark_used.assert_awaited_once_with(
        "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
        ttl_seconds=JWT_TIME_CLAIM_LEEWAY_SECONDS,
    )


async def test_claim_pending_jti_raises_token_error_on_capacity_pressure() -> None:
    """A claim the store cannot record fails closed instead of proceeding unverified."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=False, rejected_as_replay=False)
    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
    )

    with pytest.raises(TokenError, match="Could not record pending-login JTI"):
        await service._claim_pending_jti(
            "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            datetime.now(tz=UTC) + timedelta(seconds=30),
        )


async def test_claim_pending_jti_falls_back_for_stores_without_mark_used() -> None:
    """A plain JWTDenylistStore is checked then denied immediately at claim time."""
    user = ExampleUser(id=uuid4(), email="user@example.com")

    class DenyOnlyStore:
        def __init__(self) -> None:
            self.denied: dict[str, int] = {}

        async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
            self.denied[jti] = ttl_seconds
            return True

        async def is_denied(self, jti: str) -> bool:
            return jti in self.denied

    store = DenyOnlyStore()
    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=store,
    )
    jti = "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=45)

    await service._claim_pending_jti(jti, expires_at)
    assert store.denied[jti] >= JWT_TIME_CLAIM_LEEWAY_SECONDS

    with pytest.raises(totp_flow_module.InvalidTotpPendingTokenError):
        await service._claim_pending_jti(jti, expires_at)


async def test_claim_pending_jti_fail_closed_when_fallback_deny_cannot_record() -> None:
    """Capacity pressure on a mark_used-less store raises TokenError before login proceeds."""
    user = ExampleUser(id=uuid4(), email="user@example.com")

    class FullDenyOnlyStore:
        async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
            return False

        async def is_denied(self, jti: str) -> bool:
            return False

    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=FullDenyOnlyStore(),
    )

    with pytest.raises(TokenError, match="Could not record pending-login JTI"):
        await service._claim_pending_jti(
            "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            datetime.now(tz=UTC) + timedelta(seconds=30),
        )


async def test_claim_pending_jti_warns_in_unsafe_testing_without_denylist_store(
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
    jti = "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
    expires_at = datetime.now(tz=UTC) + timedelta(seconds=30)

    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._claim_pending_jti(jti, expires_at)
    with pytest.warns(SecurityWarning, match="unsafe_testing=True"):
        await service._claim_pending_jti(jti, expires_at)

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
        await service._claim_pending_jti(jti, expires_at)

    assert any(
        getattr(record, "event", None) == "totp_pending_jti_dedup_disabled"
        and getattr(record, "unsafe_testing", None) is True
        for record in caplog.records
    )


async def test_claim_pending_jti_raises_without_store_outside_unsafe_testing() -> None:
    """Production mode requires a pending-token denylist store."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    service = _service(
        _build_manager(user=user),
        totp_pending_secret=TOTP_PENDING_SECRET,
    )

    with pytest.raises(totp_flow_module.ConfigurationError, match="Configure a JWTDenylistStore"):
        await service._claim_pending_jti(
            "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            datetime.now(tz=UTC) + timedelta(seconds=30),
        )


async def test_concurrent_pending_login_verifies_allow_exactly_one_success() -> None:
    """Two concurrent completions of the same pending token: exactly one wins."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=InMemoryJWTDenylistStore(),
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("litestar_auth.totp_flow.verify_totp_with_store", AsyncMock(return_value=True))
        results = await asyncio.gather(
            *(
                service.authenticate_pending_login(
                    client_binding=CLIENT_BINDING,
                    pending_token=pending_token,
                    code="123456",
                )
                for _ in range(2)
            ),
            return_exceptions=True,
        )

    successes = [result for result in results if result is user]
    replays = [result for result in results if isinstance(result, totp_flow_module.InvalidTotpPendingTokenError)]
    assert len(successes) == 1
    assert len(replays) == 1


async def test_failed_jti_claim_never_consumes_recovery_code() -> None:
    """When the pending JTI cannot be claimed, the recovery code is left untouched."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager(user=user)
    pending_jti_store = AsyncMock()
    pending_jti_store.mark_used.return_value = JWTReplayStoreResult(stored=False, rejected_as_replay=False)
    service = _service(
        manager,
        totp_pending_secret=TOTP_PENDING_SECRET,
        pending_jti_store=pending_jti_store,
        id_parser=UUID,
    )
    pending_token = await _issue_pending_token(service, user)
    assert pending_token is not None

    with pytest.raises(TokenError):
        await service.authenticate_pending_login(
            client_binding=CLIENT_BINDING,
            pending_token=pending_token,
            code="recovery-code",
        )

    manager.find_recovery_code_hash_by_lookup.assert_not_awaited()
    manager.consume_recovery_code_by_lookup.assert_not_awaited()


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
        ("0123456789abcdef" * 2, True),
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
