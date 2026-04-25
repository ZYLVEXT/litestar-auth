"""End-to-end auth rate-limit flow through the Litestar auth plugin."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar
from litestar.testing import AsyncTestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

import litestar_auth.totp as _totp_mod
from litestar_auth._plugin.config import TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore, JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig, AuthRateLimitSlot, EndpointRateLimit, InMemoryRateLimiter
from litestar_auth.totp import (
    InMemoryTotpEnrollmentStore,
    InMemoryUsedTotpCodeStore,
    _current_counter,
    _generate_totp_code,
)
from tests.e2e.conftest import SessionMaker

pytestmark = [pytest.mark.e2e]

HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
HTTP_TOO_MANY_REQUESTS = 429
HTTP_ACCEPTED = 202


class RateLimitUserManager(BaseUserManager[User, UUID]):
    """Concrete manager used by the rate-limit e2e app."""


@dataclass(slots=True)
class MutableClock:
    """Deterministic clock for expiring in-memory rate-limit windows."""

    current_time: float = 1_000.0

    def now(self) -> float:
        """Return the current monotonic timestamp."""
        return self.current_time

    def advance(self, seconds: float) -> None:
        """Advance the current timestamp."""
        self.current_time += seconds


def _build_app_with_trusted_proxy(
    *,
    trusted_proxy: bool,
    shared_builder_recipe: bool = False,
) -> tuple[Litestar, MutableClock]:
    """Create a Litestar auth app with configurable trusted-proxy rate limiting.

    Returns:
        App under test and the shared mutable clock.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: sqlite3.Connection, _: object) -> None:
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return

        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    User.metadata.create_all(engine)
    password_helper = PasswordHelper()

    with SASession(engine) as session:
        session.add(
            User(
                email="user@example.com",
                hashed_password=password_helper.hash("correct-password"),
                is_verified=True,
            ),
        )
        session.commit()

    clock = MutableClock()
    credential_rate_limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=60, clock=clock.now)
    refresh_rate_limiter = InMemoryRateLimiter(max_attempts=3, window_seconds=90, clock=clock.now)
    totp_rate_limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=60, clock=clock.now)
    login_rate_limiter = (
        credential_rate_limiter
        if shared_builder_recipe
        else InMemoryRateLimiter(max_attempts=2, window_seconds=60, clock=clock.now)
    )
    verify_rate_limiter = (
        totp_rate_limiter
        if shared_builder_recipe
        else InMemoryRateLimiter(max_attempts=2, window_seconds=60, clock=clock.now)
    )
    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-bearer-secret-1234567890-extra",
                subject_decoder=UUID,
                allow_inmemory_denylist=True,
            ),
        ),
    )
    rate_limit_config = (
        AuthRateLimitConfig.from_shared_backend(
            credential_rate_limiter,
            group_backends={"totp": totp_rate_limiter, "refresh": refresh_rate_limiter},
            disabled={AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN},
            endpoint_overrides={
                AuthRateLimitSlot.FORGOT_PASSWORD: EndpointRateLimit(
                    backend=credential_rate_limiter,
                    scope="ip_email",
                    namespace="forgot_password",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.RESET_PASSWORD: EndpointRateLimit(
                    backend=credential_rate_limiter,
                    scope="ip",
                    namespace="reset_password",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.TOTP_ENABLE: EndpointRateLimit(
                    backend=totp_rate_limiter,
                    scope="ip",
                    namespace="totp_enable",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: EndpointRateLimit(
                    backend=totp_rate_limiter,
                    scope="ip",
                    namespace="totp_confirm_enable",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
                    backend=totp_rate_limiter,
                    scope="ip",
                    namespace="totp_verify",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.TOTP_DISABLE: EndpointRateLimit(
                    backend=totp_rate_limiter,
                    scope="ip",
                    namespace="totp_disable",
                    trusted_proxy=trusted_proxy,
                ),
                AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES: EndpointRateLimit(
                    backend=totp_rate_limiter,
                    scope="ip",
                    namespace="totp_regenerate_recovery_codes",
                    trusted_proxy=trusted_proxy,
                ),
            },
            trusted_proxy=trusted_proxy,
        )
        if shared_builder_recipe
        else AuthRateLimitConfig(
            login=EndpointRateLimit(
                backend=login_rate_limiter,
                scope="ip",
                namespace="login",
                trusted_proxy=trusted_proxy,
            ),
            totp_verify=EndpointRateLimit(
                backend=verify_rate_limiter,
                scope="ip",
                namespace="totp-verify",
            ),
        )
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=RateLimitUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            totp_secret_key=Fernet.generate_key().decode(),
            id_parser=UUID,
            password_helper=password_helper,
        ),
        rate_limit_config=rate_limit_config,
        totp_config=TotpConfig(
            totp_pending_secret="test-totp-pending-secret-thirty-two!",
            totp_pending_jti_store=InMemoryJWTDenylistStore(),
            totp_enrollment_store=InMemoryTotpEnrollmentStore(),
            totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        ),
    )
    app = Litestar(plugins=[LitestarAuth(config)])
    return app, clock


@pytest.fixture
def app(request: pytest.FixtureRequest) -> tuple[Litestar, MutableClock]:
    """Create a Litestar app wired with configurable login rate limiting.

    Returns:
        App under test and the shared mutable clock.
    """
    trusted_proxy = cast("bool", getattr(request, "param", False))
    app_instance, clock = _build_app_with_trusted_proxy(trusted_proxy=trusted_proxy)
    return app_instance, clock


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so cookie and redirect behavior matches production wiring.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


async def test_login_rate_limit_blocks_by_ip_and_resets_after_window(
    client: tuple[AsyncTestClient[Litestar], MutableClock],
) -> None:
    """Repeated failed logins hit 429 with Retry-After until the window expires."""
    test_client, clock = client

    first_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-one@example.com", "password": "wrong-password"},
    )
    second_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-two@example.com", "password": "wrong-password"},
    )
    blocked_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "wrong-password"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert blocked_response.status_code == HTTP_TOO_MANY_REQUESTS
    assert blocked_response.headers["Retry-After"].isdigit()
    assert int(blocked_response.headers["Retry-After"]) >= 1

    clock.advance(61)

    reset_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )

    assert reset_response.status_code == HTTP_CREATED
    assert isinstance(reset_response.json()["access_token"], str)


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_totp_verify_throttle_is_independent_from_enable_disable_failures(
    client: tuple[AsyncTestClient[Litestar], MutableClock],
) -> None:
    """TOTP verify throttle remains isolated from post-auth 2FA management failures."""
    test_client, _clock = client
    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    access_token = login_response.json()["access_token"]

    first_enable_failure = await test_client.post(
        "/auth/2fa/enable",
        json={"password": "wrong-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    second_enable_failure = await test_client.post(
        "/auth/2fa/enable",
        json={"password": "wrong-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    third_enable_failure = await test_client.post(
        "/auth/2fa/enable",
        json={"password": "wrong-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first_enable_failure.status_code == HTTP_BAD_REQUEST
    assert second_enable_failure.status_code == HTTP_BAD_REQUEST
    assert third_enable_failure.status_code == HTTP_BAD_REQUEST

    enable_response = await test_client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable_response.status_code == HTTP_CREATED
    enable_body = enable_response.json()
    secret = enable_body["secret"]

    confirm_code = _generate_totp_code(secret, _totp_mod._current_counter())
    confirm_response = await test_client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert confirm_response.status_code == HTTP_CREATED

    pending_for_success = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_for_success.status_code == HTTP_ACCEPTED
    verify_success = await test_client.post(
        "/auth/2fa/verify",
        json={
            "pending_token": pending_for_success.json()["pending_token"],
            "code": _generate_totp_code(secret, _current_counter()),
        },
    )
    assert verify_success.status_code == HTTP_CREATED
    full_token = verify_success.json()["access_token"]

    first_disable_failure = await test_client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    second_disable_failure = await test_client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    third_disable_failure = await test_client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    assert first_disable_failure.status_code == HTTP_BAD_REQUEST
    assert second_disable_failure.status_code == HTTP_BAD_REQUEST
    assert third_disable_failure.status_code == HTTP_BAD_REQUEST

    pending_for_failures = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_for_failures.status_code == HTTP_ACCEPTED
    pending_token = pending_for_failures.json()["pending_token"]

    first_verify_failure = await test_client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    second_verify_failure = await test_client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    blocked_verify = await test_client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    assert first_verify_failure.status_code == HTTP_BAD_REQUEST
    assert second_verify_failure.status_code == HTTP_BAD_REQUEST
    assert blocked_verify.status_code == HTTP_TOO_MANY_REQUESTS


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_plugin_shared_builder_migration_recipe_keeps_login_and_totp_verify_namespaces_separate() -> None:
    """The plugin shared-builder migration recipe keeps login and TOTP verify counters separate."""
    app, _clock = _build_app_with_trusted_proxy(trusted_proxy=False, shared_builder_recipe=True)

    async with AsyncTestClient(app=app, base_url="https://testserver.local") as test_client:
        login_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        enable_response = await test_client.post(
            "/auth/2fa/enable",
            json={"password": "correct-password"},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert enable_response.status_code == HTTP_CREATED
        enable_body = enable_response.json()

        confirm_response = await test_client.post(
            "/auth/2fa/enable/confirm",
            json={
                "enrollment_token": enable_body["enrollment_token"],
                "code": _generate_totp_code(enable_body["secret"], _totp_mod._current_counter()),
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert confirm_response.status_code == HTTP_CREATED

        pending_response = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_response.status_code == HTTP_ACCEPTED
        pending_token = pending_response.json()["pending_token"]

        first_verify_failure = await test_client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        second_verify_failure = await test_client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        blocked_verify = await test_client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": "000000"},
        )
        post_verify_login_failure = await test_client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "wrong-password"},
        )

    assert first_verify_failure.status_code == HTTP_BAD_REQUEST
    assert second_verify_failure.status_code == HTTP_BAD_REQUEST
    assert blocked_verify.status_code == HTTP_TOO_MANY_REQUESTS
    assert post_verify_login_failure.status_code == HTTP_BAD_REQUEST


async def test_login_rate_limit_ignores_forwarded_headers_when_trusted_proxy_disabled(
    client: tuple[AsyncTestClient[Litestar], MutableClock],
) -> None:
    """Spoofed forwarding headers are ignored when trusted_proxy is disabled."""
    test_client, _clock = client

    first_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-one@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    second_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-two@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    blocked_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-three@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.12"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert blocked_response.status_code == HTTP_TOO_MANY_REQUESTS


@pytest.mark.parametrize("app", [True], indirect=True)
async def test_login_rate_limit_uses_forwarded_headers_when_trusted_proxy_enabled(
    client: tuple[AsyncTestClient[Litestar], MutableClock],
) -> None:
    """Distinct forwarded client IPs do not share the same login throttle key."""
    test_client, _clock = client

    first_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-one@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.20"},
    )
    second_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-two@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.21"},
    )
    third_response = await test_client.post(
        "/auth/login",
        json={"identifier": "missing-three@example.com", "password": "wrong-password"},
        headers={"X-Forwarded-For": "203.0.113.22"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert third_response.status_code == HTTP_BAD_REQUEST
