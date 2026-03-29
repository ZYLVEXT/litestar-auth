"""Integration tests for auth endpoint rate-limiting hooks."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.middleware import DefineMiddleware

import litestar_auth.totp as _totp_mod
from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import (
    create_auth_controller,
    create_register_controller,
    create_reset_password_controller,
    create_totp_controller,
)
from litestar_auth.manager import BaseUserManager
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter
from litestar_auth.totp import InMemoryUsedTotpCodeStore, _generate_totp_code
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import DummySessionMaker, ExampleUser, InMemoryTokenStrategy, InMemoryUserDatabase

if TYPE_CHECKING:
    from httpx import Response
    from litestar import Litestar
    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_TOO_MANY_REQUESTS = 429

TOTP_PENDING_SECRET = "test-totp-pending-secret-thirty-two!"


def build_rate_limit_config() -> AuthRateLimitConfig:
    """Create a task-specific rate-limit configuration.

    Returns:
        Shared endpoint rules for the protected auth routes.
    """
    return AuthRateLimitConfig(
        login=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip_email",
            namespace="login",
        ),
        register=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="register",
        ),
        forgot_password=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="forgot-password",
        ),
        totp_verify=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="totp-verify",
        ),
    )


def build_app() -> Litestar:
    """Create an application wired with auth rate limiting.

    Returns:
        Litestar application configured with auth controllers and rate limits.
    """
    password_helper = PasswordHelper()
    existing_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
    )
    user_db = InMemoryUserDatabase([existing_user])
    user_manager = BaseUserManager[ExampleUser, UUID](
        user_db,
        password_helper=password_helper,
        verification_token_secret="verify-secret-1234567890-1234567890",
        reset_password_token_secret="reset-password-secret-1234567890-1234567890",
        reset_password_token_lifetime=timedelta(hours=1),
        id_parser=UUID,
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )
    rate_limit_config = build_rate_limit_config()

    handlers = [
        create_auth_controller(
            backend=backend,
            rate_limit_config=rate_limit_config,
            totp_pending_secret=TOTP_PENDING_SECRET,
        ),
        create_register_controller(
            rate_limit_config=rate_limit_config,
        ),
        create_reset_password_controller(
            rate_limit_config=rate_limit_config,
        ),
        create_totp_controller(
            backend=backend,
            user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
            used_tokens_store=InMemoryUsedTotpCodeStore(),
            rate_limit_config=rate_limit_config,
            totp_pending_secret=TOTP_PENDING_SECRET,
            totp_enable_requires_password=False,
            id_parser=UUID,
        ),
    ]
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    return litestar_app_with_user_manager(user_manager, *handlers, middleware=[middleware])


@pytest.fixture
def app() -> Litestar:
    """Create the shared rate-limit middleware app.

    Returns:
        Litestar app configured with auth endpoint rate limits.
    """
    return build_app()


def assert_rate_limited(response: Response[Any]) -> None:
    """Assert that a response carries the expected 429 rate-limit details."""
    assert response.status_code == HTTP_TOO_MANY_REQUESTS
    assert response.headers["Retry-After"].isdigit()
    assert int(response.headers["Retry-After"]) >= 1


async def test_login_rate_limit_uses_ip_and_email_key(client: AsyncTestClient[Litestar]) -> None:
    """Failed login attempts are isolated per email on the same IP."""
    first_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "wrong-password"},
    )
    second_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "wrong-password"},
    )
    blocked_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "wrong-password"},
    )
    other_email_response = await client.post(
        "/auth/login",
        json={"identifier": "other@example.com", "password": "wrong-password"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert_rate_limited(blocked_response)
    assert other_email_response.status_code == HTTP_BAD_REQUEST


async def test_register_rate_limit_uses_ip_key(client: AsyncTestClient[Litestar]) -> None:
    """Registration attempts share a single limit per client IP."""
    first_response = await client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "new-password"},
    )
    second_response = await client.post(
        "/auth/register",
        json={"email": "user@example.com", "password": "new-password"},
    )
    blocked_response = await client.post(
        "/auth/register",
        json={"email": "fresh@example.com", "password": "new-password"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert_rate_limited(blocked_response)


async def test_forgot_password_rate_limit_returns_429_after_configured_attempts(
    client: AsyncTestClient[Litestar],
) -> None:
    """Forgot-password requests are limited by IP and return Retry-After."""
    first_response = await client.post("/auth/forgot-password", json={"email": "user@example.com"})
    second_response = await client.post("/auth/forgot-password", json={"email": "user@example.com"})
    blocked_response = await client.post("/auth/forgot-password", json={"email": "user@example.com"})

    assert first_response.status_code == HTTP_ACCEPTED
    assert second_response.status_code == HTTP_ACCEPTED
    assert_rate_limited(blocked_response)


async def test_totp_verify_rate_limit_returns_429_after_invalid_codes(
    client: AsyncTestClient[Litestar],
) -> None:
    """Invalid TOTP verification attempts are rate-limited with Retry-After."""
    login_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    access_token = login_response.json()["access_token"]

    enable_response = await client.post("/auth/2fa/enable", headers={"Authorization": f"Bearer {access_token}"})
    assert enable_response.status_code == HTTP_CREATED
    enable_body = enable_response.json()
    assert enable_body["secret"]

    # Confirm enrollment
    confirm_code = _generate_totp_code(enable_body["secret"], _totp_mod._current_counter())
    confirm_response = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert confirm_response.status_code == HTTP_CREATED

    pending_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_response.status_code == HTTP_ACCEPTED
    pending_token = pending_response.json()["pending_token"]

    first_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    second_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )
    blocked_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": "000000"},
    )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert_rate_limited(blocked_response)


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_totp_management_endpoints_do_not_trigger_verify_throttle(
    client: AsyncTestClient[Litestar],
) -> None:
    """Enable/disable failures remain outside the verify throttling contract."""
    login_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    access_token = login_response.json()["access_token"]

    enable_response = await client.post(
        "/auth/2fa/enable",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable_response.status_code == HTTP_CREATED
    enable_body = enable_response.json()
    secret = enable_body["secret"]

    confirm_code = _generate_totp_code(secret, _totp_mod._current_counter())
    confirm_response = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert confirm_response.status_code == HTTP_CREATED

    pending_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_response.status_code == HTTP_ACCEPTED
    pending_token = pending_response.json()["pending_token"]

    verify_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_token, "code": _generate_totp_code(secret, _totp_mod._current_counter())},
    )
    assert verify_response.status_code == HTTP_CREATED
    full_token = verify_response.json()["access_token"]

    first_disable_failure = await client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    second_disable_failure = await client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    third_disable_failure = await client.post(
        "/auth/2fa/disable",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {full_token}"},
    )
    assert first_disable_failure.status_code == HTTP_BAD_REQUEST
    assert second_disable_failure.status_code == HTTP_BAD_REQUEST
    assert third_disable_failure.status_code == HTTP_BAD_REQUEST

    pending_for_throttle = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    pending_for_throttle_token = pending_for_throttle.json()["pending_token"]

    first_verify_failure = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_for_throttle_token, "code": "000000"},
    )
    second_verify_failure = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_for_throttle_token, "code": "000000"},
    )
    blocked_verify = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_for_throttle_token, "code": "000000"},
    )
    assert first_verify_failure.status_code == HTTP_BAD_REQUEST
    assert second_verify_failure.status_code == HTTP_BAD_REQUEST
    assert_rate_limited(blocked_verify)
