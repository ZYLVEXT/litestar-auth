"""Integration tests for the generated verification controller."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.status_codes import HTTP_429_TOO_MANY_REQUESTS
from litestar.testing import AsyncTestClient

from litestar_auth.controllers import create_verify_controller
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

if TYPE_CHECKING:
    from litestar import Litestar

pytestmark = pytest.mark.integration
HTTP_OK = 200
HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400


class ExtendedUserRead(msgspec.Struct):
    """Custom public schema used to validate verification extensibility."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    login_hint: str


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records verify-token request hook invocations."""

    def __init__(
        self,
        user_db: InMemoryUserDatabase,
        password_helper: PasswordHelper,
        *,
        verification_token_lifetime: timedelta = timedelta(hours=1),
        backends: tuple[object, ...] = (),
        login_identifier: Literal["email", "username"] = "email",
    ) -> None:
        """Initialize the tracking manager with predictable verification settings."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
                id_parser=UUID,
            ),
            verification_token_lifetime=verification_token_lifetime,
            backends=backends,
            login_identifier=login_identifier,
        )
        self.request_verify_events: list[tuple[ExampleUser | None, str | None]] = []

    async def on_after_request_verify_token(self, user: ExampleUser | None, token: str | None) -> None:
        """Record each requested verification token."""
        self.request_verify_events.append((user, token))


def build_app(
    *,
    verification_token_lifetime: timedelta = timedelta(hours=1),
    rate_limit_config: AuthRateLimitConfig | None = None,
    login_identifier: Literal["email", "username"] = "email",
) -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create an application wired with the generated verify controller.

    Returns:
        Litestar application, in-memory user database, and tracking user manager.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(
        user_db,
        password_helper,
        verification_token_lifetime=verification_token_lifetime,
        login_identifier=login_identifier,
    )
    controller = create_verify_controller(rate_limit_config=rate_limit_config)
    app = litestar_app_with_user_manager(user_manager, controller)
    return app, user_db, user_manager


@pytest.fixture
def app() -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create the shared verify-controller app and collaborators.

    Returns:
        App plus the in-memory database and tracking manager.
    """
    return build_app()


async def test_verify_marks_user_as_verified(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Verify updates the stored user and returns the public payload."""
    test_client, user_db, user_manager = client
    user = ExampleUser(
        id=uuid4(),
        email="verify@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
        roles=["member"],
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    token = user_manager.write_verify_token(user)

    response = await test_client.post("/auth/verify", json={"token": token})

    assert response.status_code == HTTP_OK
    payload = response.json()
    assert payload["email"] == user.email
    assert payload["is_verified"] is True
    assert payload["roles"] == ["member"]
    stored_user = await user_db.get(user.id)
    assert stored_user is not None
    assert stored_user.is_verified is True


async def test_verify_rejects_invalid_and_expired_tokens() -> None:
    """Verify returns a 400 response for malformed and expired tokens."""
    app, user_db, user_manager = build_app(verification_token_lifetime=timedelta(seconds=-1))
    user = ExampleUser(
        id=uuid4(),
        email="expired@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    expired_token = user_manager.write_verify_token(user)

    async with AsyncTestClient(app=app) as client:
        invalid_response = await client.post("/auth/verify", json={"token": "not-a-valid-token"})
        expired_response = await client.post("/auth/verify", json={"token": expired_token})

    assert invalid_response.status_code == HTTP_BAD_REQUEST
    assert invalid_response.json()["detail"] == "The email verification token is invalid."
    assert expired_response.status_code == HTTP_BAD_REQUEST
    assert expired_response.json()["detail"] == "The email verification token is invalid."


async def test_verify_rate_limit_is_optional_and_valid_requests_still_succeed() -> None:
    """Without a verify limiter, the endpoint keeps its previous success behavior."""
    app, user_db, user_manager = build_app()
    user = ExampleUser(
        id=uuid4(),
        email="verify-rate-limit@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
        roles=["member"],
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    token = user_manager.write_verify_token(user)

    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/verify", json={"token": token})

    assert response.status_code == HTTP_OK
    stored_user = await user_db.get(user.id)
    assert stored_user is not None
    assert stored_user.is_verified is True


async def test_verify_rate_limit_returns_429_after_repeated_invalid_attempts() -> None:
    """Configured verify throttling blocks repeated invalid token submissions."""
    rate_limit_config = AuthRateLimitConfig(
        verify_token=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="verify-token",
        ),
    )
    app, _user_db, _user_manager = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        first_response = await client.post("/auth/verify", json={"token": "not-a-valid-token"})
        second_response = await client.post("/auth/verify", json={"token": "also-not-valid"})
        blocked_response = await client.post("/auth/verify", json={"token": "still-not-valid"})

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert blocked_response.status_code == HTTP_429_TOO_MANY_REQUESTS
    assert blocked_response.headers["Retry-After"].isdigit()
    assert int(blocked_response.headers["Retry-After"]) >= 1


async def test_verify_rejects_already_verified_user(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Verify returns a 400 response for users that are already verified."""
    test_client, user_db, user_manager = client
    user = ExampleUser(
        id=uuid4(),
        email="verified@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
        is_verified=True,
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    token = user_manager.write_verify_token(replace(user, is_verified=False))

    response = await test_client.post("/auth/verify", json={"token": token})

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "The user is already verified."


async def test_request_verify_token_calls_hook_for_existing_unverified_user(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Requesting a verify token records the hook payload for email delivery."""
    test_client, user_db, user_manager = client
    user = ExampleUser(
        id=uuid4(),
        email="request@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    response = await test_client.post("/auth/request-verify-token", json={"email": user.email})

    assert response.status_code == HTTP_ACCEPTED
    assert len(user_manager.request_verify_events) == 1
    event_user, token = user_manager.request_verify_events[0]
    assert event_user is user
    assert isinstance(token, str)


@pytest.mark.parametrize("email", ["missing@example.com", "verified@example.com"])
async def test_request_verify_token_redacts_verified_and_missing_accounts(
    email: str,
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Verify-token requests keep the public hook payload redacted when not deliverable."""
    test_client, user_db, user_manager = client
    if email == "verified@example.com":
        user = ExampleUser(
            id=uuid4(),
            email=email,
            hashed_password=PasswordHelper().hash("plain-password"),
            is_verified=True,
        )
        user_db.users_by_id[user.id] = user
        user_db.user_ids_by_email[user.email] = user.id

    response = await test_client.post("/auth/request-verify-token", json={"email": email})

    assert response.status_code == HTTP_ACCEPTED
    assert user_manager.request_verify_events == [(None, None)]


async def test_verify_flows_stay_email_and_token_based_under_username_login_mode() -> None:
    """Username-mode login configuration does not change verify email/token contracts."""
    app, user_db, user_manager = build_app(login_identifier="username")
    user = ExampleUser(
        id=uuid4(),
        email="username-verify@example.com",
        username="verifyuser",
        hashed_password=PasswordHelper().hash("plain-password"),
        roles=["member"],
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    async with AsyncTestClient(app=app) as client:
        request_response = await client.post("/auth/request-verify-token", json={"email": user.email})
        verify_token = user_manager.request_verify_events[0][1]
        verify_response = await client.post("/auth/verify", json={"token": verify_token})

    assert user_manager.login_identifier == "username"
    assert request_response.status_code == HTTP_ACCEPTED
    assert verify_response.status_code == HTTP_OK
    assert verify_response.json()["email"] == user.email
    assert verify_response.json()["is_verified"] is True
    assert verify_response.json()["roles"] == ["member"]


async def test_verify_supports_custom_user_read_schema() -> None:
    """Verify can return a caller-provided public user schema."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    user = ExampleUser(
        id=uuid4(),
        email="custom-verify@example.com",
        hashed_password=password_helper.hash("plain-password"),
        login_hint="custom-verify",
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    token = user_manager.write_verify_token(user)
    app = litestar_app_with_user_manager(
        user_manager,
        create_verify_controller(
            user_read_schema=ExtendedUserRead,
        ),
    )

    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/verify", json={"token": token})

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "is_active": True,
        "is_verified": True,
        "is_superuser": False,
        "login_hint": "custom-verify",
    }


def test_verify_rejects_non_msgspec_user_read_schema() -> None:
    """Verify configurable response schemas must be msgspec structs."""

    class InvalidSchema:
        pass

    with pytest.raises(TypeError, match=r"user_read_schema must be a msgspec\.Struct subclass\."):
        create_verify_controller(
            user_read_schema=cast("Any", InvalidSchema),
        )


async def test_request_verify_token_rate_limit_increments_for_any_request() -> None:
    """POST /auth/request-verify-token applies rate-limit increment wiring."""
    rate_limiter_backend = AsyncMock()
    rate_limiter_backend.check.return_value = True
    rate_limiter_backend.retry_after.return_value = 0

    rate_limit_config = AuthRateLimitConfig(
        request_verify_token=EndpointRateLimit(
            backend=rate_limiter_backend,
            scope="ip_email",
            namespace="verify-request",
        ),
    )

    app, _, _ = build_app(rate_limit_config=rate_limit_config)
    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/auth/request-verify-token",
            json={"email": "unknown@example.com"},
        )

    assert resp.status_code == HTTP_ACCEPTED
    assert rate_limiter_backend.check.await_count == 1
    assert rate_limiter_backend.increment.await_count == 1


async def test_request_verify_token_rate_limit_triggers_429() -> None:
    """POST /auth/request-verify-token triggers a 429 when the limiter rejects the request."""
    rate_limiter_backend = AsyncMock()
    rate_limiter_backend.check.return_value = False
    rate_limiter_backend.retry_after.return_value = 2

    rate_limit_config = AuthRateLimitConfig(
        request_verify_token=EndpointRateLimit(
            backend=rate_limiter_backend,
            scope="ip_email",
            namespace="verify-request",
        ),
    )

    app, _, _ = build_app(rate_limit_config=rate_limit_config)
    async with AsyncTestClient(app=app) as client:
        resp = await client.post("/auth/request-verify-token", json={"email": "unknown@example.com"})

    assert resp.status_code == HTTP_429_TOO_MANY_REQUESTS
    assert resp.headers.get("Retry-After") == "2"
    assert rate_limiter_backend.increment.await_count == 0
