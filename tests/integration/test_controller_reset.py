"""Integration tests for the generated reset-password controller."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.status_codes import HTTP_429_TOO_MANY_REQUESTS
from litestar.testing import AsyncTestClient

from litestar_auth.controllers import create_reset_password_controller
from litestar_auth.exceptions import ErrorCode
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
HTTP_UNPROCESSABLE_ENTITY = 422


class ExtendedUserRead(msgspec.Struct):
    """Custom public schema used to validate reset-password extensibility."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    login_hint: str


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records forgot-password hook invocations."""

    def __init__(
        self,
        user_db: InMemoryUserDatabase,
        password_helper: PasswordHelper,
        *,
        reset_password_token_lifetime: timedelta = timedelta(hours=1),
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize the tracking manager with predictable reset-token settings."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
                id_parser=UUID,
            ),
            reset_password_token_lifetime=reset_password_token_lifetime,
            backends=backends,
        )
        self.forgot_password_events: list[tuple[ExampleUser, str]] = []

    async def on_after_forgot_password(self, user: ExampleUser | None, token: str | None) -> None:
        """Record each generated reset-password token."""
        if user is not None and token is not None:
            self.forgot_password_events.append((user, token))


def build_app(
    *,
    reset_password_token_lifetime: timedelta = timedelta(hours=1),
    rate_limit_config: AuthRateLimitConfig | None = None,
) -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create an application wired with the generated reset-password controller.

    Returns:
        Litestar application, in-memory user database, and tracking user manager.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(
        user_db,
        password_helper,
        reset_password_token_lifetime=reset_password_token_lifetime,
    )
    controller = create_reset_password_controller(rate_limit_config=rate_limit_config)
    app = litestar_app_with_user_manager(user_manager, controller)
    return app, user_db, user_manager


@pytest.fixture
def app() -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create the shared reset-password app and collaborators.

    Returns:
        App plus the in-memory database and tracking manager.
    """
    return build_app()


def test_reset_password_publishes_request_body_in_openapi(
    app: tuple[Litestar, InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """The reset-password route publishes its request body in OpenAPI."""
    litestar_app, *_ = app

    reset_post = cast("Any", litestar_app.openapi_schema.paths)["/auth/reset-password"].post
    request_body = reset_post.request_body
    reset_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["ResetPassword"]

    assert request_body is not None
    assert next(iter(request_body.content.values())).schema.ref == "#/components/schemas/ResetPassword"
    assert "token" in (reset_schema.properties or {})
    assert "password" in (reset_schema.properties or {})


async def test_forgot_password_uses_same_response_for_existing_and_missing_email(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Forgot-password returns the same response while only issuing tokens for real users."""
    test_client, user_db, user_manager = client
    user = ExampleUser(
        id=uuid4(),
        email="forgot@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    existing_response = await test_client.post("/auth/forgot-password", json={"email": user.email})
    missing_response = await test_client.post("/auth/forgot-password", json={"email": "missing@example.com"})

    assert existing_response.status_code == HTTP_ACCEPTED
    assert missing_response.status_code == HTTP_ACCEPTED
    assert existing_response.content == missing_response.content
    assert len(user_manager.forgot_password_events) == 1
    event_user, token = user_manager.forgot_password_events[0]
    assert event_user is user
    assert isinstance(token, str)


async def test_reset_password_updates_hash_for_valid_token(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Reset-password updates the stored password hash and returns the public user payload."""
    test_client, user_db, user_manager = client
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="reset@example.com",
        hashed_password=password_helper.hash("old-password"),
        is_verified=True,
        roles=["member"],
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    original_hash = user.hashed_password

    await test_client.post("/auth/forgot-password", json={"email": user.email})
    _, token = user_manager.forgot_password_events[0]

    response = await test_client.post("/auth/reset-password", json={"token": token, "password": "new-password"})

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "is_active": True,
        "is_verified": True,
        "roles": ["member"],
    }
    stored_user = await user_db.get(user.id)
    assert stored_user is user
    assert stored_user.hashed_password != original_hash
    assert password_helper.verify("new-password", stored_user.hashed_password) is True


async def test_reset_password_token_invalid_after_password_change(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Reset-password token is invalid after the user's password has been changed."""
    test_client, user_db, user_manager = client
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="changed@example.com",
        hashed_password=password_helper.hash("old-password"),
        is_verified=True,
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    await test_client.post("/auth/forgot-password", json={"email": user.email})
    _, token = user_manager.forgot_password_events[0]

    updated_user = ExampleUser(
        id=user.id,
        email=user.email,
        hashed_password=password_helper.hash("other-password"),
        is_active=user.is_active,
        is_verified=user.is_verified,
    )
    await user_db.update(user, {"hashed_password": updated_user.hashed_password})

    response = await test_client.post(
        "/auth/reset-password",
        json={"token": token, "password": "new-password"},
    )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "The password reset token is invalid."


async def test_reset_password_rejects_invalid_and_expired_tokens() -> None:
    """Reset-password returns a 400 response for malformed and expired tokens."""
    app, user_db, user_manager = build_app(reset_password_token_lifetime=timedelta(seconds=-1))
    user = ExampleUser(
        id=uuid4(),
        email="expired@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    await user_manager.forgot_password(user.email)
    _, expired_token = user_manager.forgot_password_events[0]

    async with AsyncTestClient(app=app) as client:
        invalid_response = await client.post(
            "/auth/reset-password",
            json={"token": "not-a-valid-token", "password": "new-password"},
        )
        expired_response = await client.post(
            "/auth/reset-password",
            json={"token": expired_token, "password": "new-password"},
        )

    assert invalid_response.status_code == HTTP_BAD_REQUEST
    assert invalid_response.json()["detail"] == "The password reset token is invalid."
    assert expired_response.status_code == HTTP_BAD_REQUEST
    assert expired_response.json()["detail"] == "The password reset token is invalid."


async def test_reset_password_rejects_short_password_with_domain_error_code(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Reset-password maps manager password-policy failures to the public error code."""
    test_client, user_db, user_manager = client
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="invalid-password@example.com",
        hashed_password=password_helper.hash("old-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    await test_client.post("/auth/forgot-password", json={"email": user.email})
    _, token = user_manager.forgot_password_events[0]
    original_hash = user.hashed_password

    response = await test_client.post("/auth/reset-password", json={"token": token, "password": "short"})

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["extra"]["code"] == ErrorCode.RESET_PASSWORD_INVALID_PASSWORD
    stored_user = await user_db.get(user.id)
    assert stored_user is user
    assert stored_user.hashed_password == original_hash


async def test_reset_password_rejects_password_longer_than_128_characters() -> None:
    """Reset-password returns 422 when the submitted password exceeds the schema limit."""
    app, user_db, user_manager = build_app()
    user = ExampleUser(
        id=uuid4(),
        email="too-long-password@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    await user_manager.forgot_password(user.email)
    _, token = user_manager.forgot_password_events[0]

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/reset-password",
            json={"token": token, "password": "p" * 129},
        )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY


async def test_reset_password_rejects_malformed_json_with_controller_error_contract() -> None:
    """Reset-password keeps the legacy 400 malformed-body payload shape."""
    app, _user_db, _user_manager = build_app()

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/reset-password",
            content="not-json",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    body = response.json()
    assert body["detail"] == "Invalid request body."
    assert body["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID


async def test_reset_password_rejects_token_longer_than_2048_characters() -> None:
    """Reset-password returns 422 when the submitted token exceeds the schema limit."""
    app, _, _ = build_app()

    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/reset-password",
            json={"token": "t" * 2049, "password": "new-password"},
        )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY


async def test_reset_password_supports_custom_user_read_schema() -> None:
    """Reset-password can return a caller-provided public user schema."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    user = ExampleUser(
        id=uuid4(),
        email="custom-reset@example.com",
        hashed_password=password_helper.hash("old-password"),
        login_hint="custom-reset",
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id
    app = litestar_app_with_user_manager(
        user_manager,
        create_reset_password_controller(
            user_read_schema=ExtendedUserRead,
        ),
    )
    await user_manager.forgot_password(user.email)
    _, token = user_manager.forgot_password_events[0]

    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/reset-password", json={"token": token, "password": "new-password"})

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "is_active": True,
        "is_verified": False,
        "login_hint": "custom-reset",
    }


async def test_reset_password_rate_limit_is_optional_and_valid_requests_still_succeed() -> None:
    """Without a reset-password limiter, the endpoint keeps its previous success behavior."""
    app, user_db, user_manager = build_app()
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="rate-limit-optional@example.com",
        hashed_password=password_helper.hash("old-password"),
        is_verified=True,
        roles=["member"],
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    async with AsyncTestClient(app=app) as client:
        await client.post("/auth/forgot-password", json={"email": user.email})
        _, token = user_manager.forgot_password_events[0]
        response = await client.post("/auth/reset-password", json={"token": token, "password": "new-password"})

    assert response.status_code == HTTP_OK
    stored_user = await user_db.get(user.id)
    assert stored_user is user
    assert password_helper.verify("new-password", stored_user.hashed_password) is True


async def test_forgot_password_rate_limit_increments_for_existing_and_missing_email() -> None:
    """Forgot-password increments its limiter for both real and missing accounts."""
    expected_attempts = 2
    rate_limiter_backend = AsyncMock()
    rate_limiter_backend.check.return_value = True
    rate_limiter_backend.retry_after.return_value = 0

    rate_limit_config = AuthRateLimitConfig(
        forgot_password=EndpointRateLimit(
            backend=rate_limiter_backend,
            scope="ip_email",
            namespace="forgot-password",
        ),
    )
    app, user_db, _user_manager = build_app(rate_limit_config=rate_limit_config)
    user = ExampleUser(
        id=uuid4(),
        email="forgot-rate-limit@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[user.id] = user
    user_db.user_ids_by_email[user.email] = user.id

    async with AsyncTestClient(app=app) as client:
        existing_response = await client.post("/auth/forgot-password", json={"email": user.email})
        missing_response = await client.post("/auth/forgot-password", json={"email": "missing@example.com"})

    assert existing_response.status_code == HTTP_ACCEPTED
    assert missing_response.status_code == HTTP_ACCEPTED
    assert rate_limiter_backend.check.await_count == expected_attempts
    assert rate_limiter_backend.increment.await_count == expected_attempts


async def test_forgot_password_rate_limit_triggers_429() -> None:
    """Forgot-password rejects requests before dispatch when the limiter is exhausted."""
    rate_limiter_backend = AsyncMock()
    rate_limiter_backend.check.return_value = False
    rate_limiter_backend.retry_after.return_value = 2

    rate_limit_config = AuthRateLimitConfig(
        forgot_password=EndpointRateLimit(
            backend=rate_limiter_backend,
            scope="ip_email",
            namespace="forgot-password",
        ),
    )
    app, _, _ = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        response = await client.post("/auth/forgot-password", json={"email": "unknown@example.com"})

    assert response.status_code == HTTP_429_TOO_MANY_REQUESTS
    assert response.headers.get("Retry-After") == "2"
    assert rate_limiter_backend.increment.await_count == 0


async def test_reset_password_rate_limit_returns_429_after_repeated_invalid_attempts() -> None:
    """Configured reset-password throttling blocks repeated invalid token submissions."""
    rate_limit_config = AuthRateLimitConfig(
        reset_password=EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=2, window_seconds=60),
            scope="ip",
            namespace="reset-password",
        ),
    )
    app, _user_db, _user_manager = build_app(rate_limit_config=rate_limit_config)

    async with AsyncTestClient(app=app) as client:
        first_response = await client.post(
            "/auth/reset-password",
            json={"token": "not-a-valid-token", "password": "new-password"},
        )
        second_response = await client.post(
            "/auth/reset-password",
            json={"token": "also-not-valid", "password": "new-password"},
        )
        blocked_response = await client.post(
            "/auth/reset-password",
            json={"token": "still-not-valid", "password": "new-password"},
        )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    assert blocked_response.status_code == HTTP_429_TOO_MANY_REQUESTS
    assert blocked_response.headers["Retry-After"].isdigit()
    assert int(blocked_response.headers["Retry-After"]) >= 1


def test_reset_password_rejects_non_msgspec_user_read_schema() -> None:
    """Reset-password configurable response schemas must be msgspec structs."""

    class InvalidSchema:
        pass

    with pytest.raises(TypeError, match=r"user_read_schema must be a msgspec\.Struct subclass\."):
        create_reset_password_controller(
            user_read_schema=cast("Any", InvalidSchema),
        )
