"""Integration tests for the generated registration controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest

from litestar_auth.controllers import create_register_controller
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from litestar import Litestar
else:
    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.integration
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNPROCESSABLE_ENTITY = 422
EXPECTED_RATE_LIMITED_REQUESTS = 2


class TrackingUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records registration hook invocations."""

    def __init__(
        self,
        user_db: InMemoryUserDatabase,
        password_helper: PasswordHelper,
        *,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize the tracking manager."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
                id_parser=UUID,
            ),
            backends=backends,
        )
        self.registered_users: list[ExampleUser] = []
        self.registration_tokens: dict[str, str] = {}

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Record each successfully created user."""
        self.registered_users.append(user)
        self.registration_tokens[user.email] = token


class PrivilegedRegistrationCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Custom registration schema that exposes privileged account-state fields."""

    email: str
    password: str
    is_active: bool = True
    is_verified: bool = False
    roles: list[str] | None = None


class ExtendedRegistrationCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Custom registration schema with a non-privileged extra field."""

    email: str
    password: str
    bio: str


class WeakPasswordRegistrationCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Custom registration schema that defers password validation to the manager."""

    email: str
    password: str


def build_app(
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
) -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create an application wired with the generated register controller.

    Returns:
        Litestar application, in-memory user database, and tracking user manager.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(rate_limit_config=rate_limit_config)
    app = litestar_app_with_user_manager(user_manager, controller)
    return app, user_db, user_manager


@pytest.fixture
def app() -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create the shared register-controller app and collaborators.

    Returns:
        App plus the in-memory database and tracking manager.
    """
    return build_app()


def test_register_publishes_request_body_for_custom_schema_in_openapi() -> None:
    """The configured registration schema is published as the OpenAPI request body."""
    password_helper = PasswordHelper()
    user_manager = TrackingUserManager(InMemoryUserDatabase(), password_helper)
    controller = create_register_controller(user_create_schema=ExtendedRegistrationCreate)
    app = litestar_app_with_user_manager(user_manager, controller)

    register_post = cast("Any", app.openapi_schema.paths)["/auth/register"].post
    request_body = register_post.request_body
    register_schema = cast("Any", app.openapi_schema.components.schemas)["ExtendedRegistrationCreate"]

    assert request_body is not None
    assert next(iter(request_body.content.values())).schema.ref == "#/components/schemas/ExtendedRegistrationCreate"
    assert "bio" in (register_schema.properties or {})


async def test_register_creates_user_returns_public_payload_and_calls_hook(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Register creates a hashed user and returns only public fields."""
    test_client, user_db, user_manager = client

    response = await test_client.post(
        "/auth/register",
        json={"email": "new@example.com", "password": "plain-password"},
    )

    assert response.status_code == HTTP_CREATED
    payload = response.json()
    assert payload["email"] == "new@example.com"
    assert payload["is_active"] is True
    assert payload["is_verified"] is False
    assert payload["roles"] == []
    assert "hashed_password" not in payload

    created_user = await user_db.get_by_email("new@example.com")
    assert created_user is not None
    assert created_user.hashed_password != "plain-password"
    assert PasswordHelper().verify("plain-password", created_user.hashed_password) is True
    assert user_manager.registered_users == [created_user]
    assert user_manager.registration_tokens["new@example.com"]


async def test_register_hook_token_verifies_created_user(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """The register hook receives a verification token that the manager accepts."""
    test_client, user_db, user_manager = client

    response = await test_client.post(
        "/auth/register",
        json={"email": "verify-me@example.com", "password": "plain-password"},
    )

    assert response.status_code == HTTP_CREATED
    created_user = await user_db.get_by_email("verify-me@example.com")
    assert created_user is not None

    verified_user = await user_manager.verify(user_manager.registration_tokens[created_user.email])

    assert verified_user is created_user
    assert verified_user.is_verified is True


async def test_register_rejects_duplicate_email(
    client: tuple[AsyncTestClient[Litestar], InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Register returns a 400 response and stable error code when the email already exists."""
    test_client, user_db, _ = client
    existing_user = ExampleUser(
        id=uuid4(),
        email="duplicate@example.com",
        hashed_password=PasswordHelper().hash("existing-password"),
    )
    user_db.users_by_id[existing_user.id] = existing_user
    user_db.user_ids_by_email[existing_user.email] = existing_user.id

    response = await test_client.post(
        "/auth/register",
        json={"email": "duplicate@example.com", "password": "new-password"},
    )

    assert response.status_code == HTTP_BAD_REQUEST
    body = response.json()
    assert body["detail"] == "A user with the provided credentials already exists."
    assert body["extra"]["code"] == ErrorCode.REGISTER_USER_ALREADY_EXISTS


async def test_register_rejects_invalid_password_with_error_code(
    async_test_client_factory: Callable[[Litestar], AbstractAsyncContextManager[AsyncTestClient[Litestar]]],
) -> None:
    """Register returns a 400 response and stable error code for weak passwords."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(user_create_schema=WeakPasswordRegistrationCreate)
    app = litestar_app_with_user_manager(user_manager, controller)

    async with async_test_client_factory(app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={"email": "weak-password@example.com", "password": "short"},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    body = response.json()
    assert body["detail"] == "Password must be at least 12 characters long."
    assert body["extra"]["code"] == ErrorCode.REGISTER_INVALID_PASSWORD


async def test_register_rejects_schema_validation_errors() -> None:
    """Register returns 422 with the request-body-invalid code for schema mismatches."""
    app, _user_db, _user_manager = build_app()

    async with AsyncTestClient(app=app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={"email": "schema@example.com", "password": 123},
        )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    body = response.json()
    assert body["detail"] == "Invalid request payload."
    assert body["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID


async def test_register_rejects_malformed_json_with_controller_error_contract() -> None:
    """Register keeps the legacy 400 malformed-body payload shape."""
    app, _user_db, _user_manager = build_app()

    async with AsyncTestClient(app=app) as test_client:
        response = await test_client.post(
            "/auth/register",
            content="not-json",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    body = response.json()
    assert body["detail"] == "Invalid request body."
    assert body["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID


async def test_register_rate_limit_callbacks_fire_for_success_and_error() -> None:
    """Register increments on mapped errors and resets on successful registration."""
    rate_limiter_backend = AsyncMock()
    rate_limiter_backend.check.return_value = True
    rate_limiter_backend.retry_after.return_value = 0
    rate_limit_config = AuthRateLimitConfig(
        register=EndpointRateLimit(
            backend=rate_limiter_backend,
            scope="ip",
            namespace="register",
        ),
    )
    app, user_db, _user_manager = build_app(rate_limit_config=rate_limit_config)
    existing_user = ExampleUser(
        id=uuid4(),
        email="duplicate-rate-limit@example.com",
        hashed_password=PasswordHelper().hash("plain-password"),
    )
    user_db.users_by_id[existing_user.id] = existing_user
    user_db.user_ids_by_email[existing_user.email] = existing_user.id
    async with AsyncTestClient(app=app) as test_client:
        duplicate_response = await test_client.post(
            "/auth/register",
            json={"email": existing_user.email, "password": "plain-password"},
        )
        success_response = await test_client.post(
            "/auth/register",
            json={"email": "rate-limit-success@example.com", "password": "plain-password"},
        )

    assert duplicate_response.status_code == HTTP_BAD_REQUEST
    assert success_response.status_code == HTTP_CREATED
    assert rate_limiter_backend.check.await_count == EXPECTED_RATE_LIMITED_REQUESTS
    assert rate_limiter_backend.increment.await_count == 1
    assert rate_limiter_backend.reset.await_count == 1


async def test_register_ignores_privileged_fields_from_custom_schema(
    async_test_client_factory: Callable[[Litestar], AbstractAsyncContextManager[AsyncTestClient[Litestar]]],
) -> None:
    """Registration never persists privileged fields from a custom payload schema."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(user_create_schema=PrivilegedRegistrationCreate)
    app = litestar_app_with_user_manager(user_manager, controller)

    async with async_test_client_factory(app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={
                "email": "privileged@example.com",
                "password": "plain-password",
                "is_active": False,
                "is_verified": True,
                "roles": [" Billing ", "ADMIN"],
            },
        )

    assert response.status_code == HTTP_CREATED
    payload = response.json()
    assert set(payload) == {"email", "id", "is_active", "is_verified", "roles"}
    assert payload["is_active"] is True
    assert payload["is_verified"] is False
    assert payload["roles"] == []

    created_user = await user_db.get_by_email("privileged@example.com")
    assert created_user is not None
    assert created_user.is_active is True
    assert created_user.is_verified is False
    assert created_user.roles == []


async def test_register_rejects_unknown_fields_from_builtin_schema(
    app: tuple[Litestar, InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """Built-in registration schema rejects undeclared request fields during decoding."""
    register_app, user_db, user_manager = app

    async with AsyncTestClient(app=register_app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={
                "email": "unknown-field@example.com",
                "password": "plain-password",
                "deprecated_admin_flag": True,
            },
        )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    body = response.json()
    assert (body.get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID
    assert await user_db.get_by_email("unknown-field@example.com") is None
    assert user_manager.registered_users == []


async def test_register_ignores_non_safe_fields_from_custom_schema(
    async_test_client_factory: Callable[[Litestar], AbstractAsyncContextManager[AsyncTestClient[Litestar]]],
) -> None:
    """Registration only persists SAFE_FIELDS even when the schema includes extras."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(user_create_schema=ExtendedRegistrationCreate)
    app = litestar_app_with_user_manager(user_manager, controller)

    async with async_test_client_factory(app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={
                "email": "safe@example.com",
                "password": "plain-password",
                "bio": "should-not-persist",
            },
        )

    assert response.status_code == HTTP_CREATED

    created_user = await user_db.get_by_email("safe@example.com")
    assert created_user is not None
    assert not created_user.bio
