"""Integration tests for the generated registration controller."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import msgspec
import pytest

from litestar_auth.controllers import create_register_controller
from litestar_auth.exceptions import AuthorizationError, ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit
from tests._helpers import litestar_app_with_user_manager
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from contextlib import AbstractAsyncContextManager

    from litestar import Litestar
    from litestar.openapi.spec import OpenAPIResponse
else:
    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.integration
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNPROCESSABLE_ENTITY = 422
EXPECTED_RATE_LIMITED_REQUESTS = 2
REGISTER_FAILURE_DETAIL = "Registration could not be completed."


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
        self.duplicate_registration_users: list[ExampleUser] = []

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Record each successfully created user."""
        self.registered_users.append(user)
        self.registration_tokens[user.email] = token

    async def on_after_register_duplicate(self, user: ExampleUser) -> None:
        """Record duplicate registration attempts for owner notifications."""
        self.duplicate_registration_users.append(user)


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


def _openapi_example_values(response: OpenAPIResponse) -> list[dict[str, object]]:
    """Return OpenAPI response example values as plain dictionaries."""
    content = response.content or {}
    media_type = next(iter(content.values()))
    examples = media_type.examples or {}
    return [cast("dict[str, object]", example.value) for example in examples.values()]


def build_app(
    *,
    rate_limit_config: AuthRateLimitConfig | None = None,
    register_minimum_response_seconds: float = 0,
) -> tuple[Litestar, InMemoryUserDatabase, TrackingUserManager]:
    """Create an application wired with the generated register controller.

    Returns:
        Litestar application, in-memory user database, and tracking user manager.
    """
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(
        rate_limit_config=rate_limit_config,
        register_minimum_response_seconds=register_minimum_response_seconds,
    )
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
    controller = create_register_controller(
        user_create_schema=ExtendedRegistrationCreate,
        register_minimum_response_seconds=0,
    )
    app = litestar_app_with_user_manager(user_manager, controller)

    register_post = cast("Any", app.openapi_schema.paths)["/auth/register"].post
    request_body = register_post.request_body
    register_schema = cast("Any", app.openapi_schema.components.schemas)["ExtendedRegistrationCreate"]

    assert request_body is not None
    assert next(iter(request_body.content.values())).schema.ref == "#/components/schemas/ExtendedRegistrationCreate"
    assert "bio" in (register_schema.properties or {})


def test_register_openapi_documents_enumeration_resistant_failure_codes(
    app: tuple[Litestar, InMemoryUserDatabase, TrackingUserManager],
) -> None:
    """The register OpenAPI response examples expose only the generic domain failure code."""
    litestar_app, *_ = app
    register_post = cast("Any", litestar_app.openapi_schema.paths)["/auth/register"].post

    responses = register_post.responses
    assert {"201", "400", "422", "429"}.issubset(responses)
    assert ErrorCode.REGISTER_FAILED.value in responses["400"].description
    assert ErrorCode.REQUEST_BODY_INVALID.value in responses["400"].description
    assert ErrorCode.REQUEST_BODY_INVALID.value in responses["422"].description
    assert "Retry-After" in responses["429"].description

    bad_request_examples = _openapi_example_values(responses["400"])
    unprocessable_examples = _openapi_example_values(responses["422"])
    register_failure_examples = [
        example for example in bad_request_examples if example["detail"] == REGISTER_FAILURE_DETAIL
    ]
    validation_examples = [
        *[example for example in bad_request_examples if example["detail"] != REGISTER_FAILURE_DETAIL],
        *unprocessable_examples,
    ]

    assert {cast("dict[str, str]", example["extra"])["code"] for example in register_failure_examples} == {
        ErrorCode.REGISTER_FAILED.value,
    }
    assert {cast("dict[str, str]", example["extra"])["code"] for example in validation_examples} == {
        ErrorCode.REQUEST_BODY_INVALID.value,
    }


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
    """Register returns the generic failure response when the email already exists."""
    test_client, user_db, user_manager = client
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
    assert body["detail"] == REGISTER_FAILURE_DETAIL
    assert body["extra"]["code"] == ErrorCode.REGISTER_FAILED
    assert user_manager.duplicate_registration_users == [existing_user]


async def test_register_rejects_invalid_password_with_error_code(
    async_test_client_factory: Callable[[Litestar], AbstractAsyncContextManager[AsyncTestClient[Litestar]]],
) -> None:
    """Register returns the generic failure response for weak passwords."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(
        user_create_schema=WeakPasswordRegistrationCreate,
        register_minimum_response_seconds=0,
    )
    app = litestar_app_with_user_manager(user_manager, controller)

    async with async_test_client_factory(app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={"email": "weak-password@example.com", "password": "short"},
        )

    assert response.status_code == HTTP_BAD_REQUEST
    body = response.json()
    assert body["detail"] == REGISTER_FAILURE_DETAIL
    assert body["extra"]["code"] == ErrorCode.REGISTER_FAILED


async def test_register_failures_share_response_body_and_increment_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Duplicate, password-policy, and authorization failures expose the same response body."""
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
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    existing_user = ExampleUser(
        id=uuid4(),
        email="registered@example.com",
        hashed_password=password_helper.hash("existing-password"),
    )
    user_db.users_by_id[existing_user.id] = existing_user
    user_db.user_ids_by_email[existing_user.email] = existing_user.id
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(
        rate_limit_config=rate_limit_config,
        user_create_schema=WeakPasswordRegistrationCreate,
        register_minimum_response_seconds=0,
    )
    app = litestar_app_with_user_manager(user_manager, controller)

    async with AsyncTestClient(app=app) as test_client:
        duplicate_response = await test_client.post(
            "/auth/register",
            json={"email": existing_user.email, "password": "valid-password"},
        )
        invalid_password_response = await test_client.post(
            "/auth/register",
            json={"email": "weak-password@example.com", "password": "short"},
        )

        with monkeypatch.context() as patch_context:
            patch_context.setattr(
                user_manager,
                "create",
                AsyncMock(side_effect=AuthorizationError("Custom registration policy rejected the request.")),
            )
            authorization_response = await test_client.post(
                "/auth/register",
                json={"email": "authorization@example.com", "password": "valid-password"},
            )

        success_response = await test_client.post(
            "/auth/register",
            json={"email": "fresh@example.com", "password": "valid-password"},
        )

    failure_responses = [duplicate_response, invalid_password_response, authorization_response]
    for response in failure_responses:
        assert response.status_code == HTTP_BAD_REQUEST
        assert response.json() == {
            "status_code": HTTP_BAD_REQUEST,
            "detail": REGISTER_FAILURE_DETAIL,
            "extra": {"code": ErrorCode.REGISTER_FAILED},
        }

    assert duplicate_response.content == invalid_password_response.content == authorization_response.content
    assert success_response.status_code == HTTP_CREATED
    assert user_manager.duplicate_registration_users == [existing_user]
    assert rate_limiter_backend.increment.await_count == len(failure_responses)
    assert rate_limiter_backend.reset.await_count == 1


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


async def test_register_applies_minimum_response_duration_to_success_and_domain_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Success, duplicate, password-policy, and authorization paths all meet the configured lower bound."""
    minimum_seconds = 0.05
    tolerance_seconds = 0.005
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase()
    existing_user = ExampleUser(
        id=uuid4(),
        email="timing-registered@example.com",
        hashed_password=password_helper.hash("existing-password"),
    )
    user_db.users_by_id[existing_user.id] = existing_user
    user_db.user_ids_by_email[existing_user.email] = existing_user.id
    user_manager = TrackingUserManager(user_db, password_helper)
    controller = create_register_controller(
        user_create_schema=WeakPasswordRegistrationCreate,
        register_minimum_response_seconds=minimum_seconds,
    )
    app = litestar_app_with_user_manager(user_manager, controller)

    async with AsyncTestClient(app=app) as test_client:
        started_at = time.perf_counter()
        duplicate_response = await test_client.post(
            "/auth/register",
            json={"email": existing_user.email, "password": "valid-password"},
        )
        duplicate_elapsed = time.perf_counter() - started_at

        started_at = time.perf_counter()
        invalid_password_response = await test_client.post(
            "/auth/register",
            json={"email": "timing-weak@example.com", "password": "short"},
        )
        invalid_password_elapsed = time.perf_counter() - started_at

        with monkeypatch.context() as patch_context:
            patch_context.setattr(
                user_manager,
                "create",
                AsyncMock(side_effect=AuthorizationError("Custom registration policy rejected the request.")),
            )
            started_at = time.perf_counter()
            authorization_response = await test_client.post(
                "/auth/register",
                json={"email": "timing-authorization@example.com", "password": "valid-password"},
            )
            authorization_elapsed = time.perf_counter() - started_at

        started_at = time.perf_counter()
        success_response = await test_client.post(
            "/auth/register",
            json={"email": "timing-success@example.com", "password": "valid-password"},
        )
        success_elapsed = time.perf_counter() - started_at

    assert duplicate_response.status_code == HTTP_BAD_REQUEST
    assert invalid_password_response.status_code == HTTP_BAD_REQUEST
    assert authorization_response.status_code == HTTP_BAD_REQUEST
    assert success_response.status_code == HTTP_CREATED
    for elapsed in (duplicate_elapsed, invalid_password_elapsed, authorization_elapsed, success_elapsed):
        assert elapsed >= minimum_seconds - tolerance_seconds


async def test_register_minimum_response_does_not_double_delay_after_slow_business_logic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Naturally slow registration work is not padded again after exceeding the configured minimum."""
    sleep = AsyncMock(wraps=asyncio.sleep)
    monkeypatch.setattr("litestar_auth.controllers.register.asyncio.sleep", sleep)

    class SlowTrackingUserManager(TrackingUserManager):
        """Tracking manager whose create path naturally exceeds the timing envelope."""

        async def create(
            self,
            user_create: msgspec.Struct | Mapping[str, Any],
            *,
            safe: bool = True,
            allow_privileged: bool = False,
        ) -> ExampleUser:
            await asyncio.sleep(0.03)
            return await super().create(user_create, safe=safe, allow_privileged=allow_privileged)

    password_helper = PasswordHelper()
    user_manager = SlowTrackingUserManager(InMemoryUserDatabase(), password_helper)
    controller = create_register_controller(register_minimum_response_seconds=0.01)
    app = litestar_app_with_user_manager(user_manager, controller)

    async with AsyncTestClient(app=app) as test_client:
        response = await test_client.post(
            "/auth/register",
            json={"email": "slow-success@example.com", "password": "plain-password"},
        )

    assert response.status_code == HTTP_CREATED
    assert sleep.await_count == 1


async def test_register_rejects_malformed_json_with_controller_error_contract() -> None:
    """Register keeps the controller 400 malformed-body error contract."""
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
    controller = create_register_controller(
        user_create_schema=PrivilegedRegistrationCreate,
        register_minimum_response_seconds=0,
    )
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
    controller = create_register_controller(
        user_create_schema=ExtendedRegistrationCreate,
        register_minimum_response_seconds=0,
    )
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
