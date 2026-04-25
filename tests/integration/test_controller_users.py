"""Integration tests for the generated users controller."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from litestar import Request, get
from litestar.middleware import DefineMiddleware

from litestar_auth._plugin.dependencies import authorization_error_handler
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_auth_controller, create_users_controller
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.guards import has_all_roles, has_any_role
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RateLimiterBackend,
    RedisClientProtocol,
    RedisRateLimiter,
)
from tests._helpers import auth_middleware_get_request_session, cast_fakeredis, litestar_app_with_user_manager
from tests.integration.conftest import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from httpx import Response
    from litestar import Litestar
    from litestar.openapi.spec import OpenAPIResponse
    from litestar.testing import AsyncTestClient

    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.integration
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_NO_CONTENT = 204
HTTP_TOO_MANY_REQUESTS = 429
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_UNAUTHORIZED = 401


@get("/role-guarded/any", guards=[has_any_role("admin")])
async def role_guarded_any() -> dict[str, bool]:
    """Return success when the request user has any required role."""
    await asyncio.sleep(0)
    return {"ok": True}


@get("/role-guarded/all", guards=[has_all_roles("admin", "billing")])
async def role_guarded_all() -> dict[str, bool]:
    """Return success when the request user has all required roles."""
    await asyncio.sleep(0)
    return {"ok": True}


@get("/role-guarded/runtime", guards=[has_all_roles("admin", "billing")], sync_to_thread=False)
def role_guarded_runtime(request: Request[ExampleUser, Any, Any]) -> dict[str, list[str]]:
    """Return the authenticated user's role membership from the request object."""
    user = request.user
    assert user is not None
    return {"roles": list(user.roles)}


class UsersControllerManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager exposing paginated user listings for the controller."""

    def __init__(
        self,
        user_db: InMemoryUserDatabase,
        *,
        password_helper: PasswordHelper,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize the manager and track hard-delete hooks."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-1234567890-1234567890",
                reset_password_token_secret="reset-secret-1234567890-1234567890",
            ),
            backends=backends,
        )
        self.deleted_users: list[ExampleUser] = []

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion with total count metadata."""
        return await self.user_db.list_users(offset=offset, limit=limit)

    async def on_after_delete(self, user: ExampleUser) -> None:
        """Record permanent deletions."""
        self.deleted_users.append(user)


class InvalidationCapableInMemoryTokenStrategy(InMemoryTokenStrategy):
    """In-memory strategy with refresh tokens and whole-user invalidation."""

    def __init__(self) -> None:
        """Initialize access and refresh token storage."""
        super().__init__()
        self.refresh_tokens: dict[str, UUID] = {}
        self.refresh_counter = 0

    async def write_refresh_token(self, user: ExampleUser) -> str:
        """Persist and return a refresh token.

        Returns:
            The generated refresh token value.
        """
        self.refresh_counter += 1
        token = f"refresh-{self.refresh_counter}"
        self.refresh_tokens[token] = user.id
        return token

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: BaseUserManager[ExampleUser, UUID],
    ) -> tuple[ExampleUser, str] | None:
        """Replace a refresh token with a new one for the same user.

        Returns:
            The resolved user plus a freshly minted refresh token, or ``None`` when rotation fails.
        """
        user_id = self.refresh_tokens.pop(refresh_token, None)
        if user_id is None:
            return None
        user = await user_manager.get(user_id)
        if user is None:
            return None
        return user, await self.write_refresh_token(user)

    async def invalidate_all_tokens(self, user: ExampleUser) -> None:
        """Remove all access and refresh tokens belonging to the user."""
        self.tokens = {token: user_id for token, user_id in self.tokens.items() if user_id != user.id}
        self.refresh_tokens = {token: user_id for token, user_id in self.refresh_tokens.items() if user_id != user.id}


def build_app(
    *,
    hard_delete: bool = False,
    rate_limit_config: AuthRateLimitConfig | None = None,
) -> tuple[
    Litestar,
    InMemoryUserDatabase,
    UsersControllerManager,
    InMemoryTokenStrategy,
    ExampleUser,
    ExampleUser,
]:
    """Create an application wired with the generated users controller.

    Returns:
        Application, backing database, manager, strategy, admin user, and regular user.
    """
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_verified=True,
        roles=["admin", "superuser"],
    )
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        totp_secret="sensitive-secret",
        is_verified=True,
        roles=["member"],
    )
    extra_user = ExampleUser(
        id=uuid4(),
        email="extra@example.com",
        hashed_password=password_helper.hash("extra-password"),
        is_verified=True,
        roles=["support"],
    )
    user_db = InMemoryUserDatabase([admin_user, regular_user, extra_user])
    strategy = InvalidationCapableInMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    user_manager = UsersControllerManager(user_db, password_helper=password_helper, backends=(backend,))
    auth_controller = create_auth_controller(
        backend=backend,
        enable_refresh=True,
    )
    controller = create_users_controller(
        id_parser=UUID,
        rate_limit_config=rate_limit_config,
        hard_delete=hard_delete,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    route_handlers = [
        auth_controller,
        controller,
        role_guarded_any,
        role_guarded_all,
        role_guarded_runtime,
    ]
    for route_handler in route_handlers:
        route_handler_dict = getattr(route_handler, "__dict__", {})
        existing_handlers = dict(route_handler_dict.get("exception_handlers") or {})
        existing_handlers.setdefault(AuthorizationError, cast("Any", authorization_error_handler))
        cast("Any", route_handler).exception_handlers = existing_handlers
    app = litestar_app_with_user_manager(
        user_manager,
        *route_handlers,
        middleware=[middleware],
    )
    return app, user_db, user_manager, strategy, admin_user, regular_user


def _change_password_rate_limit_config(backend: RateLimiterBackend) -> AuthRateLimitConfig:
    """Return a users-controller rate limiter for password rotation tests."""
    return AuthRateLimitConfig(
        change_password=EndpointRateLimit(
            backend=backend,
            scope="ip_email",
            namespace="change-password",
        ),
    )


def _assert_rate_limited(response: Response) -> None:
    """Assert the standard rate-limit response contract."""
    assert response.status_code == HTTP_TOO_MANY_REQUESTS
    assert response.headers["Retry-After"].isdigit()
    assert int(response.headers["Retry-After"]) >= 1


def _openapi_example_values(response: OpenAPIResponse) -> list[dict[str, object]]:
    """Return OpenAPI response example values as plain dictionaries."""
    content = response.content or {}
    media_type = next(iter(content.values()))
    examples = media_type.examples or {}
    return [cast("dict[str, object]", example.value) for example in examples.values()]


@pytest.fixture
def app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    UsersControllerManager,
    InMemoryTokenStrategy,
    ExampleUser,
    ExampleUser,
]:
    """Create the shared users-controller app and collaborators.

    Returns:
        App plus the seeded collaborators used by users-controller tests.
    """
    return build_app()


@pytest.fixture
def hard_delete_app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    UsersControllerManager,
    InMemoryTokenStrategy,
    ExampleUser,
    ExampleUser,
]:
    """Create the shared users-controller app with hard-delete enabled.

    Returns:
        App plus the seeded collaborators used by hard-delete tests.
    """
    return build_app(hard_delete=True)


def test_users_mutation_routes_publish_request_body_and_response_contracts_in_openapi(
    app: tuple[Litestar, InMemoryUserDatabase, UsersControllerManager, InMemoryTokenStrategy, ExampleUser, ExampleUser],
) -> None:
    """Users-controller mutation routes publish expected request and response contracts in OpenAPI."""
    litestar_app, *_ = app

    update_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["UserUpdate"]
    admin_update_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["AdminUserUpdate"]
    change_password_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["ChangePasswordRequest"]
    me_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/me"].patch
    change_password_post = cast("Any", litestar_app.openapi_schema.paths)["/users/me/change-password"].post
    admin_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/{user_id}"].patch
    me_request_body = me_patch.request_body
    change_password_request_body = change_password_post.request_body
    admin_request_body = admin_patch.request_body

    assert me_request_body is not None
    assert change_password_request_body is not None
    assert admin_request_body is not None
    assert next(iter(me_request_body.content.values())).schema.ref == "#/components/schemas/UserUpdate"
    assert (
        next(iter(change_password_request_body.content.values())).schema.ref
        == "#/components/schemas/ChangePasswordRequest"
    )
    assert next(iter(admin_request_body.content.values())).schema.ref == "#/components/schemas/AdminUserUpdate"
    assert "email" in (update_schema.properties or {})
    assert "roles" in (update_schema.properties or {})
    assert "password" not in (update_schema.properties or {})
    assert set(change_password_schema.required or []) == {"current_password", "new_password"}
    assert "email" in (admin_update_schema.properties or {})
    assert "password" in (admin_update_schema.properties or {})
    assert "roles" in (admin_update_schema.properties or {})

    responses = change_password_post.responses
    assert {"204", "400", "401", "422", "429"}.issubset(responses)
    assert ErrorCode.LOGIN_BAD_CREDENTIALS.value in responses["400"].description
    assert ErrorCode.UPDATE_USER_INVALID_PASSWORD.value in responses["400"].description
    assert ErrorCode.REQUEST_BODY_INVALID.value in responses["422"].description
    assert responses["204"].content is None
    assert "Retry-After" in responses["429"].description

    bad_request_examples = _openapi_example_values(responses["400"])
    unprocessable_examples = _openapi_example_values(responses["422"])
    assert {cast("dict[str, str]", example["extra"])["code"] for example in bad_request_examples} == {
        ErrorCode.LOGIN_BAD_CREDENTIALS.value,
        ErrorCode.UPDATE_USER_INVALID_PASSWORD.value,
    }
    assert cast("dict[str, str]", unprocessable_examples[0]["extra"])["code"] == ErrorCode.REQUEST_BODY_INVALID.value


async def test_me_endpoints_return_public_payload_and_allow_non_privileged_updates(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Authenticated users can read and patch their own public profile safely."""
    test_client, user_db, _, strategy, _, regular_user = client
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}
    original_email = regular_user.email

    get_response = await test_client.get("/users/me", headers=headers)
    patch_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "updated-user@example.com"},
    )

    assert get_response.status_code == HTTP_OK
    assert get_response.json() == {
        "id": str(regular_user.id),
        "email": original_email,
        "is_active": True,
        "is_verified": True,
        "roles": ["member"],
    }
    assert "hashed_password" not in get_response.json()
    assert "totp_secret" not in get_response.json()

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json() == {
        "id": str(regular_user.id),
        "email": "updated-user@example.com",
        "is_active": True,
        "is_verified": False,
        "roles": ["member"],
    }
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.email == "updated-user@example.com"
    assert stored_user.is_verified is False
    assert stored_user.roles == ["member"]
    assert PasswordHelper().verify("user-password", stored_user.hashed_password) is True


async def test_change_password_rejects_wrong_current_password_and_preserves_hash(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Wrong current-password submissions reuse the login bad-credentials contract."""
    test_client, user_db, _, strategy, _, regular_user = client
    original_hash = regular_user.hashed_password
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.post(
        "/users/me/change-password",
        headers=headers,
        json={"current_password": "wrong-password", "new_password": "rotated-password"},
    )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == INVALID_CREDENTIALS_DETAIL
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_BAD_CREDENTIALS
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.hashed_password == original_hash
    assert PasswordHelper().verify("user-password", stored_user.hashed_password) is True


async def test_patch_me_rejects_password_and_preserves_hash(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """PATCH /users/me rejects password changes and leaves the stored hash untouched."""
    test_client, user_db, _, strategy, _, regular_user = client
    original_hash = regular_user.hashed_password
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"password": "new-password"},
    )

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "Self-service updates cannot set the following fields: password."
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.hashed_password == original_hash
    assert PasswordHelper().verify("user-password", stored_user.hashed_password) is True


async def test_change_password_succeeds_and_revokes_prior_sessions(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """POST /users/me/change-password rotates credentials and revokes old session artifacts."""
    test_client, user_db, _, _, _, regular_user = client
    login_response = await test_client.post(
        "/auth/login",
        json={"identifier": regular_user.email, "password": "user-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    login_payload = login_response.json()
    access_token = cast("str", login_payload["access_token"])
    refresh_token = cast("str", login_payload["refresh_token"])
    headers = {"Authorization": f"Bearer {access_token}"}

    response = await test_client.post(
        "/users/me/change-password",
        headers=headers,
        json={"current_password": "user-password", "new_password": "rotated-password"},
    )
    old_access_response = await test_client.get("/users/me", headers=headers)
    old_refresh_response = await test_client.post("/auth/refresh", json={"refresh_token": refresh_token})
    new_login_response = await test_client.post(
        "/auth/login",
        json={"identifier": regular_user.email, "password": "rotated-password"},
    )

    assert response.status_code == HTTP_NO_CONTENT
    assert not response.content
    assert old_access_response.status_code == HTTP_UNAUTHORIZED
    assert old_refresh_response.status_code == HTTP_BAD_REQUEST
    assert old_refresh_response.json()["detail"] == "The refresh token is invalid."
    assert (old_refresh_response.json().get("extra") or {}).get("code") == ErrorCode.REFRESH_TOKEN_INVALID
    assert new_login_response.status_code == HTTP_CREATED
    assert isinstance(new_login_response.json()["access_token"], str)
    assert isinstance(new_login_response.json()["refresh_token"], str)
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert PasswordHelper().verify("rotated-password", stored_user.hashed_password) is True
    assert PasswordHelper().verify("user-password", stored_user.hashed_password) is False


async def test_change_password_rate_limit_returns_429_after_invalid_current_password_attempts(
    async_test_client_factory: Callable[[Any], Any],
) -> None:
    """Repeated wrong current-password submissions exhaust the change-password slot."""
    rate_limit_config = _change_password_rate_limit_config(
        InMemoryRateLimiter(max_attempts=2, window_seconds=60),
    )
    app_value = build_app(rate_limit_config=rate_limit_config)

    async with async_test_client_factory(app_value) as client:
        test_client, _user_db, _, strategy, _, regular_user = client
        headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}

        first_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )
        second_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )
        blocked_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    _assert_rate_limited(blocked_response)


async def test_change_password_rate_limit_resets_after_success(
    async_test_client_factory: Callable[[Any], Any],
) -> None:
    """A successful password change clears failed attempts like the login flow does."""
    rate_limit_config = _change_password_rate_limit_config(
        InMemoryRateLimiter(max_attempts=2, window_seconds=60),
    )
    app_value = build_app(rate_limit_config=rate_limit_config)

    async with async_test_client_factory(app_value) as client:
        test_client, _user_db, _, strategy, _, regular_user = client
        headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}

        first_failure = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )
        success = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "user-password", "new_password": "rotated-password"},
        )
        rotated_headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}
        post_reset_first_failure = await test_client.post(
            "/users/me/change-password",
            headers=rotated_headers,
            json={"current_password": "wrong-password", "new_password": "second-rotated-password"},
        )
        post_reset_second_failure = await test_client.post(
            "/users/me/change-password",
            headers=rotated_headers,
            json={"current_password": "wrong-password", "new_password": "second-rotated-password"},
        )
        blocked_response = await test_client.post(
            "/users/me/change-password",
            headers=rotated_headers,
            json={"current_password": "wrong-password", "new_password": "second-rotated-password"},
        )

    assert first_failure.status_code == HTTP_BAD_REQUEST
    assert success.status_code == HTTP_NO_CONTENT
    assert post_reset_first_failure.status_code == HTTP_BAD_REQUEST
    assert post_reset_second_failure.status_code == HTTP_BAD_REQUEST
    _assert_rate_limited(blocked_response)


async def test_change_password_redis_rate_limit_returns_429_after_invalid_current_password_attempts(
    async_test_client_factory: Callable[[Any], Any],
    async_fakeredis: AsyncFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redis-backed password-rotation throttling uses the shared Lua sliding-window backend."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._helpers._load_redis_asyncio", load_optional_redis)
    redis_backend = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=60,
    )
    app_value = build_app(rate_limit_config=_change_password_rate_limit_config(redis_backend))

    async with async_test_client_factory(app_value) as client:
        test_client, _user_db, _, strategy, _, regular_user = client
        headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}

        first_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )
        second_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )
        blocked_response = await test_client.post(
            "/users/me/change-password",
            headers=headers,
            json={"current_password": "wrong-password", "new_password": "rotated-password"},
        )

    assert first_response.status_code == HTTP_BAD_REQUEST
    assert second_response.status_code == HTTP_BAD_REQUEST
    _assert_rate_limited(blocked_response)


@pytest.mark.parametrize(
    ("payload", "field_name"),
    [
        ({"hashed_password": "forbidden"}, "hashed_password"),
        ({"is_active": False}, "is_active"),
        ({"is_verified": False}, "is_verified"),
        ({"roles": ["admin"]}, "roles"),
    ],
)
async def test_me_endpoints_reject_blocked_self_update_fields(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    payload: dict[str, object],
    field_name: str,
) -> None:
    """Blocked self-update fields fail closed with the controller error contract."""
    test_client, user_db, _, strategy, _, regular_user = client
    original_hash = regular_user.hashed_password
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.patch("/users/me", headers=headers, json=payload)

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == f"Self-service updates cannot set the following fields: {field_name}."
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.email == regular_user.email
    assert stored_user.is_active is True
    assert stored_user.is_verified is True
    assert stored_user.roles == ["member"]
    assert stored_user.hashed_password == original_hash


async def test_me_endpoints_reject_unknown_fields_from_builtin_schema(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Built-in self-update schema rejects undeclared fields during request decoding."""
    test_client, user_db, _, strategy, _, regular_user = client
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "ignored@example.com", "deprecated_admin_flag": True},
    )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.email == regular_user.email


async def test_me_endpoints_require_authenticated_user(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Self-service endpoints reject unauthenticated requests with the auth middleware contract."""
    test_client, *_ = client

    get_response = await test_client.get("/users/me")
    patch_response = await test_client.patch("/users/me", json={"email": "ignored@example.com"})
    change_password_response = await test_client.post(
        "/users/me/change-password",
        json={"current_password": "user-password", "new_password": "rotated-password"},
    )

    assert get_response.status_code == HTTP_UNAUTHORIZED
    assert get_response.json()["detail"] == "Authentication credentials were not provided."
    assert patch_response.status_code == HTTP_UNAUTHORIZED
    assert patch_response.json()["detail"] == "Authentication credentials were not provided."
    assert change_password_response.status_code == HTTP_UNAUTHORIZED
    assert change_password_response.json()["detail"] == "Authentication credentials were not provided."


async def test_me_endpoints_reject_inactive_users(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Inactive users cannot access self-service profile or password-rotation endpoints."""
    test_client, user_db, _, strategy, _, regular_user = client
    regular_user.is_active = False
    await user_db.update(regular_user, {"is_active": False})
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    get_response = await test_client.get("/users/me", headers=headers)
    patch_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "ignored@example.com"},
    )
    change_password_response = await test_client.post(
        "/users/me/change-password",
        headers=headers,
        json={"current_password": "user-password", "new_password": "rotated-password"},
    )

    assert get_response.status_code == HTTP_BAD_REQUEST
    assert get_response.json()["detail"] == "The user account is inactive."
    assert (get_response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_USER_INACTIVE
    assert patch_response.status_code == HTTP_BAD_REQUEST
    assert patch_response.json()["detail"] == "The user account is inactive."
    assert (patch_response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_USER_INACTIVE
    assert change_password_response.status_code == HTTP_BAD_REQUEST
    assert change_password_response.json()["detail"] == "The user account is inactive."
    assert (change_password_response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_USER_INACTIVE


async def test_update_me_maps_user_manager_errors(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATCH /me maps manager exceptions into ErrorCode responses."""
    test_client, _, user_manager, strategy, _, regular_user = client
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    exists_message = "Email already exists."
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=UserAlreadyExistsError(message=exists_message)))
    exists_response = await test_client.patch("/users/me", headers=headers, json={"email": "dup@example.com"})
    assert exists_response.status_code == HTTP_BAD_REQUEST
    assert (exists_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS

    authorization_message = "Custom policy rejected this self-update."
    monkeypatch.setattr(
        user_manager,
        "update",
        AsyncMock(side_effect=AuthorizationError(authorization_message)),
    )
    authorization_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "blocked@example.com"},
    )
    assert authorization_response.status_code == HTTP_BAD_REQUEST
    assert (authorization_response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID


async def test_update_me_rejects_schema_validation_errors(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """PATCH /me returns 422 for invalid self-update payloads."""
    test_client, _, _, strategy, _, regular_user = client
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "not-an-email"},
    )

    assert response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert response.json()["detail"] == "Invalid request payload."
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID


@pytest.mark.parametrize("route_path", ["/users/me", "/users/{user_id}"])
async def test_users_patch_routes_reject_malformed_json_with_controller_error_contract(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    route_path: str,
) -> None:
    """Both patch routes preserve the controller 400 malformed-body error contract."""
    test_client, _, _, strategy, admin_user, regular_user = client
    target_user = regular_user if route_path == "/users/me" else admin_user
    request_path = route_path.format(user_id=regular_user.id)
    token = await strategy.write_token(target_user)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    response = await test_client.patch(request_path, headers=headers, content="not-json")

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json()["detail"] == "Invalid request body."
    assert (response.json().get("extra") or {}).get("code") == ErrorCode.REQUEST_BODY_INVALID


async def test_update_user_maps_user_manager_errors(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATCH /users/{id} maps manager exceptions into ErrorCode responses."""
    test_client, _, user_manager, strategy, admin_user, regular_user = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    exists_message = "Email already exists."
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=UserAlreadyExistsError(message=exists_message)))
    exists_response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=headers,
        json={"email": "dup@example.com"},
    )
    assert exists_response.status_code == HTTP_BAD_REQUEST
    assert (exists_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS

    invalid_password_message = "Invalid password."
    monkeypatch.setattr(
        user_manager,
        "update",
        AsyncMock(side_effect=InvalidPasswordError(message=invalid_password_message)),
    )
    password_response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=headers,
        json={"password": "invalid-password"},
    )
    assert password_response.status_code == HTTP_BAD_REQUEST
    assert (password_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_INVALID_PASSWORD


async def test_admin_user_lookup_returns_404_for_unparseable_ids(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Admin get/delete routes return 404 for identifiers that cannot be parsed."""
    test_client, _, _, strategy, admin_user, _ = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    get_response = await test_client.get("/users/not-a-uuid", headers=headers)
    delete_response = await test_client.delete("/users/not-a-uuid", headers=headers)

    assert get_response.status_code == HTTP_NOT_FOUND
    assert get_response.json()["detail"] == "User not found."
    assert delete_response.status_code == HTTP_NOT_FOUND
    assert delete_response.json()["detail"] == "User not found."


async def test_get_user_not_found_returns_404(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /users/{id} returns 404 when the manager has no matching user."""
    test_client, _, user_manager, strategy, admin_user, _ = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    def _missing_user(user_id: UUID) -> ExampleUser | None:
        return admin_user if user_id == admin_user.id else None

    monkeypatch.setattr(user_manager, "get", AsyncMock(side_effect=_missing_user))
    response = await test_client.get(f"/users/{uuid4()}", headers=headers)
    assert response.status_code == HTTP_NOT_FOUND
    assert response.json()["detail"] == "User not found."


async def test_soft_delete_calls_update_and_skips_hard_delete(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Soft delete uses update(is_active=False) and never calls delete()."""
    test_client, _, user_manager, strategy, admin_user, regular_user = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    update_spy: AsyncMock = AsyncMock(wraps=user_manager.update)
    delete_spy: AsyncMock = AsyncMock(wraps=user_manager.delete)
    monkeypatch.setattr(user_manager, "update", update_spy)
    monkeypatch.setattr(user_manager, "delete", delete_spy)

    response = await test_client.delete(f"/users/{regular_user.id}", headers=headers)
    assert response.status_code == HTTP_OK
    assert update_spy.await_count == 1
    call = update_spy.await_args_list[0]
    assert getattr(call.args[0], "is_active", None) is False
    assert delete_spy.await_count == 0


async def test_admin_endpoints_require_superuser(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Non-superusers receive 403 responses for admin-only routes."""
    test_client, _, _, strategy, admin_user, regular_user = client
    token = await strategy.write_token(regular_user)
    headers = {"Authorization": f"Bearer {token}"}

    get_response = await test_client.get(f"/users/{admin_user.id}", headers=headers)
    list_response = await test_client.get("/users", headers=headers)
    delete_response = await test_client.delete(f"/users/{admin_user.id}", headers=headers)

    assert get_response.status_code == HTTP_FORBIDDEN
    assert list_response.status_code == HTTP_FORBIDDEN
    assert delete_response.status_code == HTTP_FORBIDDEN


async def test_role_guard_factories_enforce_normalized_membership_at_runtime(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Runtime requests honor any-role and all-role guards using normalized membership."""
    test_client, user_db, _, strategy, admin_user, regular_user = client
    await user_db.update(admin_user, {"roles": [" Billing ", "ADMIN"]})
    await user_db.update(regular_user, {"roles": ["support"]})
    admin_headers = {"Authorization": f"Bearer {await strategy.write_token(admin_user)}"}
    member_headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}

    any_admin_response = await test_client.get("/role-guarded/any", headers=admin_headers)
    all_admin_response = await test_client.get("/role-guarded/all", headers=admin_headers)
    any_member_response = await test_client.get("/role-guarded/any", headers=member_headers)
    all_member_response = await test_client.get("/role-guarded/all", headers=member_headers)

    assert any_admin_response.status_code == HTTP_OK
    assert any_admin_response.json() == {"ok": True}
    assert all_admin_response.status_code == HTTP_OK
    assert all_admin_response.json() == {"ok": True}
    assert any_member_response.status_code == HTTP_FORBIDDEN
    assert all_member_response.status_code == HTTP_FORBIDDEN


async def test_admin_role_updates_feed_request_user_role_contract_at_runtime(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Admin role updates are visible as normalized ``list[str]`` membership on ``request.user``."""
    test_client, user_db, _, strategy, admin_user, regular_user = client
    admin_headers = {"Authorization": f"Bearer {await strategy.write_token(admin_user)}"}

    patch_response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=admin_headers,
        json={"roles": [" Billing ", "ADMIN"]},
    )
    member_headers = {"Authorization": f"Bearer {await strategy.write_token(regular_user)}"}
    runtime_response = await test_client.get("/role-guarded/runtime", headers=member_headers)

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json()["roles"] == ["admin", "billing"]
    assert runtime_response.status_code == HTTP_OK
    assert runtime_response.json() == {"roles": ["admin", "billing"]}
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.roles == ["admin", "billing"]


async def test_superuser_update_accepts_admin_user_update_fields_including_password(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Admin PATCH keeps accepting the full privileged update surface, including password rotation."""
    test_client, user_db, _, strategy, admin_user, regular_user = client
    headers = {"Authorization": f"Bearer {await strategy.write_token(admin_user)}"}

    response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=headers,
        json={
            "email": "admin-rotated@example.com",
            "password": "rotated-admin-password",
            "is_active": False,
            "is_verified": False,
            "roles": [" Billing ", "ADMIN"],
        },
    )

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "id": str(regular_user.id),
        "email": "admin-rotated@example.com",
        "is_active": False,
        "is_verified": False,
        "roles": ["admin", "billing"],
    }
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.email == "admin-rotated@example.com"
    assert stored_user.is_active is False
    assert stored_user.is_verified is False
    assert stored_user.roles == ["admin", "billing"]
    assert PasswordHelper().verify("rotated-admin-password", stored_user.hashed_password) is True


async def test_superuser_can_read_update_and_soft_delete_users(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Superusers can manage other users and deletes are soft."""
    test_client, user_db, user_manager, strategy, admin_user, regular_user = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    get_response = await test_client.get(f"/users/{regular_user.id}", headers=headers)
    patch_response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=headers,
        json={"is_verified": False, "roles": [" Billing ", "admin", "ADMIN"]},
    )
    delete_response = await test_client.delete(f"/users/{regular_user.id}", headers=headers)

    assert get_response.status_code == HTTP_OK
    assert get_response.json()["email"] == regular_user.email
    assert "hashed_password" not in get_response.json()
    assert "totp_secret" not in get_response.json()

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json()["is_verified"] is False
    assert patch_response.json()["roles"] == ["admin", "billing"]

    assert delete_response.status_code == HTTP_OK
    assert delete_response.json()["is_active"] is False
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.is_active is False
    assert stored_user.roles == ["admin", "billing"]
    assert user_manager.deleted_users == []


async def test_superuser_cannot_delete_their_own_account(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Superusers receive a 403 response when attempting to delete themselves."""
    test_client, user_db, user_manager, strategy, admin_user, _ = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.delete(f"/users/{admin_user.id}", headers=headers)

    assert response.status_code == HTTP_FORBIDDEN
    data = response.json()
    assert data["detail"] == "Superusers cannot delete their own account."
    assert (data.get("extra") or {}).get("code") == "SUPERUSER_CANNOT_DELETE_SELF"
    stored_user = await user_db.get(admin_user.id)
    assert stored_user is admin_user
    assert stored_user.is_active is True
    assert user_manager.deleted_users == []


async def test_superuser_can_hard_delete_users(
    hard_delete_client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Superusers can permanently delete users when configured."""
    test_client, user_db, user_manager, strategy, admin_user, regular_user = hard_delete_client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    delete_response = await test_client.delete(f"/users/{regular_user.id}", headers=headers)

    assert delete_response.status_code == HTTP_OK
    assert delete_response.json() == {
        "id": str(regular_user.id),
        "email": regular_user.email,
        "is_active": True,
        "is_verified": True,
        "roles": ["member"],
    }
    assert await user_db.get(regular_user.id) is None
    assert regular_user.email not in user_db.user_ids_by_email
    assert user_manager.deleted_users == [regular_user]


async def test_users_list_returns_paginated_public_payload(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
        ExampleUser,
    ],
) -> None:
    """Superusers receive paginated public user listings."""
    test_client, _, _, strategy, admin_user, regular_user = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}

    response = await test_client.get("/users?limit=1&offset=1", headers=headers)

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "items": [
            {
                "id": str(regular_user.id),
                "email": regular_user.email,
                "is_active": True,
                "is_verified": True,
                "roles": ["member"],
            },
        ],
        "total": 3,
        "limit": 1,
        "offset": 1,
    }
