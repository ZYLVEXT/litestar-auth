"""Integration tests for configurable msgspec DTO schemas."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.middleware import DefineMiddleware

from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from litestar_auth.controllers import create_register_controller, create_users_controller
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import UserEmailField, UserPasswordField  # noqa: TC001
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
)

if TYPE_CHECKING:
    from litestar import Litestar
    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.integration
HTTP_CREATED = 201
HTTP_OK = 200
HTTP_UNPROCESSABLE_ENTITY = 422
VERIFICATION_TOKEN_SECRET = "verify-secret-1234567890-1234567890"
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
EMAIL_MAX_LENGTH = 320


class ExtendedUserCreate(msgspec.Struct):
    """Custom registration payload with an extra profile field."""

    email: UserEmailField
    password: UserPasswordField
    bio: str


class ExtendedUserRead(msgspec.Struct):
    """Custom public user payload with an extra profile field."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: list[str]
    bio: str


class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True):
    """Custom partial-update payload with an extra profile field."""

    email: UserEmailField | None = None
    password: UserPasswordField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
    roles: list[str] | None = None
    bio: str | None = None


class UsersControllerManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager exposing paginated user listings for the controller."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion with total count metadata."""
        return await self.user_db.list_users(offset=offset, limit=limit)


def build_app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    UsersControllerManager,
    InMemoryTokenStrategy,
    ExampleUser,
]:
    """Create an application with custom register and users schemas.

    Returns:
        Application, backing database, manager, strategy, and seeded admin user.
    """
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        bio="admin-bio",
        is_superuser=True,
        roles=["admin"],
    )
    user_db = InMemoryUserDatabase([admin_user])
    user_manager = UsersControllerManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_TOKEN_SECRET,
            reset_password_token_secret="reset-secret-1234567890-1234567890",
        ),
    )
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    register_controller = create_register_controller(
        user_create_schema=ExtendedUserCreate,
        user_read_schema=ExtendedUserRead,
    )
    users_controller = create_users_controller(
        id_parser=UUID,
        user_read_schema=ExtendedUserRead,
        user_update_schema=ExtendedUserUpdate,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        register_controller,
        users_controller,
        middleware=[middleware],
    )
    return app, user_db, user_manager, strategy, admin_user


@pytest.fixture
def app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    UsersControllerManager,
    InMemoryTokenStrategy,
    ExampleUser,
]:
    """Create the shared DTO-extensibility app and collaborators.

    Returns:
        App plus the seeded collaborators used by DTO-extensibility tests.
    """
    return build_app()


def test_custom_msgspec_schemas_publish_request_bodies_in_openapi(
    app: tuple[
        Litestar,
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
    ],
) -> None:
    """Configured custom request schemas remain the published OpenAPI request bodies."""
    litestar_app, *_ = app

    register_post = cast("Any", litestar_app.openapi_schema.paths)["/auth/register"].post
    update_me_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/me"].patch
    update_user_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/{user_id}"].patch
    register_request_body = register_post.request_body
    update_me_request_body = update_me_patch.request_body
    update_user_request_body = update_user_patch.request_body
    register_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["ExtendedUserCreate"]
    update_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["ExtendedUserUpdate"]

    assert register_request_body is not None
    assert update_me_request_body is not None
    assert update_user_request_body is not None
    assert register_schema.properties is not None
    assert update_schema.properties is not None
    register_email_schema = register_schema.properties["email"]
    update_email_schema = update_schema.properties["email"]
    update_password_schema = update_schema.properties["password"]
    assert next(iter(register_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserCreate"
    assert next(iter(update_me_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserUpdate"
    assert next(iter(update_user_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserUpdate"
    assert "bio" in (register_schema.properties or {})
    assert "bio" in (update_schema.properties or {})
    assert "roles" in (update_schema.properties or {})
    assert register_email_schema.max_length == EMAIL_MAX_LENGTH
    assert register_email_schema.pattern == EMAIL_PATTERN
    assert register_schema.properties["password"].min_length == DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert register_schema.properties["password"].max_length == MAX_PASSWORD_LENGTH
    assert update_email_schema.one_of is not None
    assert {getattr(candidate.type, "value", candidate.type) for candidate in update_email_schema.one_of} == {
        "string",
        "null",
    }
    assert update_password_schema.one_of is not None
    assert {candidate.type.value for candidate in update_password_schema.one_of} == {"string", "null"}


async def test_custom_msgspec_schemas_extend_register_and_users_responses(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
    ],
) -> None:
    """Custom msgspec schemas still permit richer read/update DTOs after safe registration."""
    test_client, user_db, _, strategy, admin_user = client

    register_response = await test_client.post(
        "/auth/register",
        json={
            "email": "extended@example.com",
            "password": "plain-password",
            "bio": "registered-bio",
        },
    )

    assert register_response.status_code == HTTP_CREATED
    assert register_response.json() == {
        "id": register_response.json()["id"],
        "email": "extended@example.com",
        "is_active": True,
        "is_verified": False,
        "is_superuser": False,
        "roles": [],
        "bio": "",
    }

    created_user = await user_db.get_by_email("extended@example.com")
    assert created_user is not None
    assert not created_user.bio

    token = await strategy.write_token(created_user)
    headers = {"Authorization": f"Bearer {token}"}
    get_me_response = await test_client.get("/users/me", headers=headers)
    patch_me_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"bio": "updated-bio", "is_superuser": True, "roles": [" Support ", "ADMIN"]},
    )

    assert get_me_response.status_code == HTTP_OK
    assert not get_me_response.json()["bio"]
    assert get_me_response.json()["roles"] == []

    assert patch_me_response.status_code == HTTP_OK
    assert patch_me_response.json()["bio"] == "updated-bio"
    assert patch_me_response.json()["is_superuser"] is False
    assert patch_me_response.json()["roles"] == []

    stored_user = await user_db.get(created_user.id)
    assert stored_user is not None
    assert stored_user.bio == "updated-bio"
    assert stored_user.is_superuser is False
    assert stored_user.roles == []

    admin_token = await strategy.write_token(admin_user)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    admin_patch_response = await test_client.patch(
        f"/users/{created_user.id}",
        headers=admin_headers,
        json={"roles": [" Support ", "ADMIN"]},
    )
    assert admin_patch_response.status_code == HTTP_OK
    assert admin_patch_response.json()["roles"] == ["admin", "support"]

    list_response = await test_client.get("/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert list_response.status_code == HTTP_OK
    assert list_response.json()["items"][1]["bio"] == "updated-bio"
    assert list_response.json()["items"][1]["roles"] == ["admin", "support"]


async def test_custom_registration_schema_reuses_builtin_email_and_password_contract(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
    ],
) -> None:
    """Custom registration schemas can reuse the built-in email and password contract."""
    test_client, user_db, *_ = client
    minimum_password = "p" * DEFAULT_MINIMUM_PASSWORD_LENGTH
    maximum_password = "p" * MAX_PASSWORD_LENGTH

    minimum_response = await test_client.post(
        "/auth/register",
        json={"email": "minimum@example.com", "password": minimum_password, "bio": "minimum"},
    )
    maximum_response = await test_client.post(
        "/auth/register",
        json={"email": "maximum@example.com", "password": maximum_password, "bio": "maximum"},
    )
    invalid_email_response = await test_client.post(
        "/auth/register",
        json={"email": "not-an-email", "password": minimum_password, "bio": "invalid-email"},
    )
    short_response = await test_client.post(
        "/auth/register",
        json={
            "email": "short@example.com",
            "password": "p" * (DEFAULT_MINIMUM_PASSWORD_LENGTH - 1),
            "bio": "short",
        },
    )
    long_response = await test_client.post(
        "/auth/register",
        json={"email": "long@example.com", "password": "p" * (MAX_PASSWORD_LENGTH + 1), "bio": "long"},
    )

    assert minimum_response.status_code == HTTP_CREATED
    assert maximum_response.status_code == HTTP_CREATED
    assert invalid_email_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert short_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert long_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert invalid_email_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert short_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert long_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert await user_db.get_by_email("minimum@example.com") is not None
    assert await user_db.get_by_email("maximum@example.com") is not None
    assert await user_db.get_by_email("not-an-email") is None
    assert await user_db.get_by_email("short@example.com") is None
    assert await user_db.get_by_email("long@example.com") is None


async def test_custom_update_schema_reuses_builtin_email_and_password_contract(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        UsersControllerManager,
        InMemoryTokenStrategy,
        ExampleUser,
    ],
) -> None:
    """Custom update schemas can reuse the built-in email/password contract."""
    test_client, _, _, strategy, admin_user = client
    token = await strategy.write_token(admin_user)
    headers = {"Authorization": f"Bearer {token}"}
    minimum_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"password": "p" * DEFAULT_MINIMUM_PASSWORD_LENGTH},
    )
    short_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"password": "p" * (DEFAULT_MINIMUM_PASSWORD_LENGTH - 1)},
    )
    invalid_email_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"email": "not-an-email"},
    )
    long_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"password": "p" * (MAX_PASSWORD_LENGTH + 1)},
    )

    assert minimum_response.status_code == HTTP_OK
    assert invalid_email_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert short_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert long_response.status_code == HTTP_UNPROCESSABLE_ENTITY
    assert invalid_email_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert short_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID
    assert long_response.json()["extra"]["code"] == ErrorCode.REQUEST_BODY_INVALID


def test_controllers_reject_non_msgspec_custom_schemas() -> None:
    """Configurable schemas must be msgspec structs."""

    class InvalidSchema:
        pass

    with pytest.raises(TypeError, match=r"user_read_schema must be a msgspec\.Struct subclass\."):
        create_register_controller(
            user_read_schema=cast("Any", InvalidSchema),
        )

    with pytest.raises(TypeError, match=r"user_update_schema must be a msgspec\.Struct subclass\."):
        create_users_controller(
            user_update_schema=cast("Any", InvalidSchema),
        )
