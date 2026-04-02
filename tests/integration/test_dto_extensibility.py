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
from litestar_auth.controllers import create_register_controller, create_users_controller
from litestar_auth.manager import BaseUserManager
from litestar_auth.password import PasswordHelper
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
VERIFICATION_TOKEN_SECRET = "verify-secret-1234567890-1234567890"


class ExtendedUserCreate(msgspec.Struct):
    """Custom registration payload with an extra profile field."""

    email: str
    password: str
    bio: str


class ExtendedUserRead(msgspec.Struct):
    """Custom public user payload with an extra profile field."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    bio: str


class ExtendedUserUpdate(msgspec.Struct, omit_defaults=True):
    """Custom partial-update payload with an extra profile field."""

    email: str | None = None
    password: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
    bio: str | None = None


class UsersControllerManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager exposing paginated user listings for the controller."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion with total count metadata."""
        user_db = cast("InMemoryUserDatabase", self.user_db)
        all_users = list(user_db.users_by_id.values())
        return all_users[offset : offset + limit], len(all_users)


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
    )
    user_db = InMemoryUserDatabase([admin_user])
    user_manager = UsersControllerManager(
        user_db,
        password_helper=password_helper,
        verification_token_secret=VERIFICATION_TOKEN_SECRET,
        reset_password_token_secret="reset-secret-1234567890-1234567890",
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
    assert next(iter(register_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserCreate"
    assert next(iter(update_me_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserUpdate"
    assert next(iter(update_user_request_body.content.values())).schema.ref == "#/components/schemas/ExtendedUserUpdate"
    assert "bio" in (register_schema.properties or {})
    assert "bio" in (update_schema.properties or {})


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
        json={"bio": "updated-bio", "is_superuser": True},
    )

    assert get_me_response.status_code == HTTP_OK
    assert not get_me_response.json()["bio"]

    assert patch_me_response.status_code == HTTP_OK
    assert patch_me_response.json()["bio"] == "updated-bio"
    assert patch_me_response.json()["is_superuser"] is False

    stored_user = await user_db.get(created_user.id)
    assert stored_user is not None
    assert stored_user.bio == "updated-bio"
    assert stored_user.is_superuser is False

    admin_token = await strategy.write_token(admin_user)
    list_response = await test_client.get("/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert list_response.status_code == HTTP_OK
    assert list_response.json()["items"][1]["bio"] == "updated-bio"


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
