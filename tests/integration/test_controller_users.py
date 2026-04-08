"""Integration tests for the generated users controller."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from litestar.exceptions import NotAuthorizedException
from litestar.middleware import DefineMiddleware

from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_users_controller
from litestar_auth.exceptions import ErrorCode, InvalidPasswordError, UserAlreadyExistsError
from litestar_auth.manager import BaseUserManager
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import UserUpdate
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
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_UNAUTHORIZED = 401


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
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            backends=backends,
        )
        self.deleted_users: list[ExampleUser] = []

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion with total count metadata."""
        return await self.user_db.list_users(offset=offset, limit=limit)

    async def on_after_delete(self, user: ExampleUser) -> None:
        """Record permanent deletions."""
        self.deleted_users.append(user)


def build_app(
    *,
    hard_delete: bool = False,
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
        is_superuser=True,
        is_verified=True,
    )
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        totp_secret="sensitive-secret",
        is_verified=True,
    )
    extra_user = ExampleUser(
        id=uuid4(),
        email="extra@example.com",
        hashed_password=password_helper.hash("extra-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([admin_user, regular_user, extra_user])
    user_manager = UsersControllerManager(user_db, password_helper=password_helper)
    strategy = InMemoryTokenStrategy()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    controller = create_users_controller(
        id_parser=UUID,
        hard_delete=hard_delete,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(user_manager, controller, middleware=[middleware])
    return app, user_db, user_manager, strategy, admin_user, regular_user


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


def test_users_patch_routes_publish_request_body_in_openapi(
    app: tuple[Litestar, InMemoryUserDatabase, UsersControllerManager, InMemoryTokenStrategy, ExampleUser, ExampleUser],
) -> None:
    """Both patch routes publish request bodies in the generated OpenAPI schema."""
    litestar_app, *_ = app

    update_schema = cast("Any", litestar_app.openapi_schema.components.schemas)["UserUpdate"]
    me_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/me"].patch
    admin_patch = cast("Any", litestar_app.openapi_schema.paths)["/users/{user_id}"].patch
    me_request_body = me_patch.request_body
    admin_request_body = admin_patch.request_body

    assert me_request_body is not None
    assert admin_request_body is not None
    assert next(iter(me_request_body.content.values())).schema.ref == "#/components/schemas/UserUpdate"
    assert next(iter(admin_request_body.content.values())).schema.ref == "#/components/schemas/UserUpdate"
    assert "email" in (update_schema.properties or {})
    assert "password" in (update_schema.properties or {})


async def test_me_endpoints_return_public_payload_and_ignore_restricted_self_updates(
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
        json={
            "email": "updated-user@example.com",
            "password": "new-password",
            "is_superuser": True,
            "is_verified": False,
        },
    )

    assert get_response.status_code == HTTP_OK
    assert get_response.json() == {
        "id": str(regular_user.id),
        "email": original_email,
        "is_active": True,
        "is_verified": True,
        "is_superuser": False,
    }
    assert "hashed_password" not in get_response.json()
    assert "totp_secret" not in get_response.json()

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json() == {
        "id": str(regular_user.id),
        "email": "updated-user@example.com",
        "is_active": True,
        "is_verified": False,
        "is_superuser": False,
    }
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.email == "updated-user@example.com"
    assert stored_user.is_superuser is False
    assert stored_user.is_verified is False
    assert PasswordHelper().verify("new-password", stored_user.hashed_password) is True


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
    """Requests without a user receive 401 responses with a consistent detail payload."""
    test_client, *_ = client

    get_response = await test_client.get("/users/me")
    patch_response = await test_client.patch("/users/me", json={"email": "ignored@example.com"})

    assert get_response.status_code == HTTP_UNAUTHORIZED
    assert get_response.json()["detail"] == "Authentication credentials were not provided."
    assert patch_response.status_code == HTTP_UNAUTHORIZED
    assert patch_response.json()["detail"] == "Authentication credentials were not provided."


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
    """Inactive users cannot access or update self-service profile endpoints."""
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

    assert get_response.status_code == HTTP_BAD_REQUEST
    assert get_response.json()["detail"] == "The user account is inactive."
    assert (get_response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_USER_INACTIVE
    assert patch_response.status_code == HTTP_BAD_REQUEST
    assert patch_response.json()["detail"] == "The user account is inactive."
    assert (patch_response.json().get("extra") or {}).get("code") == ErrorCode.LOGIN_USER_INACTIVE


async def test_controller_me_methods_raise_not_authorized_when_request_user_is_missing(
    app: tuple[Litestar, InMemoryUserDatabase, UsersControllerManager, InMemoryTokenStrategy, ExampleUser, ExampleUser],
) -> None:
    """Directly exercise the redundant in-handler guard branches for coverage."""
    controller_class = create_users_controller(
        id_parser=UUID,
        hard_delete=False,
    )

    class DummyRequest:
        user = None

    um_kw = {DEFAULT_USER_MANAGER_DEPENDENCY_KEY: app[2]}
    get_me_handler = cast("Any", controller_class).get_me
    with pytest.raises(NotAuthorizedException) as excinfo:
        await get_me_handler.fn(object(), DummyRequest(), **um_kw)
    assert str(excinfo.value.detail) == "Authentication credentials were not provided."

    update_me_handler = cast("Any", controller_class).update_me
    with pytest.raises(NotAuthorizedException) as excinfo:
        await update_me_handler.fn(object(), DummyRequest(), UserUpdate(), **um_kw)
    assert str(excinfo.value.detail) == "Authentication credentials were not provided."


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
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=UserAlreadyExistsError(exists_message)))
    exists_response = await test_client.patch("/users/me", headers=headers, json={"email": "dup@example.com"})
    assert exists_response.status_code == HTTP_BAD_REQUEST
    assert (exists_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS

    invalid_password_message = "Invalid password."
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=InvalidPasswordError(invalid_password_message)))
    password_response = await test_client.patch(
        "/users/me",
        headers=headers,
        json={"password": "invalid-password"},
    )
    assert password_response.status_code == HTTP_BAD_REQUEST
    assert (password_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_INVALID_PASSWORD


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
    """Both patch routes preserve the legacy 400 malformed-body payload shape."""
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
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=UserAlreadyExistsError(exists_message)))
    exists_response = await test_client.patch(
        f"/users/{regular_user.id}",
        headers=headers,
        json={"email": "dup@example.com"},
    )
    assert exists_response.status_code == HTTP_BAD_REQUEST
    assert (exists_response.json().get("extra") or {}).get("code") == ErrorCode.UPDATE_USER_EMAIL_ALREADY_EXISTS

    invalid_password_message = "Invalid password."
    monkeypatch.setattr(user_manager, "update", AsyncMock(side_effect=InvalidPasswordError(invalid_password_message)))
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
        json={"is_verified": False, "is_superuser": True},
    )
    delete_response = await test_client.delete(f"/users/{regular_user.id}", headers=headers)

    assert get_response.status_code == HTTP_OK
    assert get_response.json()["email"] == regular_user.email
    assert "hashed_password" not in get_response.json()
    assert "totp_secret" not in get_response.json()

    assert patch_response.status_code == HTTP_OK
    assert patch_response.json()["is_verified"] is False
    assert patch_response.json()["is_superuser"] is True

    assert delete_response.status_code == HTTP_OK
    assert delete_response.json()["is_active"] is False
    stored_user = await user_db.get(regular_user.id)
    assert stored_user is not None
    assert stored_user.is_active is False
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
        "is_superuser": False,
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
                "is_superuser": False,
            },
        ],
        "total": 3,
        "limit": 1,
        "offset": 1,
    }
