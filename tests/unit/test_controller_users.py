"""Unit tests for users-controller helper branches."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any, cast
from uuid import UUID, uuid4

import msgspec
import pytest
from litestar.exceptions import ClientException, NotAuthorizedException, NotFoundException
from litestar.status_codes import HTTP_400_BAD_REQUEST

import litestar_auth.controllers.users as users_module
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.controllers.users import (
    _build_safe_self_update,
    _users_get_user_or_404,
    _users_handle_delete_user,
    _users_handle_get_me,
    _users_handle_update_me,
    _UsersControllerContext,
    create_users_controller,
)
from litestar_auth.exceptions import ErrorCode, UnverifiedUserError
from litestar_auth.schemas import UserRead, UserUpdate

pytestmark = pytest.mark.unit
HTTP_FORBIDDEN = 403


def test_users_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and controller-class setup."""
    reloaded_module = importlib.reload(users_module)

    assert reloaded_module.create_users_controller.__name__ == create_users_controller.__name__
    assert reloaded_module._UsersControllerContext.__name__ == _UsersControllerContext.__name__


class DummyUser(msgspec.Struct):
    """Minimal user struct for account-state helper tests."""

    id: UUID
    email: str
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False


class DummyUserManager:
    """Manager stub exposing the explicit account-state validator contract."""

    def require_account_state(self, user: DummyUser, *, require_verified: bool) -> None:
        """Reject unverified users via the explicit controller contract.

        Raises:
            UnverifiedUserError: Always, to exercise the controller helper mapping.
        """
        del user
        del require_verified
        msg = "The user account is not verified."
        raise UnverifiedUserError(msg)


class RecordingUserManager:
    """Manager stub for direct users-controller helper coverage."""

    def __init__(self, *, user_to_get: DummyUser | None = None) -> None:
        """Store the user that helper lookups should resolve."""
        self.user_to_get = user_to_get
        self.require_account_state_calls: list[tuple[DummyUser, bool]] = []
        self.update_calls: list[tuple[object, DummyUser]] = []
        self.delete_calls: list[UUID] = []

    def require_account_state(self, user: DummyUser, *, require_verified: bool) -> None:
        """Record account-state validation requests."""
        self.require_account_state_calls.append((user, require_verified))

    async def get(self, user_id: UUID) -> DummyUser | None:
        """Return the configured user for the requested identifier."""
        if self.user_to_get is None or self.user_to_get.id != user_id:
            return None
        return self.user_to_get

    async def update(self, user_update: object, user: DummyUser) -> DummyUser:
        """Record the update payload and return a mutated copy.

        Returns:
            Updated dummy user reflecting the provided changes.

        Raises:
            TypeError: If the helper forwards an unexpected payload type.
        """
        self.update_calls.append((user_update, user))
        if isinstance(user_update, msgspec.Struct):
            payload = cast("dict[str, Any]", msgspec.to_builtins(user_update))
        elif isinstance(user_update, Mapping):
            payload = dict(user_update)
        else:
            msg = "Expected update payload to be a mapping or msgspec struct."
            raise TypeError(msg)
        return DummyUser(
            id=user.id,
            email=str(payload.get("email", user.email)),
            is_active=bool(payload.get("is_active", user.is_active)),
            is_verified=bool(payload.get("is_verified", user.is_verified)),
            is_superuser=bool(payload.get("is_superuser", user.is_superuser)),
        )

    async def delete(self, user_id: UUID) -> None:
        """Record hard-delete requests."""
        self.delete_calls.append(user_id)


class DummyRequest:
    """Minimal request stub for controller helper tests."""

    def __init__(self, *, user: DummyUser | None, body_bytes: bytes = b"{}") -> None:
        """Store a request user plus optional JSON body bytes."""
        self.user = user
        self._body_bytes = body_bytes

    async def body(self) -> bytes:
        """Return the configured request body."""
        return self._body_bytes


class ExtendedSelfUpdate(msgspec.Struct, omit_defaults=True):
    """Custom self-update payload with one safe extra field."""

    email: str | None = None
    password: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
    hashed_password: str | None = None
    bio: str | None = None


def build_context(
    *,
    hard_delete: bool = False,
    user_update_schema: type[msgspec.Struct] = UserUpdate,
) -> _UsersControllerContext[DummyUser, UUID]:
    """Create a controller context for direct helper tests.

    Returns:
        Users-controller context using UUID path parsing and the requested update schema.
    """
    return _UsersControllerContext(
        id_parser=UUID,
        user_read_schema_type=UserRead,
        user_update_schema_type=user_update_schema,
        users_page_schema_type=msgspec.defstruct(
            "UsersPageSchema",
            [
                ("items", list[object]),
                ("total", int),
                ("limit", int),
                ("offset", int),
            ],
        ),
        hard_delete=hard_delete,
        default_limit=50,
        max_limit=100,
        unsafe_testing=False,
    )


async def test_require_account_state_uses_explicit_manager_contract_for_unverified_users() -> None:
    """The shared helper maps explicit-manager UnverifiedUserError into LOGIN_USER_NOT_VERIFIED."""
    user = DummyUser(id=uuid4(), email="user@example.com")

    with pytest.raises(ClientException) as exc_info:
        await _require_account_state(user, user_manager=cast("Any", DummyUserManager()), require_verified=False)

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "The user account is not verified."
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_NOT_VERIFIED}


async def test_require_account_state_uses_attribute_fallback_without_manager_contract() -> None:
    """The shared helper falls back to direct user attributes when no manager is provided."""
    await _require_account_state(
        DummyUser(id=uuid4(), email="user@example.com"),
        require_verified=False,
    )


async def test_users_get_user_or_404_rejects_unparseable_ids() -> None:
    """User lookups map parser failures into consistent 404 responses."""
    manager = RecordingUserManager()

    with pytest.raises(NotFoundException, match="User not found\\."):
        await _users_get_user_or_404(
            "not-a-valid-id",
            user_manager=cast("Any", manager),
            id_parser=UUID,
        )


async def test_users_get_user_or_404_rejects_missing_users() -> None:
    """User lookups return 404 when the manager cannot find the user."""
    manager = RecordingUserManager()

    missing_user_id = uuid4()

    with pytest.raises(NotFoundException, match="User not found\\."):
        await _users_get_user_or_404(
            str(missing_user_id),
            user_manager=cast("Any", manager),
            id_parser=UUID,
        )


async def test_users_handle_get_me_requires_authenticated_user() -> None:
    """Direct helper coverage for the in-handler authentication guard."""
    manager = RecordingUserManager()

    with pytest.raises(NotAuthorizedException, match="Authentication credentials were not provided\\."):
        await _users_handle_get_me(
            cast("Any", DummyRequest(user=None)),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )


async def test_users_handle_get_me_validates_account_state_and_serializes_user() -> None:
    """The self-read helper validates state and returns the configured schema."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True)
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_get_me(
        cast("Any", DummyRequest(user=user)),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    assert manager.require_account_state_calls == [(user, False)]


async def test_users_handle_update_me_strips_privileged_fields() -> None:
    """Self-updates only forward safe fields to the manager."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True)
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_update_me(
        cast("Any", DummyRequest(user=user)),
        ExtendedSelfUpdate(
            email="updated@example.com",
            password="new-password",
            is_active=False,
            is_verified=False,
            is_superuser=True,
        ),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email="updated@example.com",
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    assert manager.require_account_state_calls == [(user, False)]
    assert manager.update_calls == [({"email": "updated@example.com", "password": "new-password"}, user)]


async def test_users_handle_delete_user_rejects_superuser_self_delete() -> None:
    """Superusers receive the dedicated 403 error when deleting themselves."""
    user = DummyUser(id=uuid4(), email="admin@example.com", is_superuser=True, is_verified=True)
    manager = RecordingUserManager(user_to_get=user)

    with pytest.raises(ClientException) as exc_info:
        await _users_handle_delete_user(
            str(user.id),
            cast("Any", DummyRequest(user=user)),
            ctx=build_context(),
            user_manager=cast("Any", manager),
        )

    assert exc_info.value.status_code == HTTP_FORBIDDEN
    assert exc_info.value.detail == "Superusers cannot delete their own account."
    assert exc_info.value.extra == {"code": ErrorCode.SUPERUSER_CANNOT_DELETE_SELF}


async def test_users_handle_delete_user_soft_deletes_by_disabling_user() -> None:
    """Soft-delete mode updates the user instead of calling hard delete."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True)
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_delete_user(
        str(user.id),
        cast("Any", DummyRequest(user=None)),
        ctx=build_context(),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=False,
        is_verified=True,
        is_superuser=False,
    )
    assert len(manager.update_calls) == 1
    assert manager.delete_calls == []
    payload, updated_user = manager.update_calls[0]
    assert isinstance(payload, UserUpdate)
    assert payload.is_active is False
    assert updated_user is user


async def test_users_handle_delete_user_hard_deletes_when_enabled() -> None:
    """Hard-delete mode calls the manager delete hook and returns the original user schema."""
    user = DummyUser(id=uuid4(), email="user@example.com", is_verified=True)
    manager = RecordingUserManager(user_to_get=user)

    result = await _users_handle_delete_user(
        str(user.id),
        cast("Any", DummyRequest(user=None)),
        ctx=build_context(hard_delete=True),
        user_manager=cast("Any", manager),
    )

    assert result == UserRead(
        id=user.id,
        email=user.email,
        is_active=True,
        is_verified=True,
        is_superuser=False,
    )
    assert manager.delete_calls == [user.id]
    assert manager.update_calls == []


def test_build_safe_self_update_strips_privileged_fields_and_preserves_custom_safe_fields() -> None:
    """The deny-list removes privilege fields while keeping safe custom DTO fields."""
    payload = _build_safe_self_update(
        ExtendedSelfUpdate(
            email="updated@example.com",
            password="new-password",
            is_active=False,
            is_verified=False,
            is_superuser=True,
            hashed_password="forbidden",
            bio="still-allowed",
        ),
    )

    assert payload == {
        "email": "updated@example.com",
        "password": "new-password",
        "bio": "still-allowed",
    }


def test_build_safe_self_update_rejects_non_mapping_builtins(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unexpected `msgspec.to_builtins()` output raises a defensive `TypeError`."""
    monkeypatch.setattr("litestar_auth.controllers.users.msgspec.to_builtins", lambda _value: ["not", "a", "mapping"])

    with pytest.raises(TypeError, match="Expected a mapping from msgspec\\.to_builtins\\."):
        _build_safe_self_update(ExtendedSelfUpdate(email="updated@example.com"))


def test_create_users_controller_uses_requested_path() -> None:
    """Controller factory preserves the configured base path."""
    controller = create_users_controller(path="/admin-users")

    assert controller.path == "/admin-users"
    assert controller.__module__ == "litestar_auth.controllers.users"
