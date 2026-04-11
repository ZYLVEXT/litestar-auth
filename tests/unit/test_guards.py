"""Tests for route authorization guards."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

import litestar_auth.guards._guards as guards_module
from litestar_auth.guards import (
    _guards,
    has_all_roles,
    has_any_role,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
)
from litestar_auth.guards._guards import _require_guarded_user, _require_role_capable_user
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit

HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
type Guard = Callable[[ASGIConnection[Any, Any, Any, Any], object], None]


def _build_connection(user: object | None) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal HTTP connection populated with a user.

    Args:
        user: User attached to the connection scope.

    Returns:
        Minimal Litestar connection object.
    """
    scope = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
        "user": user,
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


def _build_handler() -> BaseRouteHandler:
    """Return a mock route handler matching the Litestar guard API."""
    return cast("BaseRouteHandler", Mock())


@dataclass(slots=True)
class _UserWithoutAccountState:
    """Minimal user with only ``id`` — not a :class:`~litestar_auth.types.GuardedUserProtocol`."""

    id: UUID


@dataclass(slots=True)
class _GuardedUserWithoutRoles:
    """Guarded user missing the role-capable contract."""

    id: UUID
    is_active: bool = True
    is_verified: bool = True
    is_superuser: bool = False


@dataclass(slots=True)
class _GuardedUserWithInvalidRoles:
    """Guarded user exposing invalid role data."""

    id: UUID
    roles: tuple[object, ...]
    is_active: bool = True
    is_verified: bool = True
    is_superuser: bool = False


def test_guards_module_executes_under_coverage() -> None:
    """Reload the guard module in-test so coverage records module execution."""
    reloaded_module = importlib.reload(guards_module)

    assert reloaded_module.has_any_role is _guards.has_any_role
    assert reloaded_module.has_all_roles is _guards.has_all_roles
    assert reloaded_module.is_authenticated is _guards.is_authenticated
    assert reloaded_module.is_active is _guards.is_active
    assert reloaded_module.is_verified is _guards.is_verified
    assert reloaded_module.is_superuser is _guards.is_superuser


def test_guards_reject_user_without_guarded_protocol() -> None:
    """Guards require ``GuardedUserProtocol`` (no getattr fallback for missing flags)."""
    user = _UserWithoutAccountState(id=uuid4())
    connection = _build_connection(user)

    with pytest.raises(PermissionDeniedException) as exc_info:
        is_active(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "account state" in (exc_info.value.detail or "").lower()


@pytest.mark.parametrize("guard", [is_verified, is_superuser])
def test_dependent_guards_defensively_reject_missing_user_after_activity_check(guard: Guard) -> None:
    """Dependent guards still reject missing users if the activity check does not raise."""
    connection = _build_connection(None)

    with (
        patch.object(guards_module, "is_active", return_value=None),
        pytest.raises(NotAuthorizedException) as exc_info,
    ):
        guard(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize(
    "guard",
    [has_any_role("admin"), has_all_roles("admin", "billing")],
)
def test_role_guards_defensively_reject_missing_user_after_activity_check(guard: Guard) -> None:
    """Role guards still reject missing users if the activity check does not raise."""
    connection = _build_connection(None)

    with (
        patch.object(guards_module, "is_active", return_value=None),
        pytest.raises(NotAuthorizedException) as exc_info,
    ):
        guard(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED


def test_require_guarded_user_returns_guarded_user_instance() -> None:
    """The internal helper returns valid guarded users unchanged."""
    user = ExampleUser(id=uuid4(), is_active=True, is_verified=True, is_superuser=True)

    assert _require_guarded_user(user) is user


def test_require_role_capable_user_returns_role_capable_user_instance() -> None:
    """The internal helper returns valid role-capable users unchanged."""
    user = ExampleUser(id=uuid4(), roles=["admin"])

    assert _require_role_capable_user(user) is user


def test_require_guarded_user_rejects_none() -> None:
    """The internal helper raises 403 for missing users."""
    with pytest.raises(PermissionDeniedException) as exc_info:
        _require_guarded_user(None)

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "account state" in (exc_info.value.detail or "").lower()


def test_require_role_capable_user_rejects_user_without_roles() -> None:
    """The internal helper raises 403 for users without role membership."""
    with pytest.raises(PermissionDeniedException) as exc_info:
        _require_role_capable_user(_GuardedUserWithoutRoles(id=uuid4()))

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "role membership" in (exc_info.value.detail or "").lower()


def test_guard_exports_reference_internal_implementations() -> None:
    """Public guard exports are direct aliases of the implementation functions."""
    public_module = importlib.import_module("litestar_auth.guards")

    assert public_module.has_any_role.__module__ == _guards.__name__
    assert public_module.has_all_roles.__module__ == _guards.__name__
    assert public_module.is_authenticated.__module__ == _guards.__name__
    assert public_module.is_active.__module__ == _guards.__name__
    assert public_module.is_verified.__module__ == _guards.__name__
    assert public_module.is_superuser.__module__ == _guards.__name__


@pytest.mark.parametrize(
    ("factory", "args", "expected_exception"),
    [
        pytest.param(has_any_role, (), ValueError, id="any-empty"),
        pytest.param(has_all_roles, (), ValueError, id="all-empty"),
        pytest.param(has_any_role, (" ",), ValueError, id="any-blank"),
        pytest.param(has_all_roles, (1,), TypeError, id="all-non-string"),
    ],
)
def test_role_guard_factories_reject_invalid_configuration(
    factory: Callable[..., Guard],
    args: tuple[object, ...],
    expected_exception: type[Exception],
) -> None:
    """Role-guard factories reject empty or malformed role configuration."""
    with pytest.raises(expected_exception):
        factory(*cast("Any", args))


@pytest.mark.parametrize(
    ("guard", "user"),
    [
        pytest.param(has_any_role("admin"), ExampleUser(id=uuid4(), roles=[" Billing ", "ADMIN"]), id="any"),
        pytest.param(
            has_all_roles("admin", "billing"),
            ExampleUser(id=uuid4(), roles=[" Billing ", "ADMIN"]),
            id="all",
        ),
    ],
)
def test_role_guards_allow_matching_normalized_roles(guard: Guard, user: ExampleUser) -> None:
    """Role guards normalize both configured roles and user membership before matching."""
    connection = _build_connection(user)

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "user"),
    [
        pytest.param(is_authenticated, ExampleUser(id=uuid4()), id="authenticated"),
        pytest.param(is_active, ExampleUser(id=uuid4(), is_active=True), id="active"),
        pytest.param(is_verified, ExampleUser(id=uuid4(), is_verified=True), id="verified"),
        pytest.param(is_superuser, ExampleUser(id=uuid4(), is_superuser=True), id="superuser"),
    ],
)
def test_guards_allow_authorized_users(
    guard: Guard,
    user: ExampleUser,
) -> None:
    """Each guard allows a user satisfying its predicate."""
    connection = _build_connection(user)

    assert guard(connection, _build_handler()) is None


def test_is_authenticated_rejects_missing_user() -> None:
    """Authentication guard raises 401 when no user is present."""
    connection = _build_connection(None)

    with pytest.raises(NotAuthorizedException) as exc_info:
        is_authenticated(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED


def test_is_active_rejects_missing_user() -> None:
    """Active-user guard raises 401 when no user is present."""
    connection = _build_connection(None)

    with pytest.raises(NotAuthorizedException) as exc_info:
        is_active(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize("guard", [is_verified, is_superuser])
def test_dependent_guards_reject_missing_user(guard: Guard) -> None:
    """Verified and superuser guards still raise 401 when no user is present."""
    connection = _build_connection(None)

    with pytest.raises(NotAuthorizedException) as exc_info:
        guard(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize(
    ("guard", "user"),
    [
        pytest.param(is_active, ExampleUser(id=uuid4(), is_active=False), id="inactive"),
        pytest.param(is_verified, ExampleUser(id=uuid4(), is_verified=False), id="unverified"),
        pytest.param(
            is_verified,
            ExampleUser(id=uuid4(), is_active=False, is_verified=True),
            id="inactive-verified",
        ),
        pytest.param(is_superuser, ExampleUser(id=uuid4(), is_superuser=False), id="not-superuser"),
        pytest.param(
            is_superuser,
            ExampleUser(id=uuid4(), is_active=False, is_superuser=True),
            id="inactive-superuser",
        ),
    ],
)
def test_authorization_guards_reject_invalid_users(
    guard: Guard,
    user: ExampleUser,
) -> None:
    """Authorization guards raise 403 when the required flag is missing."""
    connection = _build_connection(user)

    with pytest.raises(PermissionDeniedException) as exc_info:
        guard(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN


@pytest.mark.parametrize(
    ("guard", "user", "expected_exception", "detail_fragment"),
    [
        pytest.param(has_any_role("admin"), None, NotAuthorizedException, "authentication", id="missing-user"),
        pytest.param(
            has_any_role("admin"),
            ExampleUser(id=uuid4(), roles=["admin"], is_active=False),
            PermissionDeniedException,
            "inactive",
            id="inactive-user",
        ),
        pytest.param(
            has_any_role("admin"),
            _GuardedUserWithoutRoles(id=uuid4()),
            PermissionDeniedException,
            "role membership",
            id="missing-role-contract",
        ),
        pytest.param(
            has_any_role("admin"),
            _GuardedUserWithInvalidRoles(id=uuid4(), roles=(object(),)),
            PermissionDeniedException,
            "role membership",
            id="invalid-user-roles",
        ),
        pytest.param(
            has_any_role("billing"),
            ExampleUser(id=uuid4(), roles=["support"]),
            PermissionDeniedException,
            "required roles",
            id="any-role-miss",
        ),
        pytest.param(
            has_all_roles("admin", "billing"),
            ExampleUser(id=uuid4(), roles=["admin"]),
            PermissionDeniedException,
            "all of the required roles",
            id="all-role-miss",
        ),
    ],
)
def test_role_guards_fail_closed_for_unauthorized_requests(
    guard: Guard,
    user: object | None,
    expected_exception: type[Exception],
    detail_fragment: str,
) -> None:
    """Role guards fail closed for missing, inactive, incompatible, or insufficient users."""
    connection = _build_connection(user)

    with pytest.raises(expected_exception) as exc_info:
        guard(connection, _build_handler())

    assert detail_fragment in (str(exc_info.value.detail) if hasattr(exc_info.value, "detail") else "").lower()
