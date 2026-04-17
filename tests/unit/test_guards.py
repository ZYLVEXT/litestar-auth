"""Tests for route authorization guards."""

from __future__ import annotations

import importlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, assert_type, cast
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.handlers.base import BaseRouteHandler

import litestar_auth.guards._guards as guards_module
from litestar_auth.exceptions import ErrorCode, InsufficientRolesError
from litestar_auth.guards import (
    _guards,
    has_all_roles,
    has_any_role,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
)
from litestar_auth.guards._guards import (
    _require_active_guarded_user,
    _require_guarded_user,
    _require_role_capable_user,
)
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit

HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
type Guard = Callable[[ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], Awaitable[None] | None]


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


@dataclass(frozen=True, slots=True)
class _ExpectedInsufficientRoles:
    """Expected structured context emitted by a role guard."""

    required_roles: frozenset[str]
    user_roles: frozenset[str]
    require_all: bool


class _TypedRole(StrEnum):
    """Typed role fixture for StrEnum guard coverage."""

    ADMIN = "admin"
    BILLING = "billing"


_LITERAL_ADMIN_ROLE: Literal["admin"] = "admin"


def test_guards_module_executes_under_coverage() -> None:
    """Reload the guard module in-test so coverage records module execution."""
    reloaded_module = importlib.reload(guards_module)

    assert reloaded_module.has_any_role is _guards.has_any_role
    assert reloaded_module.has_all_roles is _guards.has_all_roles
    assert reloaded_module.is_authenticated is _guards.is_authenticated
    assert reloaded_module.is_active is _guards.is_active
    assert reloaded_module.is_verified is _guards.is_verified
    assert reloaded_module.is_superuser is _guards.is_superuser


@pytest.mark.parametrize(
    ("guard", "expected_name"),
    [
        pytest.param(is_active, "is_active", id="is_active"),
        pytest.param(is_verified, "is_verified", id="is_verified"),
        pytest.param(is_superuser, "is_superuser", id="is_superuser"),
    ],
)
def test_guards_reject_user_without_guarded_protocol(
    guard: Guard,
    expected_name: str,
) -> None:
    """Guards require ``GuardedUserProtocol`` (no getattr fallback for missing flags)."""
    user = _UserWithoutAccountState(id=uuid4())
    connection = _build_connection(user)

    with pytest.raises(PermissionDeniedException) as exc_info:
        guard(connection, _build_handler())

    detail = (exc_info.value.detail or "").lower()
    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "account state" in detail
    assert expected_name in detail
    assert "guardeduserprotocol" in detail


def test_require_active_guarded_user_returns_active_guarded_instance() -> None:
    """The active-user helper returns the same user object narrowed for downstream checks."""
    user = ExampleUser(id=uuid4(), is_active=True, is_verified=True, is_superuser=False)
    connection = _build_connection(user)

    assert _require_active_guarded_user(connection) is user


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

    detail = (exc_info.value.detail or "").lower()
    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "account state" in detail
    assert "guard" in detail
    assert "guardeduserprotocol" in detail


def test_require_role_capable_user_rejects_user_without_roles() -> None:
    """The internal helper raises 403 for users without role membership."""
    with pytest.raises(PermissionDeniedException) as exc_info:
        _require_role_capable_user(_GuardedUserWithoutRoles(id=uuid4()))

    detail = (exc_info.value.detail or "").lower()
    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "role membership" in detail
    assert "guard" in detail
    assert "rolecapableuserprotocol" in detail


def test_guard_exports_reference_internal_implementations() -> None:
    """Public guard exports are direct aliases of the implementation functions."""
    public_module = importlib.import_module("litestar_auth.guards")

    assert public_module.has_any_role.__module__ == _guards.__name__
    assert public_module.has_all_roles.__module__ == _guards.__name__
    assert public_module.is_authenticated.__module__ == _guards.__name__
    assert public_module.is_active.__module__ == _guards.__name__
    assert public_module.is_verified.__module__ == _guards.__name__
    assert public_module.is_superuser.__module__ == _guards.__name__


def test_has_any_role_exposes_role_name_typevar_annotation() -> None:
    """The public guard factory exposes the shared role-name type variable in its signature."""
    assert _guards.has_any_role.__annotations__["roles"] == "RoleNameT"


def test_has_all_roles_exposes_role_name_typevar_annotation() -> None:
    """The public guard factory exposes the shared role-name type variable in its signature."""
    assert _guards.has_all_roles.__annotations__["roles"] == "RoleNameT"


def test_typed_role_literal_inputs_pass_static_type_checks() -> None:
    """Literal-typed role names remain valid inputs to the generic role guard factories."""
    any_guard = has_any_role(_LITERAL_ADMIN_ROLE)
    all_guard = has_all_roles(_LITERAL_ADMIN_ROLE)

    assert_type(any_guard, Guard)
    assert_type(all_guard, Guard)


def test_typed_role_str_enum_inputs_pass_static_type_checks() -> None:
    """StrEnum members remain valid inputs to the generic role guard factories."""
    any_guard = has_any_role(_TypedRole.ADMIN)
    all_guard = has_all_roles(_TypedRole.ADMIN, _TypedRole.BILLING)

    assert_type(any_guard, Guard)
    assert_type(all_guard, Guard)


@pytest.mark.parametrize(
    ("guard", "user"),
    [
        pytest.param(
            has_any_role(_LITERAL_ADMIN_ROLE),
            ExampleUser(id=uuid4(), roles=[" ADMIN "]),
            id="literal-any-runtime",
        ),
        pytest.param(
            has_all_roles(_TypedRole.ADMIN, _TypedRole.BILLING),
            ExampleUser(id=uuid4(), roles=[" Billing ", "ADMIN"]),
            id="str-enum-all-runtime",
        ),
    ],
)
def test_typed_role_inputs_preserve_runtime_guard_semantics(guard: Guard, user: ExampleUser) -> None:
    """Literal and StrEnum role inputs still normalize and authorize like plain strings."""
    connection = _build_connection(user)

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize("factory", [has_any_role, has_all_roles], ids=["any", "all"])
def test_role_guard_no_role_raises_value_error(factory: Callable[..., Guard]) -> None:
    """Role guards reject empty role configuration at build time."""
    with pytest.raises(ValueError, match="at least one role"):
        factory()


@pytest.mark.parametrize(
    ("factory", "args", "expected_input"),
    [
        pytest.param(has_any_role, ("",), "''", id="any-empty-string"),
        pytest.param(has_all_roles, ("admin", " \t "), "' \\t '", id="all-whitespace-string"),
    ],
)
def test_role_guard_factory_empty_role_raises_with_offending_input(
    factory: Callable[..., Guard],
    args: tuple[str, ...],
    expected_input: str,
) -> None:
    """Blank role names are rejected at guard-build time with the offending raw input."""
    with pytest.raises(ValueError, match="empty role names after normalization") as exc_info:
        factory(*args)

    assert expected_input in str(exc_info.value)


@pytest.mark.parametrize(
    ("factory", "args", "expected_input"),
    [
        pytest.param(has_any_role, ("",), "''", id="any-empty-string"),
        pytest.param(has_all_roles, (" ", "\t"), "' '", id="all-blank-roles"),
    ],
)
def test_role_guard_empty_role_raises_value_error(
    factory: Callable[..., Guard],
    args: tuple[str, ...],
    expected_input: str,
) -> None:
    """Role guards reject blank role inputs before they can produce a guard."""
    with pytest.raises(ValueError, match="empty role names after normalization") as exc_info:
        factory(*args)

    assert expected_input in str(exc_info.value)


def test_role_guard_invalid_role_type_raises_type_error() -> None:
    """Role guards reject non-string role inputs."""
    with pytest.raises(TypeError):
        has_all_roles(*cast("Any", (1,)))


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
            "has_any_role",
            id="missing-role-contract-any",
        ),
        pytest.param(
            has_all_roles("admin"),
            _GuardedUserWithoutRoles(id=uuid4()),
            PermissionDeniedException,
            "has_all_roles",
            id="missing-role-contract-all",
        ),
        pytest.param(
            has_any_role("admin"),
            _GuardedUserWithInvalidRoles(id=uuid4(), roles=(object(),)),
            PermissionDeniedException,
            "has_any_role",
            id="invalid-user-roles",
        ),
        pytest.param(
            has_any_role("billing"),
            ExampleUser(id=uuid4(), roles=["support"]),
            InsufficientRolesError,
            "required roles",
            id="any-role-miss",
        ),
        pytest.param(
            has_all_roles("admin", "billing"),
            ExampleUser(id=uuid4(), roles=["admin"]),
            InsufficientRolesError,
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

    detail = (str(exc_info.value.detail) if hasattr(exc_info.value, "detail") else str(exc_info.value)).lower()
    assert detail_fragment in detail
    if detail_fragment in {"has_any_role", "has_all_roles"}:
        assert "rolecapableuserprotocol" in detail


@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        pytest.param(
            has_any_role("billing"),
            _ExpectedInsufficientRoles(
                required_roles=frozenset({"billing"}),
                user_roles=frozenset({"support"}),
                require_all=False,
            ),
            id="any-role-context",
        ),
        pytest.param(
            has_all_roles("admin", "billing"),
            _ExpectedInsufficientRoles(
                required_roles=frozenset({"admin", "billing"}),
                user_roles=frozenset({"admin"}),
                require_all=True,
            ),
            id="all-role-context",
        ),
    ],
)
def test_role_guards_raise_insufficient_roles_error_with_context(
    guard: Guard,
    expected: _ExpectedInsufficientRoles,
) -> None:
    """Role guards expose structured role-denial context for downstream handlers."""
    connection = _build_connection(ExampleUser(id=uuid4(), roles=sorted(expected.user_roles)))

    with pytest.raises(InsufficientRolesError) as exc_info:
        guard(connection, _build_handler())

    error = exc_info.value
    assert error.code == ErrorCode.INSUFFICIENT_ROLES
    assert error.required_roles == expected.required_roles
    assert error.user_roles == expected.user_roles
    assert error.require_all is expected.require_all
