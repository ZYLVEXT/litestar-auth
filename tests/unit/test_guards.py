"""Tests for route authorization guards."""

from __future__ import annotations

import ast
import importlib
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal, assert_type, cast
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.handlers.base import BaseRouteHandler

import litestar_auth.guards._api_key_guards as api_key_guards_module
import litestar_auth.guards._guards as guards_module
import litestar_auth.guards._permission_guards as permission_guards_module
from litestar_auth._permissions import (
    PERMISSION_RESOLVER_SENTINEL,
    StaticRolePermissionResolver,
    set_scope_permission_resolver,
)
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME, SUPERUSER_ROLE_NAME_SENTINEL
from litestar_auth.authentication.strategy.api_key import ApiKeyContext
from litestar_auth.exceptions import ErrorCode, InsufficientPermissionsError, InsufficientRolesError
from litestar_auth.guards import (
    _guards,
    has_all_permissions,
    has_all_roles,
    has_any_permission,
    has_any_role,
    has_any_scope,
    has_permission,
    has_scope,
    is_active,
    is_authenticated,
    is_superuser,
    is_verified,
    requires_api_key,
    requires_password_session,
)
from litestar_auth.guards._protocol_narrowing import (
    _require_active_guarded_user,
    _require_guarded_user,
    _require_role_capable_user,
)
from tests._helpers import ExampleUser

_roles_include_all_fixed_work = guards_module._roles_include_all_fixed_work
_roles_intersect_fixed_work = guards_module._roles_intersect_fixed_work

if TYPE_CHECKING:
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit

HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
type Guard = Callable[[ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], Awaitable[None] | None]


def _build_connection(
    user: object | None,
    *,
    auth: object | None = None,
    state: object | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal HTTP connection populated with a user.

    Args:
        user: User attached to the connection scope.
        auth: Optional request authentication context.
        state: Optional request-scope state.

    Returns:
        Minimal Litestar connection object.
    """
    scope = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
        "user": user,
        "auth": auth,
    }
    if state is not None:
        scope["state"] = state
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


@dataclass(slots=True)
class _GuardedUserWithInvalidRoles:
    """Guarded user exposing invalid role data."""

    id: UUID
    roles: tuple[object, ...]
    is_active: bool = True
    is_verified: bool = True


class _RoleCapableUserWithExplodingSuperuserFlag:
    """Role-capable guarded user whose obsolete boolean flag must not be read."""

    def __init__(
        self,
        *,
        user_id: UUID,
        roles: list[str],
        is_active: bool = True,
        is_verified: bool = True,
    ) -> None:
        """Store account state and roles."""
        self.id = user_id
        self.roles = roles
        self.is_active = is_active
        self.is_verified = is_verified

    @property
    def is_superuser(self) -> bool:
        """Fail the test if the role-based guard reads the obsolete flag.

        Raises:
            AssertionError: Always, because this property must not be read.
        """
        msg = "is_superuser should not be read by the is_superuser guard."
        raise AssertionError(msg)


@dataclass(frozen=True, slots=True)
class _ExpectedInsufficientRoles:
    """Expected structured context emitted by a role guard."""

    required_roles: frozenset[str]
    user_roles: frozenset[str]
    require_all: bool


@dataclass(frozen=True, slots=True)
class _ExpectedInsufficientPermissions:
    """Expected structured context emitted by a permission guard."""

    required_permissions: frozenset[str]
    granted_permissions: frozenset[str]
    require_all: bool


@dataclass(frozen=True, slots=True)
class _RoleGuardHelperDispatchCase:
    """Role guard helper dispatch expectation."""

    factory: Callable[..., Guard]
    helper_name: str
    roles: tuple[str, ...]
    user_roles: list[str]
    expected_required_roles: tuple[str, ...]


class _TypedRole(StrEnum):
    """Typed role fixture for StrEnum guard coverage."""

    ADMIN = "admin"
    BILLING = "billing"


_LITERAL_ADMIN_ROLE: Literal["admin"] = "admin"


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
    user = ExampleUser(id=uuid4(), is_active=True, is_verified=True)
    connection = _build_connection(user)

    assert _require_active_guarded_user(connection) is user


def test_require_guarded_user_returns_guarded_user_instance() -> None:
    """The internal helper returns valid guarded users unchanged."""
    user = ExampleUser(id=uuid4(), is_active=True, is_verified=True)

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


def test_api_key_guard_exports_reference_internal_implementations() -> None:
    """Public API-key guard exports are direct aliases of their implementation module."""
    public_module = importlib.import_module("litestar_auth.guards")

    assert public_module.requires_api_key.__module__ == "litestar_auth.guards._api_key_guards"
    assert public_module.requires_password_session.__module__ == "litestar_auth.guards._api_key_guards"
    assert public_module.has_scope.__module__ == "litestar_auth.guards._api_key_guards"
    assert public_module.has_any_scope.__module__ == "litestar_auth.guards._api_key_guards"


def test_permission_guard_exports_reference_internal_implementations() -> None:
    """Public permission guard exports are direct aliases of their implementation module."""
    public_module = importlib.import_module("litestar_auth.guards")
    root_module = importlib.import_module("litestar_auth")

    assert public_module.has_permission.__module__ == permission_guards_module.__name__
    assert public_module.has_all_permissions.__module__ == permission_guards_module.__name__
    assert public_module.has_any_permission.__module__ == permission_guards_module.__name__
    assert root_module.has_permission is public_module.has_permission
    assert root_module.has_all_permissions is public_module.has_all_permissions
    assert root_module.has_any_permission is public_module.has_any_permission


@pytest.mark.parametrize(
    ("auth", "should_allow"),
    [
        pytest.param(ApiKeyContext(key_id="key", scopes=("read",), prefix_env="prod"), True, id="api-key"),
        pytest.param("bearer", False, id="bearer"),
        pytest.param("cookie", False, id="cookie"),
    ],
)
def test_requires_api_key_allows_only_api_key_context(auth: object, should_allow: object) -> None:
    """The API-key-only guard rejects non-API-key authenticated callers."""
    connection = _build_connection(ExampleUser(id=uuid4(), roles=["read"]), auth=auth)

    if should_allow:
        assert requires_api_key(connection, _build_handler()) is None
        return

    with pytest.raises(PermissionDeniedException) as exc_info:
        requires_api_key(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.extra == {"code": ErrorCode.AUTHORIZATION_DENIED}


@pytest.mark.parametrize(
    ("auth", "should_allow"),
    [
        pytest.param(ApiKeyContext(key_id="key", scopes=("read",), prefix_env="prod"), False, id="api-key"),
        pytest.param("bearer", True, id="bearer"),
        pytest.param("cookie", True, id="cookie"),
    ],
)
def test_requires_password_session_rejects_api_key_callers(auth: object, should_allow: object) -> None:
    """Password-session-only routes fail closed for API-key callers."""
    connection = _build_connection(ExampleUser(id=uuid4(), roles=["read"]), auth=auth)

    if should_allow:
        assert requires_password_session(connection, _build_handler()) is None
        return

    with pytest.raises(PermissionDeniedException) as exc_info:
        requires_password_session(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.extra == {"code": ErrorCode.AUTHORIZATION_DENIED}


@pytest.mark.parametrize(
    ("guard", "auth", "user_roles", "expected_code"),
    [
        pytest.param(has_scope("read"), "bearer", ["read"], ErrorCode.AUTHORIZATION_DENIED, id="bearer"),
        pytest.param(
            has_scope("read"),
            ApiKeyContext(key_id="key", scopes=("write",), prefix_env="prod"),
            ["write"],
            ErrorCode.API_KEY_SCOPE_DENIED,
            id="missing-required-scope",
        ),
        pytest.param(
            has_any_scope("read", "write"),
            ApiKeyContext(key_id="key", scopes=("admin",), prefix_env="prod"),
            ["admin"],
            ErrorCode.API_KEY_SCOPE_DENIED,
            id="missing-any-scope",
        ),
        pytest.param(
            has_scope("read"),
            ApiKeyContext(key_id="key", scopes=("read",), prefix_env="prod"),
            [],
            ErrorCode.API_KEY_SCOPE_DENIED,
            id="downscoped-by-current-roles",
        ),
    ],
)
def test_api_key_scope_guards_reject_missing_or_downscoped_authority(
    guard: Guard,
    auth: object,
    user_roles: list[str],
    expected_code: ErrorCode,
) -> None:
    """Scope guards deny missing key scopes and keys no longer covered by user roles."""
    connection = _build_connection(ExampleUser(id=uuid4(), roles=user_roles), auth=auth)

    with pytest.raises(PermissionDeniedException) as exc_info:
        guard(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.extra == {"code": expected_code}


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(has_scope("read", "write"), id="all"),
        pytest.param(has_any_scope("admin", "read"), id="any"),
    ],
)
def test_api_key_scope_guards_allow_matching_key_scopes_and_current_roles(guard: Guard) -> None:
    """API-key scope guards authorize only when key scopes remain within current user roles."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=["read", "write"]),
        auth=ApiKeyContext(key_id="key", scopes=("read", "write"), prefix_env="prod"),
    )

    assert guard(connection, _build_handler()) is None


def test_api_key_scope_guard_skips_role_downscoping_when_context_disables_subset_check() -> None:
    """Scope guards can honor API-key configs that explicitly disable user-role downscoping."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=[]),
        auth=ApiKeyContext(key_id="key", scopes=("read",), prefix_env="prod", scope_subset_check=False),
    )

    assert has_scope("read")(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "api_key_scopes", "should_allow"),
    [
        pytest.param(has_scope("read"), ("read",), True, id="all-exact-match"),
        pytest.param(has_scope("read"), (), False, id="all-empty-key-scopes"),
        pytest.param(has_scope("read", "write"), ("read",), False, id="all-required-strict-superset"),
        pytest.param(has_any_scope("read", "write"), ("write",), True, id="any-partial-overlap"),
        pytest.param(has_any_scope("read", "write"), ("admin",), False, id="any-no-overlap"),
    ],
)
def test_api_key_scope_guards_match_set_membership_truth_table(
    guard: Guard,
    api_key_scopes: tuple[str, ...],
    should_allow: object,
) -> None:
    """API-key scope guards preserve all/any set membership behavior."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=[]),
        auth=ApiKeyContext(key_id="key", scopes=api_key_scopes, prefix_env="prod", scope_subset_check=False),
    )

    if should_allow:
        assert guard(connection, _build_handler()) is None
        return

    with pytest.raises(PermissionDeniedException) as exc_info:
        guard(connection, _build_handler())

    assert exc_info.value.extra == {"code": ErrorCode.API_KEY_SCOPE_DENIED}


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(has_scope("billing:read"), id="all"),
        pytest.param(has_any_scope("billing:read", "billing:write"), id="any"),
    ],
)
def test_api_key_scope_guards_use_default_scope_authority_for_role_downscoping(guard: Guard) -> None:
    """The default API-key authority uses resolved permissions for permission-shaped scopes."""
    state: dict[str, object] = {}
    user = ExampleUser(id=uuid4(), roles=["billing"])
    set_scope_permission_resolver(
        {"state": state},
        StaticRolePermissionResolver({"billing": ("billing:read", "billing:write")}),
    )
    connection = _build_connection(
        user,
        auth=ApiKeyContext(
            key_id="key",
            scopes=("billing:read", "billing:write"),
            prefix_env="prod",
            scope_authority=api_key_guards_module.default_api_key_scope_authority,
        ),
        state=state,
    )

    assert guard(connection, _build_handler()) is None


def test_api_key_scope_guards_preserve_legacy_role_scope_authority() -> None:
    """Simple legacy scopes still use exact role-name subset checks."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=["read", "write"]),
        auth=ApiKeyContext(
            key_id="key",
            scopes=("read", "write"),
            prefix_env="prod",
            scope_authority=api_key_guards_module.default_api_key_scope_authority,
        ),
    )

    assert has_scope("read", "write")(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "api_key_scopes"),
    [
        pytest.param(has_scope("posts:read", "posts:write"), ("posts:*",), id="all-resource-wildcard"),
        pytest.param(has_any_scope("posts:delete", "users:read"), ("*",), id="any-global-wildcard"),
    ],
)
def test_api_key_scope_guards_honor_permission_wildcards(
    guard: Guard,
    api_key_scopes: tuple[str, ...],
) -> None:
    """Permission-shaped API-key scopes use the same granted-side wildcard matcher as permissions."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=[]),
        auth=ApiKeyContext(key_id="key", scopes=api_key_scopes, prefix_env="prod", scope_subset_check=False),
    )

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("api_key_scopes", "user_permissions"),
    [
        pytest.param(("posts:read",), ("posts:*",), id="specific-key-covered-by-owner-wildcard"),
        pytest.param(("posts:*",), ("posts:*",), id="wildcard-key-covered-by-owner-wildcard"),
        pytest.param(("*",), ("*",), id="global-key-covered-by-owner-global"),
    ],
)
def test_api_key_scope_subset_allows_only_owner_covered_permission_scopes(
    api_key_scopes: tuple[str, ...],
    user_permissions: tuple[str, ...],
) -> None:
    """The default authority permits permission-shaped key scopes only within owner permissions."""
    state: dict[str, object] = {}
    user = ExampleUser(id=uuid4(), roles=["owner"])
    set_scope_permission_resolver({"state": state}, StaticRolePermissionResolver({"owner": user_permissions}))
    connection = _build_connection(
        user,
        auth=ApiKeyContext(
            key_id="key",
            scopes=api_key_scopes,
            prefix_env="prod",
            scope_authority=api_key_guards_module.default_api_key_scope_authority,
        ),
        state=state,
    )

    assert has_any_scope("posts:read")(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("api_key_scopes", "user_permissions"),
    [
        pytest.param(("posts:*",), ("posts:read",), id="wildcard-key-exceeds-specific-owner-permission"),
        pytest.param(("*",), ("posts:*",), id="global-key-exceeds-resource-owner-permission"),
    ],
)
def test_api_key_scope_subset_denies_permission_scopes_exceeding_owner_permissions(
    api_key_scopes: tuple[str, ...],
    user_permissions: tuple[str, ...],
) -> None:
    """The subset check fails closed when a delegated wildcard is broader than owner permissions."""
    state: dict[str, object] = {}
    user = ExampleUser(id=uuid4(), roles=["owner"])
    set_scope_permission_resolver({"state": state}, StaticRolePermissionResolver({"owner": user_permissions}))
    connection = _build_connection(
        user,
        auth=ApiKeyContext(
            key_id="key",
            scopes=api_key_scopes,
            prefix_env="prod",
            scope_authority=api_key_guards_module.default_api_key_scope_authority,
        ),
        state=state,
    )

    with pytest.raises(PermissionDeniedException) as exc_info:
        has_any_scope("posts:read")(connection, _build_handler())

    assert exc_info.value.extra == {"code": ErrorCode.API_KEY_SCOPE_DENIED}


def test_api_key_scope_subset_denies_invalid_scope_permission_resolver() -> None:
    """Invalid permission resolver state fails closed as an API-key scope denial."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=["owner"]),
        auth=ApiKeyContext(
            key_id="key",
            scopes=("posts:read",),
            prefix_env="prod",
            scope_authority=api_key_guards_module.default_api_key_scope_authority,
        ),
        state={PERMISSION_RESOLVER_SENTINEL: object()},
    )

    with pytest.raises(PermissionDeniedException) as exc_info:
        has_scope("posts:read")(connection, _build_handler())

    assert exc_info.value.extra == {"code": ErrorCode.API_KEY_SCOPE_DENIED}


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(has_scope("billing:read"), id="all"),
        pytest.param(has_any_scope("billing:read", "billing:write"), id="any"),
    ],
)
def test_api_key_scope_guards_allow_custom_scope_authority_to_grant_downscoped_key(guard: Guard) -> None:
    """A custom authority can allow API-key scopes that are not role names."""
    calls: list[tuple[object, frozenset[str]]] = []

    def _scope_authority(connection: ASGIConnection[Any, Any, Any, Any], api_key_scopes: frozenset[str]) -> bool:
        calls.append((connection.user, api_key_scopes))
        return True

    user = ExampleUser(id=uuid4(), roles=["support"])
    connection = _build_connection(
        user,
        auth=ApiKeyContext(
            key_id="key",
            scopes=("billing:read",),
            prefix_env="prod",
            scope_authority=_scope_authority,
        ),
    )

    assert guard(connection, _build_handler()) is None
    assert calls == [(user, frozenset({"billing:read"}))]


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(has_scope("read"), id="all"),
        pytest.param(has_any_scope("read", "write"), id="any"),
    ],
)
def test_api_key_scope_guards_allow_custom_scope_authority_to_deny_role_subset(guard: Guard) -> None:
    """A custom authority governs downscoping even when the default authority would allow it."""
    calls: list[frozenset[str]] = []

    def _scope_authority(_connection: ASGIConnection[Any, Any, Any, Any], api_key_scopes: frozenset[str]) -> bool:
        calls.append(api_key_scopes)
        return False

    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=["read", "write"]),
        auth=ApiKeyContext(
            key_id="key",
            scopes=("read",),
            prefix_env="prod",
            scope_authority=_scope_authority,
        ),
    )

    with pytest.raises(PermissionDeniedException) as exc_info:
        guard(connection, _build_handler())

    assert exc_info.value.extra == {"code": ErrorCode.API_KEY_SCOPE_DENIED}
    assert calls == [frozenset({"read"})]


@pytest.mark.parametrize("factory", [has_scope, has_any_scope], ids=["all", "any"])
def test_api_key_scope_guard_no_scope_raises_value_error(factory: Callable[..., Guard]) -> None:
    """API-key scope guards reject empty scope configuration at build time."""
    with pytest.raises(ValueError, match="at least one scope"):
        factory()


@pytest.mark.parametrize(
    ("factory", "args", "expected_exception"),
    [
        pytest.param(has_scope, ("",), ValueError, id="blank"),
        pytest.param(has_any_scope, (1,), TypeError, id="non-string"),
    ],
)
def test_api_key_scope_guard_invalid_scope_inputs_raise(
    factory: Callable[..., Guard],
    args: tuple[object, ...],
    expected_exception: type[Exception],
) -> None:
    """API-key scope guards reject invalid scope names at build time."""
    with pytest.raises(expected_exception):
        factory(*cast("Any", args))


def test_api_key_scope_guard_rejects_invalid_runtime_scope_context() -> None:
    """API-key scope guards fail closed when request auth exposes invalid scope data."""
    connection = _build_connection(
        ExampleUser(id=uuid4(), roles=["read"]),
        auth=ApiKeyContext(key_id="key", scopes=cast("Any", (object(),)), prefix_env="prod"),
    )

    with pytest.raises(PermissionDeniedException) as exc_info:
        has_scope("read")(connection, _build_handler())

    assert exc_info.value.extra == {"code": ErrorCode.API_KEY_SCOPE_DENIED}


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
    ("user_roles", "required_roles", "expected"),
    [
        pytest.param(frozenset({"admin"}), ("admin",), True, id="single-hit"),
        pytest.param(frozenset({"billing"}), ("admin",), False, id="single-miss"),
        pytest.param(frozenset({"support", "admin"}), ("admin", "billing"), True, id="multi-hit"),
        pytest.param(frozenset({"support", "viewer"}), ("admin", "billing"), False, id="multi-miss"),
        pytest.param(frozenset(), ("admin",), False, id="empty-user-roles"),
        pytest.param(frozenset({"admin"}), ("admin", "admin"), True, id="duplicate-required-role"),
    ],
)
def test_roles_intersect_fixed_work_matches_any_role_truth_table(
    user_roles: frozenset[str],
    required_roles: tuple[str, ...],
    expected: object,
) -> None:
    """The any-role helper preserves normalized role-intersection truth-table behavior."""
    assert _roles_intersect_fixed_work(user_roles, required_roles) is expected


@pytest.mark.parametrize(
    ("user_roles", "required_roles", "expected"),
    [
        pytest.param(frozenset({"admin", "billing"}), ("admin",), True, id="single-hit"),
        pytest.param(frozenset({"billing"}), ("admin",), False, id="single-miss"),
        pytest.param(frozenset({"support", "admin", "billing"}), ("admin", "billing"), True, id="multi-hit"),
        pytest.param(frozenset({"support", "admin"}), ("admin", "billing"), False, id="multi-miss"),
        pytest.param(frozenset(), ("admin",), False, id="empty-user-roles"),
        pytest.param(frozenset({"admin"}), ("admin", "admin"), True, id="duplicate-required-role"),
    ],
)
def test_roles_include_all_fixed_work_matches_all_role_truth_table(
    user_roles: frozenset[str],
    required_roles: tuple[str, ...],
    expected: object,
) -> None:
    """The all-role helper preserves normalized subset truth-table behavior."""
    assert _roles_include_all_fixed_work(user_roles, required_roles) is expected


@pytest.mark.parametrize(
    "helper",
    [
        pytest.param(_roles_intersect_fixed_work, id="any"),
        pytest.param(_roles_include_all_fixed_work, id="all"),
    ],
)
def test_fixed_work_role_helpers_do_not_use_short_circuit_role_matching(helper: Callable[..., bool]) -> None:
    """Role helpers avoid set predicates and early returns inside role-comparison loops."""
    source = inspect.getsource(helper)
    tree = ast.parse(source)
    forbidden_call_names = {"any", "all"}
    forbidden_method_names = {"issubset", "isdisjoint", "intersection"}
    loop_depth = 0
    compare_digest_calls = 0

    class _Visitor(ast.NodeVisitor):
        def visit_For(self, node: ast.For) -> None:
            nonlocal loop_depth
            loop_depth += 1
            self.generic_visit(node)
            loop_depth -= 1

        def visit_Return(self, node: ast.Return) -> None:
            assert loop_depth == 0
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal compare_digest_calls
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_call_names
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_method_names
                if node.func.attr == "compare_digest":
                    compare_digest_calls += 1
            self.generic_visit(node)

        def visit_BoolOp(self, node: ast.BoolOp) -> None:
            pytest.fail("fixed-work role helpers must not use short-circuit boolean operators")

        def visit_BinOp(self, node: ast.BinOp) -> None:
            assert not isinstance(node.op, ast.BitAnd | ast.BitOr)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            assert not isinstance(node.op, ast.BitAnd | ast.BitOr)
            self.generic_visit(node)

    _Visitor().visit(tree)
    assert compare_digest_calls == 1


def test_build_role_guard_does_not_use_short_circuit_set_predicates() -> None:
    """Role guard wiring delegates role authorization to fixed-work helper predicates."""
    source = inspect.getsource(guards_module._build_role_guard)
    tree = ast.parse(source)

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"intersection", "issubset", "isdisjoint"}
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            assert not isinstance(node.op, ast.BitAnd | ast.BitOr)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            assert not isinstance(node.op, ast.BitAnd | ast.BitOr)
            self.generic_visit(node)

    _Visitor().visit(tree)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            _RoleGuardHelperDispatchCase(
                factory=has_any_role,
                helper_name="_roles_intersect_fixed_work",
                roles=("admin",),
                user_roles=["viewer"],
                expected_required_roles=("admin",),
            ),
            id="any-role",
        ),
        pytest.param(
            _RoleGuardHelperDispatchCase(
                factory=has_all_roles,
                helper_name="_roles_include_all_fixed_work",
                roles=("admin", "billing"),
                user_roles=["admin"],
                expected_required_roles=("admin", "billing"),
            ),
            id="all-role",
        ),
    ],
)
def test_role_guards_dispatch_to_fixed_work_helpers(
    monkeypatch: pytest.MonkeyPatch,
    case: _RoleGuardHelperDispatchCase,
) -> None:
    """Role guards use fixed-work helpers for authorization decisions."""
    calls: list[tuple[frozenset[str], tuple[str, ...]]] = []

    def _fake_helper(runtime_user_roles: frozenset[str], required_roles: tuple[str, ...]) -> bool:
        calls.append((runtime_user_roles, required_roles))
        return True

    monkeypatch.setattr(guards_module, case.helper_name, _fake_helper)

    guard = case.factory(*case.roles)
    connection = _build_connection(ExampleUser(id=uuid4(), roles=case.user_roles))

    assert guard(connection, _build_handler()) is None
    assert calls == [(frozenset(case.user_roles), case.expected_required_roles)]


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
    ("guard", "roles", "allowed"),
    [
        pytest.param(has_any_role("café"), ["café"], True, id="any-non-ascii-match"),
        pytest.param(has_any_role("café"), ["thé"], False, id="any-non-ascii-mismatch"),
        pytest.param(has_all_roles("café", "thé"), ["café", "thé"], True, id="all-non-ascii-match"),
        pytest.param(has_all_roles("café", "thé"), ["café"], False, id="all-non-ascii-partial"),
        pytest.param(has_any_role("статья"), ["статья"], True, id="any-cyrillic-match"),
    ],
)
def test_role_guards_match_non_ascii_role_names(guard: Guard, roles: list[str], *, allowed: bool) -> None:
    """Role matching must resolve non-ASCII role names instead of raising.

    ``hmac.compare_digest`` rejects non-ASCII ``str`` operands; the fixed-work role
    matchers compare UTF-8 bytes so NFKC-normalized non-ASCII roles still authorize.
    """
    connection = _build_connection(ExampleUser(id=uuid4(), roles=roles))

    if allowed:
        assert guard(connection, _build_handler()) is None
    else:
        with pytest.raises(InsufficientRolesError):
            guard(connection, _build_handler())


def test_is_superuser_matches_non_ascii_scope_role_name() -> None:
    """The superuser guard authorizes a non-ASCII configured role without raising."""
    user = ExampleUser(id=uuid4(), roles=["café"])
    connection = _build_connection(user, state={SUPERUSER_ROLE_NAME_SENTINEL: "café"})

    assert is_superuser(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "user"),
    [
        pytest.param(is_authenticated, ExampleUser(id=uuid4()), id="authenticated"),
        pytest.param(is_active, ExampleUser(id=uuid4(), is_active=True), id="active"),
        pytest.param(is_verified, ExampleUser(id=uuid4(), is_verified=True), id="verified"),
        pytest.param(is_superuser, ExampleUser(id=uuid4(), roles=[" SUPERUSER "]), id="superuser"),
    ],
)
def test_guards_allow_authorized_users(
    guard: Guard,
    user: ExampleUser,
) -> None:
    """Each guard allows a user satisfying its predicate."""
    connection = _build_connection(user)

    assert guard(connection, _build_handler()) is None


def test_is_superuser_allows_default_superuser_role_without_reading_obsolete_flag() -> None:
    """The superuser guard authorizes normalized role membership, not an obsolete bool."""
    user = _RoleCapableUserWithExplodingSuperuserFlag(user_id=uuid4(), roles=[" SuperUser "])
    connection = _build_connection(user)

    assert is_superuser(connection, _build_handler()) is None


def test_is_superuser_honors_configured_scope_role_name() -> None:
    """Plugin-managed scope state controls which normalized role grants superuser access."""
    user = ExampleUser(id=uuid4(), roles=[" Admin "])
    connection = _build_connection(user, state={SUPERUSER_ROLE_NAME_SENTINEL: " ADMIN "})

    assert is_superuser(connection, _build_handler()) is None


def test_is_superuser_dispatches_to_fixed_work_role_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Superuser authorization uses the same fixed-work role predicate as role guards."""
    calls: list[tuple[frozenset[str], tuple[str, ...]]] = []

    def _fake_helper(runtime_user_roles: frozenset[str], required_roles: tuple[str, ...]) -> bool:
        calls.append((runtime_user_roles, required_roles))
        return True

    monkeypatch.setattr(guards_module, "_roles_intersect_fixed_work", _fake_helper)

    user = ExampleUser(id=uuid4(), roles=["member"])
    connection = _build_connection(user, state={SUPERUSER_ROLE_NAME_SENTINEL: " ADMIN "})

    assert is_superuser(connection, _build_handler()) is None
    assert calls == [(frozenset({"member"}), ("admin",))]


def test_is_superuser_falls_back_to_default_when_scope_state_is_not_mapping() -> None:
    """Non-plugin scope state does not override the canonical default role."""
    user = ExampleUser(id=uuid4(), roles=[DEFAULT_SUPERUSER_ROLE_NAME])
    connection = cast(
        "ASGIConnection[Any, Any, Any, Any]",
        SimpleNamespace(user=user, scope={"state": object()}),
    )

    assert is_superuser(connection, _build_handler()) is None


@pytest.mark.parametrize(
    "configured_role",
    [
        pytest.param(object(), id="non-string"),
        pytest.param("   ", id="blank-string"),
    ],
)
def test_is_superuser_rejects_invalid_configured_scope_role_name(configured_role: object) -> None:
    """Invalid plugin-provided superuser role names fail closed."""
    user = ExampleUser(id=uuid4(), roles=["superuser"])
    connection = _build_connection(user, state={SUPERUSER_ROLE_NAME_SENTINEL: configured_role})

    with pytest.raises(PermissionDeniedException) as exc_info:
        is_superuser(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "The configured superuser role name is invalid."


def test_is_superuser_denies_user_without_configured_role() -> None:
    """A role-capable active user without the configured superuser role is denied."""
    user = ExampleUser(id=uuid4(), roles=["member"])
    connection = _build_connection(user)

    with pytest.raises(PermissionDeniedException) as exc_info:
        is_superuser(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "sufficient privileges" in (exc_info.value.detail or "").lower()


def test_is_superuser_rejects_user_without_role_capable_protocol() -> None:
    """The superuser guard fails closed when role membership is unavailable."""
    connection = _build_connection(_GuardedUserWithoutRoles(id=uuid4()))

    with pytest.raises(PermissionDeniedException) as exc_info:
        is_superuser(connection, _build_handler())

    detail = (exc_info.value.detail or "").lower()
    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "rolecapableuserprotocol" in detail
    assert "is_superuser" in detail


def test_is_superuser_rejects_invalid_user_roles() -> None:
    """The superuser guard fails closed when runtime role data cannot be normalized."""
    connection = _build_connection(_GuardedUserWithInvalidRoles(id=uuid4(), roles=(object(),)))

    with pytest.raises(PermissionDeniedException) as exc_info:
        is_superuser(connection, _build_handler())

    detail = (exc_info.value.detail or "").lower()
    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert "rolecapableuserprotocol" in detail
    assert "is_superuser" in detail


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
        pytest.param(is_superuser, ExampleUser(id=uuid4(), roles=["member"]), id="not-superuser"),
        pytest.param(
            is_superuser,
            ExampleUser(id=uuid4(), is_active=False, roles=["superuser"]),
            id="inactive-superuser",
        ),
    ],
)
def test_authorization_guards_reject_invalid_users(
    guard: Guard,
    user: ExampleUser,
) -> None:
    """Authorization guards raise 403 when the required state or role predicate is missing."""
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


def _permission_connection(
    user: object | None,
    role_permissions: dict[str, object],
) -> ASGIConnection[Any, Any, Any, Any]:
    """Build a connection with a static request-scope permission resolver.

    Returns:
        Minimal Litestar connection with permission resolver state.
    """
    connection = _build_connection(user)
    set_scope_permission_resolver(connection.scope, StaticRolePermissionResolver(role_permissions))
    return connection


def _api_key_permission_connection(
    user: object | None,
    role_permissions: dict[str, object],
    *,
    scopes: tuple[str, ...],
) -> ASGIConnection[Any, Any, Any, Any]:
    """Build an API-key-authenticated connection with a static permission resolver.

    Returns:
        Connection whose ``auth`` is an :class:`ApiKeyContext` carrying ``scopes``.
    """
    connection = _build_connection(
        user,
        auth=ApiKeyContext(key_id="key", scopes=scopes, prefix_env="prod"),
    )
    set_scope_permission_resolver(connection.scope, StaticRolePermissionResolver(role_permissions))
    return connection


@pytest.mark.parametrize(
    ("guard", "role_permissions", "roles"),
    [
        pytest.param(has_permission("posts:read"), {"reader": ("posts:read",)}, ["reader"], id="single"),
        pytest.param(
            has_all_permissions("posts:read", "posts:write"),
            {"editor": ("posts:*",)},
            ["editor"],
            id="all-with-granted-wildcard",
        ),
        pytest.param(
            has_any_permission("posts:delete", "posts:read"),
            {"reader": ("posts:read",)},
            ["reader"],
            id="any-partial-match",
        ),
    ],
)
def test_permission_guards_allow_matching_effective_permissions(
    guard: Guard,
    role_permissions: dict[str, object],
    roles: list[str],
) -> None:
    """Permission guards resolve effective permissions from request scope before matching."""
    connection = _permission_connection(ExampleUser(id=uuid4(), roles=roles), role_permissions)

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(has_permission("tenants:delete"), id="single"),
        pytest.param(has_all_permissions("tenants:delete", "billing:write"), id="all"),
        pytest.param(has_any_permission("tenants:delete", "billing:write"), id="any"),
    ],
)
def test_permission_guards_allow_superuser_global_permission_grant(guard: Guard) -> None:
    """The configured superuser role resolves to the global permission grant for permission guards."""
    connection = _permission_connection(ExampleUser(id=uuid4(), roles=[DEFAULT_SUPERUSER_ROLE_NAME]), {})

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "role_permissions", "roles", "expected"),
    [
        pytest.param(
            has_permission("posts:delete"),
            {"reader": ("posts:read",)},
            ["reader"],
            _ExpectedInsufficientPermissions(
                required_permissions=frozenset({"posts:delete"}),
                granted_permissions=frozenset({"posts:read"}),
                require_all=True,
            ),
            id="single-denied",
        ),
        pytest.param(
            has_any_permission("posts:delete", "users:write"),
            {"reader": ("posts:read",)},
            ["reader"],
            _ExpectedInsufficientPermissions(
                required_permissions=frozenset({"posts:delete", "users:write"}),
                granted_permissions=frozenset({"posts:read"}),
                require_all=False,
            ),
            id="any-denied",
        ),
        pytest.param(
            has_all_permissions("posts:read", "posts:write"),
            {"reader": ("posts:read",)},
            ["reader"],
            _ExpectedInsufficientPermissions(
                required_permissions=frozenset({"posts:read", "posts:write"}),
                granted_permissions=frozenset({"posts:read"}),
                require_all=True,
            ),
            id="all-partial-denied",
        ),
    ],
)
def test_permission_guards_raise_insufficient_permissions_error_with_context(
    guard: Guard,
    role_permissions: dict[str, object],
    roles: list[str],
    expected: _ExpectedInsufficientPermissions,
) -> None:
    """Permission guard denials expose structured context without leaking names in the message."""
    connection = _permission_connection(ExampleUser(id=uuid4(), roles=roles), role_permissions)

    with pytest.raises(InsufficientPermissionsError) as exc_info:
        guard(connection, _build_handler())

    error = exc_info.value
    assert error.code == ErrorCode.INSUFFICIENT_PERMISSIONS
    assert error.required_permissions == expected.required_permissions
    assert error.granted_permissions == expected.granted_permissions
    assert error.require_all is expected.require_all
    assert "posts:delete" not in str(error)
    assert "posts:read" not in str(error)


@pytest.mark.parametrize(
    ("guard", "role_permissions", "roles", "scopes"),
    [
        pytest.param(
            has_permission("posts:read"),
            {"editor": ("posts:read", "posts:write")},
            ["editor"],
            ("posts:read",),
            id="key-delegates-required",
        ),
        pytest.param(
            has_permission("posts:read"),
            {},
            [DEFAULT_SUPERUSER_ROLE_NAME],
            ("posts:read",),
            id="superuser-user-with-key-delegating-required",
        ),
        pytest.param(
            has_any_permission("posts:delete", "posts:read"),
            {"editor": ("posts:read", "posts:write")},
            ["editor"],
            ("posts:read",),
            id="any-key-delegates-one",
        ),
    ],
)
def test_permission_guards_allow_api_key_within_delegated_scopes(
    guard: Guard,
    role_permissions: dict[str, object],
    roles: list[str],
    scopes: tuple[str, ...],
) -> None:
    """An API-key request passes a permission guard only for permissions the key delegates and the user holds."""
    connection = _api_key_permission_connection(
        ExampleUser(id=uuid4(), roles=roles),
        role_permissions,
        scopes=scopes,
    )

    assert guard(connection, _build_handler()) is None


@pytest.mark.parametrize(
    ("guard", "role_permissions", "roles", "scopes"),
    [
        pytest.param(
            has_permission("posts:write"),
            {"editor": ("posts:read", "posts:write")},
            ["editor"],
            ("posts:read",),
            id="user-has-permission-but-key-scope-does-not-delegate-it",
        ),
        pytest.param(
            has_permission("billing:write"),
            {},
            [DEFAULT_SUPERUSER_ROLE_NAME],
            ("posts:read",),
            id="superuser-user-cannot-exceed-key-delegation",
        ),
        pytest.param(
            has_permission("posts:read"),
            {"editor": ("posts:read",)},
            ["editor"],
            ("reader",),
            id="legacy-non-permission-key-scope-fails-closed",
        ),
        pytest.param(
            has_permission("posts:read"),
            {"editor": ("posts:read",)},
            ["editor"],
            (),
            id="empty-key-scopes-fail-closed",
        ),
    ],
)
def test_permission_guards_deny_api_key_exceeding_delegated_scopes(
    guard: Guard,
    role_permissions: dict[str, object],
    roles: list[str],
    scopes: tuple[str, ...],
) -> None:
    """A scoped API key can never exceed its delegation on a permission-guarded route (least privilege)."""
    connection = _api_key_permission_connection(
        ExampleUser(id=uuid4(), roles=roles),
        role_permissions,
        scopes=scopes,
    )

    with pytest.raises(InsufficientPermissionsError):
        guard(connection, _build_handler())


@pytest.mark.parametrize(
    ("guard", "user", "expected_exception", "detail_fragment"),
    [
        pytest.param(has_permission("posts:read"), None, NotAuthorizedException, "authentication", id="missing-user"),
        pytest.param(
            has_permission("posts:read"),
            ExampleUser(id=uuid4(), roles=["reader"], is_active=False),
            PermissionDeniedException,
            "inactive",
            id="inactive-user",
        ),
        pytest.param(
            has_permission("posts:read"),
            _GuardedUserWithoutRoles(id=uuid4()),
            PermissionDeniedException,
            "has_permission",
            id="missing-role-contract",
        ),
        pytest.param(
            has_all_permissions("posts:read"),
            ExampleUser(id=uuid4(), roles=["reader"]),
            InsufficientPermissionsError,
            "required permissions",
            id="missing-resolver",
        ),
    ],
)
def test_permission_guards_fail_closed_for_unauthorized_requests(
    guard: Guard,
    user: object | None,
    expected_exception: type[Exception],
    detail_fragment: str,
) -> None:
    """Permission guards deny missing, inactive, incompatible, or unconfigured requests."""
    connection = _build_connection(user)

    with pytest.raises(expected_exception) as exc_info:
        guard(connection, _build_handler())

    detail = (str(exc_info.value.detail) if hasattr(exc_info.value, "detail") else str(exc_info.value)).lower()
    assert detail_fragment in detail
    if detail_fragment == "has_permission":
        assert "rolecapableuserprotocol" in detail
    if isinstance(exc_info.value, InsufficientPermissionsError):
        assert exc_info.value.granted_permissions == frozenset()


def test_permission_guard_rejects_invalid_resolver_output() -> None:
    """Permission guards fail closed when a resolver returns malformed permissions."""
    connection = _build_connection(ExampleUser(id=uuid4(), roles=["reader"]))
    resolver = SimpleNamespace(resolve=lambda *_args, **_kwargs: ("posts",))
    set_scope_permission_resolver(connection.scope, cast("Any", resolver))

    with pytest.raises(PermissionDeniedException) as exc_info:
        has_permission("posts:read")(connection, _build_handler())

    assert exc_info.value.status_code == HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "The configured permission resolver returned invalid permissions."


@pytest.mark.parametrize(
    "factory",
    [has_permission, has_all_permissions, has_any_permission],
    ids=["single", "all", "any"],
)
def test_permission_guard_no_permission_raises_value_error(factory: Callable[..., Guard]) -> None:
    """Permission guards reject empty permission configuration at build time."""
    with pytest.raises(ValueError, match="at least one permission"):
        factory()


@pytest.mark.parametrize(
    ("factory", "args", "expected_exception"),
    [
        pytest.param(has_permission, ("",), ValueError, id="blank"),
        pytest.param(has_all_permissions, ("posts",), ValueError, id="malformed"),
        pytest.param(has_any_permission, (1,), TypeError, id="non-string"),
    ],
)
def test_permission_guard_invalid_permission_inputs_raise(
    factory: Callable[..., Guard],
    args: tuple[object, ...],
    expected_exception: type[Exception],
) -> None:
    """Permission guards reject invalid permission names at build time."""
    with pytest.raises(expected_exception):
        factory(*cast("Any", args))
