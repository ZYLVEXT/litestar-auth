"""Internal helpers for normalized permission strings and wildcard matching."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from litestar.exceptions import PermissionDeniedException

from litestar_auth._roles import normalize_role_name as _normalize_role_name
from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME, normalize_superuser_role_name

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from litestar.connection import ASGIConnection

    from litestar_auth.types import PermissionResolver

GLOBAL_PERMISSION_GRANT = "*"
PERMISSION_SEPARATOR = ":"
PERMISSION_RESOLVER_SENTINEL = "litestar_auth.permission_resolver"
WILDCARD_PERMISSION_ACTION = "*"


class StaticRolePermissionResolver:
    """Resolve effective permissions from flat user roles and a static permission map."""

    __slots__ = ("role_permissions", "superuser_role_name")

    role_permissions: Mapping[str, frozenset[str]]
    superuser_role_name: str

    def __init__(
        self,
        role_permissions: Mapping[str, object],
        *,
        superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME,
    ) -> None:
        """Store a normalized role-to-permissions mapping."""
        self.role_permissions = {
            _normalize_role_name(role_name): frozenset(normalize_permissions(permissions))
            for role_name, permissions in role_permissions.items()
        }
        self.superuser_role_name = normalize_superuser_role_name(superuser_role_name)

    def resolve(self, user: object, *, context: object | None = None) -> frozenset[str]:  # noqa: ARG002
        """Return normalized permissions granted by the user's normalized roles."""
        user_roles = _normalize_roles(getattr(user, "roles", ()))
        if self.superuser_role_name in user_roles:
            return frozenset({GLOBAL_PERMISSION_GRANT})

        resolved_permissions: set[str] = set()
        for role_name in user_roles:
            resolved_permissions.update(self.role_permissions.get(role_name, ()))
        return frozenset(resolved_permissions)


DEFAULT_PERMISSION_RESOLVER: PermissionResolver = StaticRolePermissionResolver({})


def set_scope_permission_resolver(scope: object, permission_resolver: PermissionResolver) -> None:
    """Store the resolved permission resolver on ASGI request scope state."""
    mutable_scope = cast("MutableMapping[str, Any]", scope)
    state = cast("MutableMapping[str, Any]", mutable_scope.setdefault("state", {}))
    state[PERMISSION_RESOLVER_SENTINEL] = permission_resolver


def read_scope_permission_resolver(connection: ASGIConnection[Any, Any, Any, Any]) -> PermissionResolver:
    """Return the request-scope permission resolver, or the safe empty default.

    Raises:
        PermissionDeniedException: When plugin state contains an invalid resolver.
    """
    scope_state = connection.scope.get("state")
    if not isinstance(scope_state, Mapping):
        return DEFAULT_PERMISSION_RESOLVER

    resolver = scope_state.get(PERMISSION_RESOLVER_SENTINEL, DEFAULT_PERMISSION_RESOLVER)
    if not callable(getattr(resolver, "resolve", None)):
        msg = "The configured permission resolver is invalid."
        raise PermissionDeniedException(detail=msg)
    return cast("PermissionResolver", resolver)


def resolve_connection_permissions(connection: ASGIConnection[Any, Any, Any, Any]) -> frozenset[str]:
    """Resolve normalized permissions for the authenticated request user.

    Returns:
        Normalized effective permissions, or an empty set for anonymous requests.

    Raises:
        PermissionDeniedException: When the configured resolver is invalid or returns invalid permissions.
    """
    user = connection.user
    if user is None:
        return frozenset()

    resolver = read_scope_permission_resolver(connection)
    try:
        return frozenset(normalize_permissions(resolver.resolve(user, context=connection)))
    except (TypeError, ValueError) as exc:
        msg = "The configured permission resolver returned invalid permissions."
        raise PermissionDeniedException(detail=msg) from exc


def normalize_permissions(permissions: object) -> list[str]:
    """Return deterministic normalized permission membership.

    Permission tokens use ``resource:action`` grammar. Granted permissions may also
    use ``resource:*`` or ``*`` wildcard tokens.
    """
    normalized_permissions = _normalize_roles(permissions)
    for permission in normalized_permissions:
        _validate_permission_token(permission)
    return normalized_permissions


def normalize_permission_name(permission: str) -> str:
    """Normalize and validate one permission token.

    Returns:
        The normalized permission token.
    """
    normalized_permission = _normalize_role_name(permission)
    _validate_permission_token(normalized_permission)
    return normalized_permission


def permission_grants(granted_permission: str, required_permission: str) -> bool:
    """Return whether one granted permission satisfies one required permission."""
    granted = normalize_permission_name(granted_permission)
    required = normalize_permission_name(required_permission)
    if _permission_contains_wildcard(required):
        return False
    if granted == GLOBAL_PERMISSION_GRANT:
        return True
    if granted == required:
        return True
    granted_resource, granted_action = _split_permission(granted)
    required_resource, _required_action = _split_permission(required)
    return granted_resource == required_resource and granted_action == WILDCARD_PERMISSION_ACTION


def permissions_grant(granted_permissions: object, required_permission: str) -> bool:
    """Return whether any granted permission satisfies the required permission."""
    required = normalize_permission_name(required_permission)
    if _permission_contains_wildcard(required):
        return False
    for granted_permission in normalize_permissions(granted_permissions):
        if permission_grants(granted_permission, required):
            return True
    return False


def permission_grants_fixed_work(granted_permissions: frozenset[str], required_permission: str) -> bool:
    """Return whether any granted permission satisfies one required permission.

    Constant-work counterpart of :func:`permissions_grant` for the authorization
    hot path: every granted permission is compared with :func:`hmac.compare_digest`
    and no comparison short-circuits, mirroring the role-guard matching contract
    (``_roles_intersect_fixed_work``). Both arguments must already be normalized.
    A wildcard required permission is never satisfied, matching :func:`permission_grants`.

    Returns:
        ``True`` when a granted permission grants the requirement.
    """
    if _permission_contains_wildcard(required_permission):
        return False
    required_resource, _required_action = _split_permission(required_permission)
    resource_wildcard = f"{required_resource}{PERMISSION_SEPARATOR}{WILDCARD_PERMISSION_ACTION}"
    # ``hmac.compare_digest`` raises ``TypeError`` on non-ASCII ``str`` operands, and
    # permission tokens are only NFKC-normalized (not ASCII-restricted), so they may
    # legitimately contain non-ASCII characters. Compare the UTF-8 byte encodings to
    # keep the match constant-time AND total for every valid permission token.
    required_bytes = required_permission.encode("utf-8")
    global_bytes = GLOBAL_PERMISSION_GRANT.encode("utf-8")
    resource_wildcard_bytes = resource_wildcard.encode("utf-8")
    granted = False
    for granted_permission in granted_permissions:
        candidate_bytes = granted_permission.encode("utf-8")
        matches_global = hmac.compare_digest(candidate_bytes, global_bytes)
        matches_exact = hmac.compare_digest(candidate_bytes, required_bytes)
        matches_resource_wildcard = hmac.compare_digest(candidate_bytes, resource_wildcard_bytes)
        granted = bool(int(granted) + int(matches_global) + int(matches_exact) + int(matches_resource_wildcard))
    return granted


def permissions_cover_delegated_grant(granted_permissions: object, delegated_permission: str) -> bool:
    """Return whether existing grants can safely delegate one permission token.

    Unlike route requirements, delegated API-key grants may themselves contain
    wildcards. A user permission covers a delegated wildcard only when it is at
    least as broad as the delegated grant.
    """
    delegated = normalize_permission_name(delegated_permission)
    normalized_grants = normalize_permissions(granted_permissions)
    if not _permission_contains_wildcard(delegated):
        return permissions_grant(normalized_grants, delegated)
    if GLOBAL_PERMISSION_GRANT in normalized_grants:
        return True
    if delegated == GLOBAL_PERMISSION_GRANT:
        return False
    delegated_resource, _delegated_action = _split_permission(delegated)
    return f"{delegated_resource}:{WILDCARD_PERMISSION_ACTION}" in normalized_grants


def _validate_permission_token(permission: str) -> None:
    if permission == GLOBAL_PERMISSION_GRANT:
        return
    resource, action = _split_permission(permission)
    if not resource or not action:
        msg = "Permissions must be '*' or use non-empty 'resource:action' tokens."
        raise ValueError(msg)


def _split_permission(permission: str) -> tuple[str, str]:
    try:
        resource, action = permission.split(PERMISSION_SEPARATOR, maxsplit=1)
    except ValueError as exc:
        msg = "Permissions must be '*' or use non-empty 'resource:action' tokens."
        raise ValueError(msg) from exc
    if PERMISSION_SEPARATOR in action:
        msg = "Permissions must be '*' or use non-empty 'resource:action' tokens."
        raise ValueError(msg)
    return resource, action


def _permission_contains_wildcard(permission: str) -> bool:
    if permission == GLOBAL_PERMISSION_GRANT:
        return True
    _resource, action = _split_permission(permission)
    return action == WILDCARD_PERMISSION_ACTION


__all__ = (
    "DEFAULT_PERMISSION_RESOLVER",
    "GLOBAL_PERMISSION_GRANT",
    "PERMISSION_RESOLVER_SENTINEL",
    "PERMISSION_SEPARATOR",
    "WILDCARD_PERMISSION_ACTION",
    "StaticRolePermissionResolver",
    "normalize_permission_name",
    "normalize_permissions",
    "permission_grants",
    "permission_grants_fixed_work",
    "permissions_cover_delegated_grant",
    "permissions_grant",
    "read_scope_permission_resolver",
    "resolve_connection_permissions",
    "set_scope_permission_resolver",
)
