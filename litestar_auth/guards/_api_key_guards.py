"""API-key authorization guards."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Never, TypeVar

from litestar.exceptions import PermissionDeniedException

from litestar_auth._permissions import (
    normalize_permissions,
    permissions_cover_delegated_grant,
    permissions_grant,
    resolve_connection_permissions,
)
from litestar_auth._roles import normalize_role_name as _normalize_role_name
from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth.authentication.strategy.api_key import ApiKeyContext
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards._guards import _normalized_user_roles

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Guard

ScopeNameT = TypeVar("ScopeNameT", bound=str)

_API_KEY_REQUIRED_DETAIL = "The route requires API-key authentication."
_SESSION_AUTH_REQUIRED_DETAIL = "The route requires session authentication."
_API_KEY_SCOPE_DENIED_DETAIL = "The API key does not satisfy the required scopes."


def _api_key_context(connection: ASGIConnection[Any, Any, Any, Any]) -> ApiKeyContext | None:
    """Return the request API-key context when the API-key backend authenticated it."""
    auth = connection.scope.get("auth")
    if isinstance(auth, ApiKeyContext):
        return auth
    return None


def api_key_delegation_scopes(connection: ASGIConnection[Any, Any, Any, Any]) -> frozenset[str] | None:
    """Return the permission-shaped scopes a delegated API key may exercise.

    Returns:
        ``None`` when the request was not API-key authenticated, so no delegation
        ceiling applies. For an API-key request, the key's normalized
        permission-shaped scopes; legacy simple scopes (no ``resource:action``
        grammar) or malformed scope material carry no permission authority and
        yield an empty set so permission guards fail closed for the delegated
        credential rather than inheriting the owning user's full permissions.
    """
    context = _api_key_context(connection)
    if context is None:
        return None
    try:
        return frozenset(normalize_permissions(context.scopes))
    except (TypeError, ValueError):
        return frozenset()


def _raise_authorization_denied(detail: str) -> Never:
    raise PermissionDeniedException(detail=detail, extra={"code": ErrorCode.AUTHORIZATION_DENIED})


def _raise_scope_denied() -> Never:
    raise PermissionDeniedException(
        detail=_API_KEY_SCOPE_DENIED_DETAIL,
        extra={"code": ErrorCode.API_KEY_SCOPE_DENIED},
    )


def _normalize_required_scopes(scopes: tuple[object, ...]) -> tuple[str, ...]:
    """Normalize configured scope names for API-key scope guard factories.

    Returns:
        Deterministically normalized scope names.

    Raises:
        TypeError: If any provided scope is not a string.
        ValueError: If no scopes were provided or a scope normalizes to an empty string.
    """
    if not scopes:
        msg = "API-key scope guards require at least one scope."
        raise ValueError(msg)

    string_scopes: list[str] = []
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "API-key scopes must be provided as non-empty strings."
            raise TypeError(msg)
        string_scopes.append(raw_scope)
    try:
        return tuple(normalize_permissions(string_scopes))
    except ValueError:
        pass

    normalized_scopes: set[str] = set()
    for raw_scope in string_scopes:
        try:
            normalized_scopes.add(_normalize_role_name(raw_scope))
        except ValueError as exc:
            msg = f"API-key scope guards do not accept empty scope names after normalization: {raw_scope!r}."
            raise ValueError(msg) from exc
    return tuple(sorted(normalized_scopes))


def default_api_key_scope_authority(
    connection: ASGIConnection[Any, Any, Any, Any],
    api_key_scopes: frozenset[str],
) -> bool:
    """Return whether current user permissions still cover API-key scopes.

    Permission-shaped scopes use the request-scope permission resolver and the
    shared permission matcher. Legacy simple scopes keep the v1
    scopes-as-role-names subset contract.
    """
    try:
        normalized_api_key_scopes = frozenset(normalize_permissions(api_key_scopes))
    except ValueError:
        normalized_api_key_scopes = frozenset(_normalize_roles(api_key_scopes))
        user_roles = _normalized_user_roles(connection.user, guard_name="has_scope")
        return normalized_api_key_scopes.issubset(user_roles)

    try:
        user_permissions = resolve_connection_permissions(connection)
    except PermissionDeniedException:
        return False
    return all(
        permissions_cover_delegated_grant(user_permissions, api_key_scope)
        for api_key_scope in normalized_api_key_scopes
    )


def _normalize_api_key_scopes(scopes: object) -> frozenset[str]:
    try:
        return frozenset(normalize_permissions(scopes))
    except ValueError:
        return frozenset(_normalize_roles(scopes))


def _api_key_scopes_grant(
    *,
    api_key_scopes: frozenset[str],
    required_scopes: tuple[str, ...],
    require_all: bool,
) -> bool:
    try:
        normalized_api_key_scopes = frozenset(normalize_permissions(api_key_scopes))
        normalized_required_scopes = tuple(normalize_permissions(required_scopes))
    except ValueError:
        required_scope_set = frozenset(required_scopes)
        return required_scope_set <= api_key_scopes if require_all else bool(api_key_scopes & required_scope_set)

    if require_all:
        return all(
            permissions_grant(normalized_api_key_scopes, required_scope)
            for required_scope in normalized_required_scopes
        )
    return any(
        permissions_grant(normalized_api_key_scopes, required_scope) for required_scope in normalized_required_scopes
    )


def _scope_subset_still_allowed(
    connection: ASGIConnection[Any, Any, Any, Any],
    context: ApiKeyContext,
    api_key_scopes: frozenset[str],
) -> bool:
    """Return whether the configured scope authority still allows key scopes."""
    scope_authority = context.scope_authority or default_api_key_scope_authority
    return scope_authority(connection, api_key_scopes)


def requires_api_key(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Require authentication through the API-key backend."""
    if _api_key_context(connection) is not None:
        return
    _raise_authorization_denied(_API_KEY_REQUIRED_DETAIL)


def requires_password_session(
    connection: ASGIConnection[Any, Any, Any, Any],
    _handler: BaseRouteHandler,
) -> None:
    """Reject API-key-authenticated callers from password-session-only routes."""
    if _api_key_context(connection) is None:
        return
    _raise_authorization_denied(_SESSION_AUTH_REQUIRED_DETAIL)


def _build_scope_guard(*, required_scopes: tuple[str, ...], require_all: bool) -> Guard:
    def _guard(
        connection: ASGIConnection[Any, Any, Any, Any],
        _handler: BaseRouteHandler,
    ) -> None:
        context = _api_key_context(connection)
        if context is None:
            _raise_authorization_denied(_API_KEY_REQUIRED_DETAIL)
        try:
            api_key_scopes = _normalize_api_key_scopes(context.scopes)
        except (TypeError, ValueError) as exc:
            raise PermissionDeniedException(
                detail=_API_KEY_SCOPE_DENIED_DETAIL,
                extra={"code": ErrorCode.API_KEY_SCOPE_DENIED},
            ) from exc
        if context.scope_subset_check and not _scope_subset_still_allowed(connection, context, api_key_scopes):
            _raise_scope_denied()
        if _api_key_scopes_grant(
            api_key_scopes=api_key_scopes,
            required_scopes=required_scopes,
            require_all=require_all,
        ):
            return
        _raise_scope_denied()

    return _guard


def has_scope[ScopeNameT: str](*scopes: ScopeNameT) -> Guard:
    """Return a guard requiring an API key to have every configured scope."""
    return _build_scope_guard(required_scopes=_normalize_required_scopes(scopes), require_all=True)


def has_any_scope[ScopeNameT: str](*scopes: ScopeNameT) -> Guard:
    """Return a guard requiring an API key to have any configured scope."""
    return _build_scope_guard(required_scopes=_normalize_required_scopes(scopes), require_all=False)


__all__ = (
    "api_key_delegation_scopes",
    "default_api_key_scope_authority",
    "has_any_scope",
    "has_scope",
    "requires_api_key",
    "requires_password_session",
)
