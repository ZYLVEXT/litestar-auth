"""API-key authorization guards."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Never, TypeVar

from litestar.exceptions import PermissionDeniedException

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

    normalized_scopes: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "API-key scopes must be provided as non-empty strings."
            raise TypeError(msg)
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
    """Return whether current user roles still cover API-key scopes.

    This is the default v1 scopes-as-role-names authority used when API-key
    scope subset checking is enabled and no custom authority is configured.
    """
    user_roles = _normalized_user_roles(connection.user, guard_name="has_scope")
    return api_key_scopes.issubset(user_roles)


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
            api_key_scopes = frozenset(_normalize_roles(context.scopes))
        except (TypeError, ValueError) as exc:
            raise PermissionDeniedException(
                detail=_API_KEY_SCOPE_DENIED_DETAIL,
                extra={"code": ErrorCode.API_KEY_SCOPE_DENIED},
            ) from exc
        if context.scope_subset_check and not _scope_subset_still_allowed(connection, context, api_key_scopes):
            _raise_scope_denied()
        required_scope_set = frozenset(required_scopes)
        if require_all:
            if required_scope_set <= api_key_scopes:
                return
            _raise_scope_denied()
        if api_key_scopes & required_scope_set:
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
    "default_api_key_scope_authority",
    "has_any_scope",
    "has_scope",
    "requires_api_key",
    "requires_password_session",
)
