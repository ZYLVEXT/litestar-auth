"""Exception-handler wiring for auth plugin routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response

from litestar_auth.controllers._utils import _is_litestar_auth_route_handler
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InsufficientRolesError, LitestarAuthError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from litestar.connection import Request
    from litestar.types import ControllerRouterHandler, ExceptionHandler

    from litestar_auth._plugin._protocols import RouteHandlerWithHandlers
    from litestar_auth._plugin.config import ExceptionResponseHook


class _PluginRouteAuthError(LitestarAuthError):
    """Route-scoped auth error wrapper carrying response metadata for custom hooks."""

    if TYPE_CHECKING:
        required_roles: frozenset[str]
        user_roles: frozenset[str]
        require_all: bool

    def __init__(
        self,
        *,
        message: str,
        code: str,
        status_code: int,
        headers: dict[str, str] | None,
    ) -> None:
        """Store auth error details plus the originating response metadata."""
        super().__init__(message=message, code=code)
        self.status_code = status_code
        self.headers = headers


def _copy_structured_auth_context(source: LitestarAuthError, target: _PluginRouteAuthError) -> None:
    """Copy structured auth-error context used by custom exception hooks."""
    if isinstance(source, InsufficientRolesError):
        target.required_roles = source.required_roles
        target.user_roles = source.user_roles
        target.require_all = source.require_all


def _wrap_litestar_auth_error(
    exc: LitestarAuthError,
    *,
    status_code: int,
    headers: dict[str, str] | None = None,
) -> _PluginRouteAuthError:
    """Wrap a domain auth error with HTTP response metadata for custom hooks.

    Returns:
        Wrapped auth error carrying the original message/code plus HTTP metadata.
    """
    wrapped_error = _PluginRouteAuthError(
        message=str(exc),
        code=exc.code,
        status_code=status_code,
        headers=headers,
    )
    _copy_structured_auth_context(exc, wrapped_error)
    return wrapped_error


def _resolve_client_exception_code(exc: ClientException) -> str | None:
    """Return the auth error code embedded in ``exc.extra`` when present."""
    extra = exc.extra if isinstance(exc.extra, dict) else {}
    code = extra.get("code")
    return code if isinstance(code, str) else None


def _to_litestar_auth_error(exc: ClientException) -> _PluginRouteAuthError:
    """Adapt a plugin-owned ``ClientException`` into ``LitestarAuthError`` metadata.

    Returns:
        A ``LitestarAuthError`` carrying the auth message/code plus the original
        response status/header metadata needed by custom response hooks.
    """
    original_error = exc.__cause__ if isinstance(exc.__cause__, LitestarAuthError) else None
    if original_error is not None:
        return _wrap_litestar_auth_error(
            original_error,
            status_code=exc.status_code or 400,
            headers=dict(exc.headers) if exc.headers is not None else None,
        )
    return _PluginRouteAuthError(
        message=exc.detail,
        code=_resolve_client_exception_code(exc) or LitestarAuthError.default_code,
        status_code=exc.status_code or 400,
        headers=dict(exc.headers) if exc.headers is not None else None,
    )


def client_exception_handler(
    _request: Request[Any, Any, Any],
    exc: ClientException,
) -> Response[Any]:
    """Format ClientException as detail and code for auth responses.

    Returns:
        JSON error response containing ``detail`` and ``code``.
    """
    extra = exc.extra if isinstance(exc.extra, dict) else {}
    code = extra.get("code", ErrorCode.UNKNOWN)
    return Response(
        content={"detail": exc.detail, "code": code},
        status_code=exc.status_code or 400,
        media_type=MediaType.JSON,
        headers=exc.headers,
    )


def _authorization_error_content(exc: AuthorizationError) -> dict[str, object]:
    """Build the JSON payload for route-scoped authorization failures.

    Returns:
        JSON-serializable payload matching the plugin auth error contract.
    """
    content: dict[str, object] = {
        "detail": str(exc),
        "code": exc.code,
    }
    return content


def authorization_error_handler(
    _request: Request[Any, Any, Any],
    exc: AuthorizationError,
) -> Response[Any]:
    """Format authorization failures as the auth JSON error contract.

    Returns:
        JSON response with HTTP 403 semantics for authz failures.
    """
    return Response(
        content=_authorization_error_content(exc),
        status_code=403,
        media_type=MediaType.JSON,
    )


def _build_client_exception_handler(
    exception_response_hook: ExceptionResponseHook | None,
) -> Callable[[Request[Any, Any, Any], ClientException], Response[Any]]:
    """Return the route-scoped auth ``ClientException`` handler for plugin routes."""
    if exception_response_hook is None:
        return client_exception_handler

    def handle_client_exception(
        request: Request[Any, Any, Any],
        exc: ClientException,
    ) -> Response[Any]:
        return exception_response_hook(_to_litestar_auth_error(exc), request)

    return handle_client_exception


def _build_authorization_error_handler(
    exception_response_hook: ExceptionResponseHook | None,
) -> Callable[[Request[Any, Any, Any], AuthorizationError], Response[Any]]:
    """Return the route-scoped auth authorization-error handler for plugin routes."""
    if exception_response_hook is None:
        return authorization_error_handler

    def handle_authorization_error(
        request: Request[Any, Any, Any],
        exc: AuthorizationError,
    ) -> Response[Any]:
        return exception_response_hook(_wrap_litestar_auth_error(exc, status_code=403), request)

    return handle_authorization_error


def register_exception_handlers(
    route_handlers: Sequence[ControllerRouterHandler],
    *,
    exception_response_hook: ExceptionResponseHook | None = None,
) -> None:
    """Register auth exception handlers on route handlers passed by the plugin orchestrator."""
    client_handler = _build_client_exception_handler(exception_response_hook)
    authorization_handler = _build_authorization_error_handler(exception_response_hook)
    for route_handler in route_handlers:
        route_handler_dict = getattr(route_handler, "__dict__", {})
        existing_handlers = route_handler_dict.get("exception_handlers")
        existing = dict(existing_handlers) if existing_handlers is not None else {}
        existing.setdefault(AuthorizationError, cast("ExceptionHandler", authorization_handler))
        if _is_litestar_auth_route_handler(route_handler):
            existing.setdefault(ClientException, cast("ExceptionHandler", client_handler))
        cast("RouteHandlerWithHandlers", route_handler).exception_handlers = existing
