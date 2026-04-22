"""Dependency and exception-handler wiring for the auth plugin."""

from __future__ import annotations

import inspect
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from advanced_alchemy.extensions.litestar import async_autocommit_handler_maker
from litestar.datastructures.state import State
from litestar.di import Provide
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response
from litestar.types import Scope
from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    ExceptionResponseHook,
    LitestarAuthConfig,
)
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.scoped_session import SessionFactory, get_or_create_scoped_session
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.controllers._utils import _is_litestar_auth_route_handler
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InsufficientRolesError, LitestarAuthError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.config.app import AppConfig
    from litestar.connection import Request
    from litestar.types import ControllerRouterHandler


type DbSessionProvider = Callable[[State, Scope], AsyncSession]
_RETURNS_ASYNC_GENERATOR_MARKER = "__litestar_auth_returns_async_generator__"


@dataclass(frozen=True, slots=True)
class DependencyProviders:
    """Bound dependency provider callables used during app init."""

    config: object
    user_manager: object
    backends: object
    user_model: object
    oauth_associate_user_manager: object


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
        existing.setdefault(AuthorizationError, cast("Any", authorization_handler))
        if _is_litestar_auth_route_handler(route_handler):
            existing.setdefault(ClientException, cast("Any", client_handler))
        cast("Any", route_handler).exception_handlers = existing


def _make_db_session_provide(
    session_maker: SessionFactory,
) -> DbSessionProvider:
    """Build a sync dependency callable matching Advanced Alchemy ``provide_session`` semantics.

    Returns:
        Callable taking ``(state, scope)`` and returning the shared request ``AsyncSession``.
    """

    def provide_db_session(state: State, scope: Scope) -> AsyncSession:
        return get_or_create_scoped_session(state, scope, session_maker)

    return provide_db_session


def _make_dependency_signature(parameter_name: str) -> inspect.Signature:
    """Build a one-parameter signature for Litestar dependency matching.

    Returns:
        Signature exposing ``parameter_name`` as a positional-or-keyword dependency input.
    """
    return inspect.Signature(
        parameters=[
            inspect.Parameter(
                name=parameter_name,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Any,
            ),
        ],
    )


def _resolve_dependency_argument(
    provider_name: str,
    parameter_name: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object:
    """Resolve a single dependency argument with function-call-style errors.

    Returns:
        Resolved dependency object to pass into the underlying builder.

    Raises:
        TypeError: If the caller supplies missing, duplicate, or unexpected inputs.
    """
    if len(args) > 1:
        msg = f"{provider_name}() takes 1 positional argument but {len(args)} were given"
        raise TypeError(msg)
    if len(args) == 1 and parameter_name in kwargs:
        msg = f"{provider_name}() got multiple values for argument {parameter_name!r}"
        raise TypeError(msg)

    unexpected_kwargs = [key for key in kwargs if key != parameter_name]
    if unexpected_kwargs:
        msg = f"{provider_name}() got an unexpected keyword argument {unexpected_kwargs[0]!r}"
        raise TypeError(msg)

    if args:
        return args[0]
    if parameter_name not in kwargs:
        msg = f"{provider_name}() missing 1 required positional argument: {parameter_name!r}"
        raise TypeError(msg)
    return kwargs[parameter_name]


def _make_user_manager_dependency_provider[TManager](
    build_user_manager: Callable[[AsyncSession], TManager],
    db_session_key: str,
) -> Callable[..., AsyncGenerator[TManager, None]]:
    """Build Litestar DI async generator: one user-manager instance per injected ``AsyncSession``.

    Args:
        build_user_manager: Callable that builds a manager for a request session (typically
            ``LitestarAuth._build_user_manager`` bound to the plugin).
        db_session_key: Dependency key / Python parameter name (must be a valid identifier).

    Returns:
        Async generator dependency suitable for ``Provide`` (``use_cache=False``).
    """
    signature = _make_dependency_signature(db_session_key)

    async def _yield_user_manager(session: AsyncSession) -> AsyncGenerator[object, None]:  # noqa: RUF029
        yield build_user_manager(session)

    def _provide_user_manager(*args: object, **kwargs: object) -> AsyncGenerator[object, None]:
        session = _resolve_dependency_argument(
            _provide_user_manager.__name__,
            db_session_key,
            args,
            kwargs,
        )
        return _yield_user_manager(cast("AsyncSession", session))

    cast("Any", _provide_user_manager).__signature__ = signature
    cast("Any", _provide_user_manager).__annotations__ = {
        db_session_key: Any,
        "return": AsyncGenerator[object, None],
    }
    setattr(_provide_user_manager, _RETURNS_ASYNC_GENERATOR_MARKER, True)
    return cast("Callable[..., AsyncGenerator[TManager, None]]", _provide_user_manager)


def _make_backends_dependency_provider[UP: UserProtocol[Any], ID](
    build_backends: Callable[[AsyncSession], Sequence[AuthenticationBackend[UP, ID]]],
    db_session_key: str,
) -> Callable[..., Sequence[AuthenticationBackend[UP, ID]]]:
    """Build a dependency provider that returns request-scoped backends for the active session.

    Returns:
        Callable dependency provider whose signature matches ``db_session_key``.
    """
    signature = _make_dependency_signature(db_session_key)

    def _provide_backends(*args: object, **kwargs: object) -> Sequence[AuthenticationBackend[Any, Any]]:
        session = _resolve_dependency_argument(
            _provide_backends.__name__,
            db_session_key,
            args,
            kwargs,
        )
        return build_backends(cast("AsyncSession", session))

    cast("Any", _provide_backends).__signature__ = signature
    cast("Any", _provide_backends).__annotations__ = {
        db_session_key: Any,
        "return": Sequence[AuthenticationBackend[Any, Any]],
    }
    return cast("Callable[..., Sequence[AuthenticationBackend[UP, ID]]]", _provide_backends)


def register_dependencies[UP: UserProtocol[Any], ID](
    app_config: AppConfig,
    config: LitestarAuthConfig[UP, ID],
    *,
    providers: DependencyProviders,
) -> None:
    """Register plugin dependency providers and guard against key collisions.

    Raises:
        ValueError: If the app already defines one of the required dependency keys.
    """
    dependency_providers = {
        DEFAULT_CONFIG_DEPENDENCY_KEY: providers.config,
        DEFAULT_USER_MANAGER_DEPENDENCY_KEY: providers.user_manager,
        DEFAULT_BACKENDS_DEPENDENCY_KEY: providers.backends,
        DEFAULT_USER_MODEL_DEPENDENCY_KEY: providers.user_model,
    }
    if config.session_maker is not None and not config.db_session_dependency_provided_externally:
        dependency_providers[config.db_session_dependency_key] = _make_db_session_provide(config.session_maker)
    oauth_contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    if oauth_contract.has_plugin_owned_associate_routes:
        dependency_providers[OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY] = providers.oauth_associate_user_manager
    collisions = sorted(set(dependency_providers).intersection(app_config.dependencies))
    if collisions:
        msg = f"Auth dependency keys already exist: {', '.join(collisions)}"
        raise ValueError(msg)

    for key, provider in dependency_providers.items():
        if (
            key == config.db_session_dependency_key
            and config.session_maker is not None
            and not config.db_session_dependency_provided_externally
        ):
            app_config.dependencies[key] = Provide(
                cast("Any", provider),
                sync_to_thread=False,
                use_cache=False,
            )
        elif key == DEFAULT_BACKENDS_DEPENDENCY_KEY:
            app_config.dependencies[key] = _to_dependency_provider(provider, use_cache=False)
        else:
            app_config.dependencies[key] = _to_dependency_provider(provider)

    if config.session_maker is not None and not config.db_session_dependency_provided_externally:
        app_config.before_send.append(async_autocommit_handler_maker())


def _to_dependency_provider(provider: object, *, use_cache: bool | None = None) -> Provide:
    """Wrap dependency callables in explicit Litestar providers.

    Returns:
        Litestar provider configured with caching when the callable is not a generator dependency.
    """
    returns_async_generator = inspect.isasyncgenfunction(provider) or bool(
        getattr(provider, _RETURNS_ASYNC_GENERATOR_MARKER, False),
    )
    effective_use_cache = not returns_async_generator if use_cache is None else use_cache
    is_async = inspect.iscoroutinefunction(provider) or inspect.isasyncgenfunction(provider)
    if is_async:
        return Provide(cast("Any", provider), use_cache=effective_use_cache)
    dependency_provider = Provide(cast("Any", provider), use_cache=effective_use_cache, sync_to_thread=False)
    if returns_async_generator:
        dependency_provider.has_async_generator_dependency = True
    return dependency_provider
