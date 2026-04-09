"""Dependency and exception-handler wiring for the auth plugin."""

from __future__ import annotations

import inspect
from collections.abc import Callable
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
    LitestarAuthConfig,
    _build_oauth_route_registration_contract,
)
from litestar_auth._plugin.scoped_session import SessionFactory, get_or_create_scoped_session
from litestar_auth.controllers._utils import _is_litestar_auth_route_handler
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence

    from litestar.config.app import AppConfig
    from litestar.connection import Request
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend


type DbSessionProvider = Callable[[State, Scope], AsyncSession]


@dataclass(frozen=True, slots=True)
class DependencyProviders:
    """Bound dependency provider callables used during app init."""

    config: object
    user_manager: object
    backends: object
    user_model: object
    oauth_associate_user_manager: object


def client_exception_handler(
    _request: Request[Any, Any, Any],
    exc: ClientException,
) -> Response[Any]:
    """Format ClientException as detail and code for auth responses.

    Returns:
        JSON error response containing ``detail`` and ``code``.
    """
    extra = exc.extra if isinstance(exc.extra, dict) else {}
    code = extra.get("code", "UNKNOWN")
    return Response(
        content={"detail": exc.detail, "code": code},
        status_code=exc.status_code or 400,
        media_type=MediaType.JSON,
        headers=exc.headers,
    )


def register_exception_handlers(
    route_handlers: Sequence[ControllerRouterHandler],
) -> None:
    """Register the auth ClientException handler on litestar-auth route handlers only."""
    for route_handler in route_handlers:
        if not _is_litestar_auth_route_handler(route_handler):
            continue
        route_handler_dict = getattr(route_handler, "__dict__", {})
        existing_handlers = route_handler_dict.get("exception_handlers")
        existing = dict(existing_handlers) if existing_handlers is not None else {}
        existing.setdefault(ClientException, cast("Any", client_exception_handler))
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
    namespace = {
        "Any": Any,
        "_build_user_manager": build_user_manager,
    }
    # Litestar matches dependency keys to real callable parameter names, so we
    # compile a tiny provider with the configured identifier instead of
    # overriding ``__signature__`` metadata at runtime.
    source = (
        f"async def _provide_user_manager({db_session_key}: Any):\n    yield _build_user_manager({db_session_key})\n"
    )
    exec(source, namespace)  # noqa: S102
    provider = cast("Any", namespace["_provide_user_manager"])
    provider.__module__ = __name__
    provider.__qualname__ = "_make_user_manager_dependency_provider.<locals>._provide_user_manager"
    return cast("Callable[..., AsyncGenerator[TManager, None]]", provider)


def _make_backends_dependency_provider[UP: UserProtocol[Any], ID](
    build_backends: Callable[[AsyncSession], Sequence[AuthenticationBackend[UP, ID]]],
    db_session_key: str,
) -> Callable[..., Sequence[AuthenticationBackend[UP, ID]]]:
    """Build a dependency provider that returns request-scoped backends for the active session.

    Returns:
        Callable dependency provider whose signature matches ``db_session_key``.
    """
    namespace = {
        "Any": Any,
        "_build_backends": build_backends,
    }
    # Keep the Litestar-visible signature native rather than patching metadata.
    source = f"def _provide_backends({db_session_key}: Any):\n    return _build_backends({db_session_key})\n"
    exec(source, namespace)  # noqa: S102
    provider = cast("Any", namespace["_provide_backends"])
    provider.__module__ = __name__
    provider.__qualname__ = "_make_backends_dependency_provider.<locals>._provide_backends"
    return cast("Callable[..., Sequence[AuthenticationBackend[UP, ID]]]", provider)


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
    effective_use_cache = not inspect.isasyncgenfunction(provider) if use_cache is None else use_cache
    is_async = inspect.iscoroutinefunction(provider) or inspect.isasyncgenfunction(provider)
    if is_async:
        return Provide(cast("Any", provider), use_cache=effective_use_cache)
    return Provide(cast("Any", provider), use_cache=effective_use_cache, sync_to_thread=False)
