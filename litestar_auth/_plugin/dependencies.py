"""Dependency and exception-handler wiring for the auth plugin."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from advanced_alchemy.extensions.litestar import async_autocommit_handler_maker
from litestar.datastructures.state import State  # noqa: TC002
from litestar.di import Provide
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response
from litestar.types import Scope  # noqa: TC002
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
)
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable

    from litestar.config.app import AppConfig
    from litestar.connection import Request


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


def register_exception_handlers(app_config: AppConfig) -> None:
    """Register the auth ClientException handler on the app config."""
    existing = dict(app_config.exception_handlers) if app_config.exception_handlers else {}
    existing[ClientException] = cast("Any", client_exception_handler)
    app_config.exception_handlers = existing


def _make_db_session_provide(
    session_maker: async_sessionmaker[AsyncSession],
) -> Callable[[State, Scope], AsyncSession]:
    """Build a sync dependency callable matching Advanced Alchemy ``provide_session`` semantics.

    Returns:
        Callable taking ``(state, scope)`` and returning the shared request ``AsyncSession``.
    """

    def provide_db_session(state: State, scope: Scope) -> AsyncSession:
        return get_or_create_scoped_session(state, scope, session_maker)

    return provide_db_session


def _make_user_manager_dependency_provider(
    build_user_manager: Callable[[AsyncSession], Any],
    db_session_key: str,
) -> Callable[..., AsyncGenerator[Any, None]]:
    """Build Litestar DI async generator: one ``BaseUserManager`` per injected ``AsyncSession``.

    The async generator parameter name matches ``db_session_key`` so Litestar injects the
    same session registered under ``LitestarAuthConfig.db_session_dependency_key``.

    Args:
        build_user_manager: Callable that builds a manager for a request session (typically
            ``LitestarAuth._build_user_manager`` bound to the plugin).
        db_session_key: Dependency key / Python parameter name (must be a valid identifier).

    Returns:
        Async generator dependency suitable for ``Provide`` (``use_cache=False``).

    Note:
        ``db_session_key`` must be validated by :meth:`LitestarAuthConfig.__post_init__` before this
        runs; invalid keys are rejected at configuration construction time.
    """
    missing = object()

    async def _provide_user_manager(
        session: object = missing,
        /,
        **dependencies: object,
    ) -> AsyncGenerator[Any, None]:
        if False:  # pragma: no cover
            await asyncio.sleep(0)
        if session is not missing:
            if dependencies:
                msg = f"_provide_user_manager() got multiple values for argument {db_session_key!r}"
                raise TypeError(msg)
            yield build_user_manager(cast("AsyncSession", session))
            return

        if len(dependencies) != 1 or db_session_key not in dependencies:
            if not dependencies:
                msg = f"_provide_user_manager() missing 1 required argument: {db_session_key!r}"
            else:
                unexpected = ", ".join(sorted(repr(name) for name in dependencies))
                msg = f"_provide_user_manager() got unexpected keyword argument(s): {unexpected}"
            raise TypeError(msg)

        yield build_user_manager(cast("AsyncSession", dependencies[db_session_key]))

    provider_fn = cast("Any", _provide_user_manager)
    provider_fn.__signature__ = inspect.Signature(
        parameters=(
            inspect.Parameter(
                db_session_key,
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Any,
            ),
        ),
    )
    provider_fn.__annotations__ = {db_session_key: "Any"}
    # Litestar resolves forward references from the defining module; keep metadata stable.
    provider_fn.__module__ = __name__
    provider_fn.__qualname__ = "_make_user_manager_dependency_provider.<locals>._provide_user_manager"
    return cast("Callable[..., AsyncGenerator[Any, None]]", provider_fn)


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
    oauth_config = config.oauth_config
    if oauth_config is not None and oauth_config.include_oauth_associate and oauth_config.oauth_associate_providers:
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
        else:
            app_config.dependencies[key] = _to_dependency_provider(provider)

    if config.session_maker is not None and not config.db_session_dependency_provided_externally:
        app_config.before_send.append(async_autocommit_handler_maker())


def _to_dependency_provider(provider: object) -> Provide:
    """Wrap dependency callables in explicit Litestar providers.

    Returns:
        Litestar provider configured with caching when the callable is not a generator dependency.
    """
    use_cache = not inspect.isasyncgenfunction(provider)
    is_async = inspect.iscoroutinefunction(provider) or inspect.isasyncgenfunction(provider)
    if is_async:
        return Provide(cast("Any", provider), use_cache=use_cache)
    return Provide(cast("Any", provider), use_cache=use_cache, sync_to_thread=False)
