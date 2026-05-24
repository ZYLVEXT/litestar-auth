"""Dependency wiring for the auth plugin."""

from __future__ import annotations

import inspect
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from advanced_alchemy.extensions.litestar import async_autocommit_handler_maker
from litestar.datastructures.state import State
from litestar.di import Provide
from litestar.types import Scope
from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._plugin._hooks import iter_feature_wiring
from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
)
from litestar_auth._plugin.exception_handlers import (
    authorization_error_handler,  # noqa: F401
    client_exception_handler,  # noqa: F401
    register_exception_handlers,  # noqa: F401
)
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.scoped_session import (
    SESSION_SCOPE_KEY,
    SessionFactory,
    get_or_create_scoped_session,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_auth._plugin._protocols import DependencyProvider


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


@dataclass(frozen=True, slots=True)
class _DependencyRegistration:
    """Resolved dependency key and provider pair for app-config registration."""

    key: str
    provider: object


def _make_db_session_provide(
    session_maker: SessionFactory,
    *,
    session_scope_key: str,
) -> DbSessionProvider:
    def provide_db_session(state: State, scope: Scope) -> AsyncSession:
        return get_or_create_scoped_session(
            state,
            scope,
            session_maker,
            session_scope_key=session_scope_key,
        )

    return provide_db_session


def _resolve_session_scope_key[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> str:
    return config.session_scope_key if config.session_scope_key is not None else SESSION_SCOPE_KEY


def _make_dependency_signature(parameter_name: str) -> inspect.Signature:
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

    provider = cast("DependencyProvider", _provide_user_manager)
    provider.__signature__ = signature
    provider.__annotations__ = {
        db_session_key: Any,
        "return": AsyncGenerator[object, None],
    }
    setattr(_provide_user_manager, _RETURNS_ASYNC_GENERATOR_MARKER, True)
    return cast("Callable[..., AsyncGenerator[TManager, None]]", _provide_user_manager)


def _make_backends_dependency_provider[UP: UserProtocol[Any], ID](
    build_backends: Callable[[AsyncSession], Sequence[AuthenticationBackend[UP, ID]]],
    db_session_key: str,
) -> Callable[..., Sequence[AuthenticationBackend[UP, ID]]]:
    signature = _make_dependency_signature(db_session_key)

    def _provide_backends(*args: object, **kwargs: object) -> Sequence[AuthenticationBackend[Any, Any]]:
        session = _resolve_dependency_argument(
            _provide_backends.__name__,
            db_session_key,
            args,
            kwargs,
        )
        return build_backends(cast("AsyncSession", session))

    provider = cast("DependencyProvider", _provide_backends)
    provider.__signature__ = signature
    provider.__annotations__ = {
        db_session_key: Any,
        "return": Sequence[AuthenticationBackend[Any, Any]],
    }
    return cast("Callable[..., Sequence[AuthenticationBackend[UP, ID]]]", _provide_backends)


def _resolve_builtin_db_session_provider_factory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> SessionFactory | None:
    if config.db_session_dependency_provided_externally:
        return None
    return config.session_maker


def _wrap_registered_dependency[UP: UserProtocol[Any], ID](
    key: str,
    provider: object,
    *,
    config: LitestarAuthConfig[UP, ID],
) -> Provide:
    if key == config.db_session_dependency_key and _resolve_builtin_db_session_provider_factory(config) is not None:
        return Provide(
            cast("DependencyProvider", provider),
            sync_to_thread=False,
            use_cache=False,
        )
    if key == DEFAULT_BACKENDS_DEPENDENCY_KEY:
        return _to_dependency_provider(provider, use_cache=False)
    return _to_dependency_provider(provider)


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
    dependency_registrations = tuple(_iter_dependency_registrations(config, providers=providers))
    dependency_keys = tuple(registration.key for registration in dependency_registrations)
    collisions = sorted(set(dependency_keys).intersection(app_config.dependencies))
    if collisions:
        msg = f"Auth dependency keys already exist: {', '.join(collisions)}"
        raise ValueError(msg)

    for registration in dependency_registrations:
        app_config.dependencies[registration.key] = _wrap_registered_dependency(
            registration.key,
            registration.provider,
            config=config,
        )

    session_maker = _resolve_builtin_db_session_provider_factory(config)
    if session_maker is not None:
        app_config.before_send.append(
            async_autocommit_handler_maker(session_scope_key=_resolve_session_scope_key(config)),
        )


def _iter_dependency_registrations[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    providers: DependencyProviders,
) -> tuple[_DependencyRegistration, ...]:
    registrations: list[_DependencyRegistration] = []
    for wiring in iter_feature_wiring(config):
        for provider_name in wiring.dependency_providers:
            registration = _resolve_dependency_registration(provider_name, config=config, providers=providers)
            if registration is not None:
                registrations.append(registration)
    return tuple(registrations)


def _resolve_dependency_registration[UP: UserProtocol[Any], ID](
    provider_name: str,
    *,
    config: LitestarAuthConfig[UP, ID],
    providers: DependencyProviders,
) -> _DependencyRegistration | None:
    static_registrations = {
        "config": _DependencyRegistration(DEFAULT_CONFIG_DEPENDENCY_KEY, providers.config),
        "user_manager": _DependencyRegistration(DEFAULT_USER_MANAGER_DEPENDENCY_KEY, providers.user_manager),
        "backends": _DependencyRegistration(DEFAULT_BACKENDS_DEPENDENCY_KEY, providers.backends),
        "user_model": _DependencyRegistration(DEFAULT_USER_MODEL_DEPENDENCY_KEY, providers.user_model),
    }
    static_registration = static_registrations.get(provider_name)
    if static_registration is not None:
        return static_registration
    if provider_name == "db_session":
        session_maker = _resolve_builtin_db_session_provider_factory(config)
        if session_maker is None:
            return None
        return _DependencyRegistration(
            config.db_session_dependency_key,
            _make_db_session_provide(
                session_maker,
                session_scope_key=_resolve_session_scope_key(config),
            ),
        )
    if provider_name == "oauth_associate_user_manager":
        oauth_contract = _build_oauth_route_registration_contract(
            auth_path=config.auth_path,
            oauth_config=config.oauth_config,
        )
        if not oauth_contract.has_plugin_owned_associate_routes:
            return None
        return _DependencyRegistration(
            OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
            providers.oauth_associate_user_manager,
        )
    msg = f"Unknown auth dependency provider wiring: {provider_name}"
    raise RuntimeError(msg)


def _to_dependency_provider(provider: object, *, use_cache: bool | None = None) -> Provide:
    returns_async_generator = inspect.isasyncgenfunction(provider) or bool(
        getattr(provider, _RETURNS_ASYNC_GENERATOR_MARKER, False),
    )
    effective_use_cache = not returns_async_generator if use_cache is None else use_cache
    is_async = inspect.iscoroutinefunction(provider) or inspect.isasyncgenfunction(provider)
    if is_async:
        return Provide(cast("DependencyProvider", provider), use_cache=effective_use_cache)
    dependency_provider = Provide(
        cast("DependencyProvider", provider),
        use_cache=effective_use_cache,
        sync_to_thread=False,
    )
    if returns_async_generator:
        dependency_provider.has_async_generator_dependency = True
    return dependency_provider
