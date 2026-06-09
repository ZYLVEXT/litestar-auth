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

from litestar_auth._current_organization import read_scope_current_organization_context
from litestar_auth._permissions import resolve_connection_permissions
from litestar_auth._plugin._hooks import iter_feature_wiring
from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
    DEFAULT_DB_SESSION_DEPENDENCY_KEY,
    DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
    DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
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
    from litestar.connection import ASGIConnection

    from litestar_auth._plugin._protocols import DependencyProvider
    from litestar_auth._plugin.extensions import ExtensionDependencyContribution
    from litestar_auth.db import BaseOrganizationStore


type DbSessionProvider = Callable[[State, Scope], AsyncSession]
_RETURNS_ASYNC_GENERATOR_MARKER = "__litestar_auth_returns_async_generator__"
_NON_OVERRIDABLE_EXTENSION_DEPENDENCY_KEYS = frozenset(
    (
        DEFAULT_CONFIG_DEPENDENCY_KEY,
        DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        DEFAULT_BACKENDS_DEPENDENCY_KEY,
        OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
        DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
        DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
        DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
    ),
)


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


def _make_organization_store_dependency_provider(
    store_factory: Callable[[AsyncSession], BaseOrganizationStore[Any, Any, Any, Any]],
    db_session_key: str,
) -> Callable[..., BaseOrganizationStore[Any, Any, Any, Any]]:
    signature = _make_dependency_signature(db_session_key)

    def _provide_organization_store(*args: object, **kwargs: object) -> BaseOrganizationStore[Any, Any, Any, Any]:
        session = _resolve_dependency_argument(
            _provide_organization_store.__name__,
            db_session_key,
            args,
            kwargs,
        )
        return store_factory(cast("AsyncSession", session))

    provider = cast("DependencyProvider", _provide_organization_store)
    provider.__signature__ = signature
    provider.__annotations__ = {
        db_session_key: Any,
        "return": Any,
    }
    return _provide_organization_store


def provide_resolved_permissions(request: ASGIConnection[Any, Any, Any, Any]) -> frozenset[str]:
    """Return the authenticated request user's effective permission set.

    Returns:
        Normalized permissions from the request-scope resolver, or an empty set
        for anonymous requests.
    """
    return resolve_connection_permissions(request)


def provide_current_organization(request: ASGIConnection[Any, Any, Any, Any]) -> object | None:
    """Return the request's verified current organization context, if any.

    Returns:
        The middleware-published current organization context for authenticated
        member requests, or ``None`` when no verified organization is available.
    """
    return read_scope_current_organization_context(request)


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
    extension_dependencies: Sequence[ExtensionDependencyContribution] = (),
) -> None:
    """Register plugin dependency providers and guard against key collisions.

    Raises:
        ValueError: If dependency keys collide without an explicit override.
    """
    dependency_registrations = tuple(_iter_dependency_registrations(config, providers=providers))
    dependency_keys = tuple(registration.key for registration in dependency_registrations)
    collisions = sorted(set(dependency_keys).intersection(app_config.dependencies))
    if collisions:
        msg = f"Auth dependency keys already exist: {', '.join(collisions)}"
        raise ValueError(msg)

    _validate_extension_dependency_contributions(
        app_config,
        config=config,
        dependency_keys=dependency_keys,
        extension_dependencies=extension_dependencies,
    )

    for registration in dependency_registrations:
        app_config.dependencies[registration.key] = _wrap_registered_dependency(
            registration.key,
            registration.provider,
            config=config,
        )

    for contribution in extension_dependencies:
        app_config.dependencies[contribution.key] = _wrap_registered_dependency(
            contribution.key,
            contribution.provider,
            config=config,
        )

    session_maker = _resolve_builtin_db_session_provider_factory(config)
    if session_maker is not None:
        app_config.before_send.append(
            async_autocommit_handler_maker(session_scope_key=_resolve_session_scope_key(config)),
        )


def _validate_extension_dependency_contributions(
    app_config: AppConfig,
    *,
    config: LitestarAuthConfig[Any, Any],
    dependency_keys: Sequence[str],
    extension_dependencies: Sequence[ExtensionDependencyContribution],
) -> None:
    seen_extension_keys: dict[str, str] = {}
    core_dependency_keys = _reserved_dependency_keys(config, dependency_keys=dependency_keys)

    for contribution in extension_dependencies:
        previous_extension_name = seen_extension_keys.get(contribution.key)
        if previous_extension_name is not None:
            msg = (
                "Auth extension dependency key "
                f"{contribution.key!r} from extension {contribution.extension_name!r} conflicts with extension "
                f"{previous_extension_name!r}."
            )
            raise ValueError(msg)
        seen_extension_keys[contribution.key] = contribution.extension_name

        if contribution.key in _NON_OVERRIDABLE_EXTENSION_DEPENDENCY_KEYS:
            msg = (
                "Auth extension dependency key "
                f"{contribution.key!r} from extension {contribution.extension_name!r} cannot override an "
                "authentication- or authorization-critical core auth dependency key."
            )
            raise ValueError(msg)

        if contribution.allow_override:
            continue

        if contribution.key in core_dependency_keys:
            msg = (
                "Auth extension dependency key "
                f"{contribution.key!r} from extension {contribution.extension_name!r} conflicts with a core auth "
                "dependency key. Set allow_override=True to replace it explicitly."
            )
            raise ValueError(msg)

        if contribution.key in app_config.dependencies:
            msg = f"Auth dependency keys already exist: {contribution.key}"
            raise ValueError(msg)


def _reserved_dependency_keys[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    dependency_keys: Sequence[str],
) -> frozenset[str]:
    return frozenset(
        (
            *dependency_keys,
            DEFAULT_CONFIG_DEPENDENCY_KEY,
            DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
            DEFAULT_BACKENDS_DEPENDENCY_KEY,
            DEFAULT_USER_MODEL_DEPENDENCY_KEY,
            DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
            DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
            DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
            config.db_session_dependency_key or DEFAULT_DB_SESSION_DEPENDENCY_KEY,
        ),
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
        "resolved_permissions": _DependencyRegistration(
            DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
            provide_resolved_permissions,
        ),
        "current_organization": _DependencyRegistration(
            DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
            provide_current_organization,
        ),
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
    if provider_name == "organization_store":
        return _resolve_organization_store_registration(config)
    msg = f"Unknown auth dependency provider wiring: {provider_name}"
    raise RuntimeError(msg)


def _resolve_organization_store_registration[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _DependencyRegistration | None:
    organization_config = config.organization_config
    if (
        not organization_config.enabled
        or not (
            organization_config.include_switch_organization
            or organization_config.include_organization_admin
            or organization_config.include_organization_invitations
        )
        or organization_config.store_factory is None
    ):
        return None
    return _DependencyRegistration(
        DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY,
        _make_organization_store_dependency_provider(
            organization_config.store_factory,
            config.db_session_dependency_key,
        ),
    )


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
