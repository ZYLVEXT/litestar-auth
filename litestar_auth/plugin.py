"""Litestar plugin/orchestrator facade for wiring the auth library into an app."""

from __future__ import annotations

import inspect
from functools import partial
from typing import TYPE_CHECKING, Any, cast, override

from litestar.middleware import DefineMiddleware
from litestar.plugins import InitPlugin

from litestar_auth._plugin import config as _plugin_config
from litestar_auth._plugin.controllers import (
    build_controllers,
    totp_backend,
)
from litestar_auth._plugin.dependencies import (
    DependencyProviders,
    _make_user_manager_dependency_provider,
    register_dependencies,
    register_exception_handlers,
)
from litestar_auth._plugin.middleware import build_csrf_config, get_cookie_transports
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session
from litestar_auth._plugin.session_binding import (
    _AccountStateValidator as PluginAccountStateValidator,
)
from litestar_auth._plugin.session_binding import (
    _ScopedUserDatabaseProxy as ScopedUserDatabaseProxyImpl,
)
from litestar_auth._plugin.startup import (
    bootstrap_bundled_token_orm_models,
    require_oauth_token_encryption_for_configured_providers,
    warn_if_insecure_oauth_redirect_in_production,
    warn_insecure_plugin_startup_defaults,
)
from litestar_auth._plugin.validation import validate_config
from litestar_auth.authentication import Authenticator, LitestarAuthMiddleware
from litestar_auth.config import plugin_secret_role_warning_owner
from litestar_auth.oauth_encryption import (
    register_oauth_token_encryption_key,
    require_oauth_token_encryption_key,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.config.app import AppConfig
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.manager import BaseUserManager

    DEFAULT_CONFIG_DEPENDENCY_KEY = _plugin_config.DEFAULT_CONFIG_DEPENDENCY_KEY
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY = _plugin_config.DEFAULT_USER_MANAGER_DEPENDENCY_KEY
    DEFAULT_BACKENDS_DEPENDENCY_KEY = _plugin_config.DEFAULT_BACKENDS_DEPENDENCY_KEY
    DEFAULT_USER_MODEL_DEPENDENCY_KEY = _plugin_config.DEFAULT_USER_MODEL_DEPENDENCY_KEY
    DEFAULT_CSRF_COOKIE_NAME = _plugin_config.DEFAULT_CSRF_COOKIE_NAME
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY = _plugin_config.OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY

    _ScopedUserDatabaseProxy = ScopedUserDatabaseProxyImpl

LitestarAuthConfig = _plugin_config.LitestarAuthConfig
OAuthConfig = _plugin_config.OAuthConfig
TotpConfig = _plugin_config.TotpConfig


class LitestarAuth[UP: UserProtocol[Any], ID](InitPlugin):
    """Main auth orchestrator that wires middleware, controllers, and DI."""

    def __init__(self, config: LitestarAuthConfig[UP, ID]) -> None:
        """Store the plugin configuration and validate the requested setup.

        Args:
            config: Fully specified plugin configuration (session factory, backends,
                user manager factory, optional OAuth/TOTP settings).
        """
        self.config = config
        oauth_token_encryption_key = (
            self.config.oauth_config.oauth_token_encryption_key if self.config.oauth_config is not None else None
        )
        register_oauth_token_encryption_key(self, oauth_token_encryption_key)
        validate_config(self.config)
        self._session_maker = _plugin_config.require_session_maker(self.config)
        self._user_manager_factory = _plugin_config.resolve_user_manager_factory(self.config)
        self._provide_user_manager = _make_user_manager_dependency_provider(
            self._build_user_manager,
            self.config.db_session_dependency_key,
        )
        self._provide_request_backends = _make_backends_dependency_provider(
            self._session_bound_backends,
            self.config.db_session_dependency_key,
        )
        self._provide_oauth_associate_user_manager = _make_user_manager_dependency_provider(
            self._build_user_manager,
            self.config.db_session_dependency_key,
        )

    @override
    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Register auth middleware, controllers, and dependencies on the app.

        Returns:
            The updated application config.
        """
        warn_insecure_plugin_startup_defaults(self.config)
        require_oauth_token_encryption_for_configured_providers(
            config=self.config,
            require_key=partial(require_oauth_token_encryption_key, self),
        )
        warn_if_insecure_oauth_redirect_in_production(config=self.config, app_config=app_config)
        bootstrap_bundled_token_orm_models(self.config)
        self._register_dependencies(app_config)
        self._register_middleware(app_config)
        self._register_controllers(app_config)
        self._register_exception_handlers(app_config)
        return app_config

    def _session_bound_backends(self, session: AsyncSession) -> list[AuthenticationBackend[UP, ID]]:
        """Bind all configured backends to the current request-local DB session.

        Returns:
            Backends rebound to the provided request-local session.
        """
        database_token_auth = self.config.database_token_auth
        if database_token_auth is not None:
            _plugin_config.bind_database_token_request_session(session)
            return [
                _plugin_config.build_database_token_backend(database_token_auth, session=session),
            ]

        return [backend.with_session(session) for backend in self.config.backends]

    def _build_user_manager(
        self,
        session: AsyncSession,
        *,
        backends: Sequence[AuthenticationBackend[UP, ID]] | None = None,
    ) -> BaseUserManager[UP, ID]:
        user_db_factory = self.config.user_db_factory
        if user_db_factory is None:  # pragma: no cover — __post_init__ always fills this
            msg = "user_db_factory must be set (filled by __post_init__)"
            raise TypeError(msg)
        user_db = ScopedUserDatabaseProxyImpl(user_db_factory(session), oauth_scope=self)
        manager_inputs = _plugin_config.ManagerConstructorInputs(
            manager_kwargs=self.config.user_manager_kwargs,
            manager_security=self.config.user_manager_security,
        )
        secret_inputs = manager_inputs.secret_inputs
        bound_backends = tuple(backends or self._session_bound_backends(session))
        # Plugin validation owns the config-managed warning baseline; manager construction
        # should only add a warning if a custom factory diverges from that secret surface.
        with plugin_secret_role_warning_owner(
            verification_token_secret=secret_inputs.verification_token_secret,
            reset_password_token_secret=secret_inputs.reset_password_token_secret,
            totp_secret_key=secret_inputs.totp_secret_key,
        ):
            return self._user_manager_factory(
                session=session,
                user_db=user_db,
                config=self.config,
                backends=bound_backends,
            )

    def _build_authenticator(self, session: AsyncSession) -> Authenticator[UP, ID]:
        backends = self._session_bound_backends(session)
        manager = self._build_user_manager(session, backends=backends)
        return Authenticator(backends, manager)

    def _resolve_account_state_validator(self) -> PluginAccountStateValidator[UP]:
        """Return the configured manager-class account-state validator.

        Uses ``getattr`` to obtain ``require_account_state`` from the
        manager class.  For ``BaseUserManager`` subclasses, this returns the
        static method (already unwrapped into a plain function by the
        descriptor protocol), which delegates to
        ``UserPolicy.require_account_state``.

        Raises:
            TypeError: If the configured manager class does not expose
                ``require_account_state()``.
        """
        manager_cls = self.config.user_manager_class
        validator = getattr(manager_cls, "require_account_state", None)
        if callable(validator):
            return validator

        msg = (
            f"{manager_cls.__name__!r} (user_manager_class) must expose "
            "require_account_state(user, *, require_verified=False). "
            "Subclass litestar_auth.manager.BaseUserManager for the default implementation, "
            "or define require_account_state on your manager class with the same contract."
        )
        raise TypeError(msg)

    def _register_controllers(self, app_config: AppConfig) -> None:
        app_config.route_handlers.extend(build_controllers(self.config))

    def _register_exception_handlers(self, app_config: AppConfig) -> None:  # noqa: PLR6301
        """Register ClientException handler for uniform detail and code response format."""
        register_exception_handlers(app_config)

    def _register_dependencies(self, app_config: AppConfig) -> None:
        register_dependencies(
            app_config,
            self.config,
            providers=DependencyProviders(
                config=self._provide_config,
                user_manager=self._provide_user_manager,
                backends=self._provide_request_backends,
                user_model=self._provide_user_model,
                oauth_associate_user_manager=self._provide_oauth_associate_user_manager,
            ),
        )

    def _register_middleware(self, app_config: AppConfig) -> None:
        cookie_transports = get_cookie_transports(self.config.backends)
        if cookie_transports:
            app_config.csrf_config = build_csrf_config(self.config, cookie_transports)

        auth_cookie_names = frozenset(
            {
                *(transport.cookie_name.encode() for transport in cookie_transports),
                *(transport.refresh_cookie_name.encode() for transport in cookie_transports),
            },
        )
        app_config.middleware.insert(
            0,
            DefineMiddleware(
                LitestarAuthMiddleware[UP, ID],
                get_request_session=partial(get_or_create_scoped_session, session_maker=self._session_maker),
                authenticator_factory=self._build_authenticator,
                auth_cookie_names=auth_cookie_names,
            ),
        )

    def _provide_backends(self) -> object:
        return self.config.backends

    def _provide_config(self) -> object:
        return self.config

    def _provide_user_model(self) -> object:
        return self.config.user_model

    def _totp_backend(self) -> AuthenticationBackend[UP, ID]:
        return totp_backend(self.config)


__all__ = (
    "LitestarAuth",
    "LitestarAuthConfig",
    "OAuthConfig",
    "TotpConfig",
)


def _make_backends_dependency_provider[UP: UserProtocol[Any], ID](
    build_backends: object,
    db_session_key: str,
) -> object:
    """Build a dependency provider that returns request-scoped backends for the active session.

    Returns:
        Callable dependency provider whose signature matches ``db_session_key``.
    """
    missing = object()

    def _provide_backends(
        session: object = missing,
        /,
        **dependencies: object,
    ) -> object:
        if session is not missing:
            if dependencies:
                msg = f"_provide_backends() got multiple values for argument {db_session_key!r}"
                raise TypeError(msg)
            return cast("Any", build_backends)(session)

        if len(dependencies) != 1 or db_session_key not in dependencies:
            if not dependencies:
                msg = f"_provide_backends() missing 1 required argument: {db_session_key!r}"
            else:
                unexpected = ", ".join(sorted(repr(name) for name in dependencies))
                msg = f"_provide_backends() got unexpected keyword argument(s): {unexpected}"
            raise TypeError(msg)

        return cast("Any", build_backends)(dependencies[db_session_key])

    provider_fn = cast("Any", _provide_backends)
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
    provider_fn.__module__ = __name__
    provider_fn.__qualname__ = "_make_backends_dependency_provider.<locals>._provide_backends"
    return provider_fn
