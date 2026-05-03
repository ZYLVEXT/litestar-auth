"""Litestar plugin/orchestrator facade for wiring the auth library into an app."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, override

from litestar.middleware import DefineMiddleware
from litestar.plugins import CLIPlugin, InitPlugin

from litestar_auth._plugin import config as _plugin_config
from litestar_auth._plugin.controllers import (
    build_controllers,
    totp_backend,
)
from litestar_auth._plugin.dependencies import (
    DependencyProviders,
    _make_backends_dependency_provider,
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
    require_refreshable_strategy_when_enable_refresh,
    require_secure_oauth_redirect_in_production,
    require_shared_rate_limit_backends_for_multiworker,
    warn_insecure_plugin_startup_defaults,
)
from litestar_auth._plugin.validation import (
    resolve_user_manager_account_state_validator,
    validate_config,
)
from litestar_auth.authentication import Authenticator, LitestarAuthMiddleware, LitestarAuthMiddlewareConfig
from litestar_auth.config import OAuthProviderConfig
from litestar_auth.oauth_encryption import (
    OAuthTokenEncryption,
    require_oauth_token_encryption,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.cli._utils import Group
    from litestar.config.app import AppConfig
    from litestar.types import ControllerRouterHandler
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

from litestar_auth.manager import FernetKeyringConfig

DatabaseTokenAuthConfig = _plugin_config.DatabaseTokenAuthConfig
ControllerHook = _plugin_config.ControllerHook
ExceptionResponseHook = _plugin_config.ExceptionResponseHook
LitestarAuthConfig = _plugin_config.LitestarAuthConfig
MiddlewareHook = _plugin_config.MiddlewareHook
OAuthConfig = _plugin_config.OAuthConfig
StartupBackendTemplate = _plugin_config.StartupBackendTemplate
TotpConfig = _plugin_config.TotpConfig


class LitestarAuth[UP: UserProtocol[Any], ID](InitPlugin, CLIPlugin):
    """Main auth orchestrator that wires middleware, controllers, and DI."""

    def __init__(self, config: LitestarAuthConfig[UP, ID]) -> None:
        """Store the plugin configuration and validate the requested setup.

        Args:
            config: Fully specified plugin configuration (session factory, backends,
                user manager factory, optional OAuth/TOTP settings).
        """
        self.config = config
        self._oauth_token_encryption = _build_oauth_token_encryption(self.config)
        validate_config(self.config)
        self._session_maker = _plugin_config.require_session_maker(self.config)
        from litestar_auth._plugin.user_manager_builder import resolve_user_manager_factory  # noqa: PLC0415

        self._user_manager_factory = resolve_user_manager_factory(self.config)
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
        require_shared_rate_limit_backends_for_multiworker(self.config)
        require_refreshable_strategy_when_enable_refresh(self.config)
        warn_insecure_plugin_startup_defaults(self.config)
        require_oauth_token_encryption_for_configured_providers(
            config=self.config,
            require_key=partial(require_oauth_token_encryption, self._oauth_token_encryption),
        )
        require_secure_oauth_redirect_in_production(config=self.config, app_config=app_config)
        bootstrap_bundled_token_orm_models(self.config)
        self._register_dependencies(app_config)
        self._register_middleware(app_config)
        security = self._register_openapi_security(app_config)
        self._register_controllers(app_config, security=security)
        self._register_exception_handlers(app_config.route_handlers)
        return app_config

    @override
    def on_cli_init(self, cli: Group) -> None:
        """Register plugin-owned CLI commands without affecting app startup wiring."""
        from litestar_auth._plugin.role_cli import register_roles_cli  # noqa: PLC0415

        register_roles_cli(cli, self.config)

    def _session_bound_backends(self, session: AsyncSession) -> list[AuthenticationBackend[UP, ID]]:
        """Bind all configured backends to the current request-local DB session.

        Returns:
            Backends rebound to the provided request-local session.
        """
        return list(self.config.resolve_backends(session))

    def _build_user_manager(
        self,
        session: AsyncSession,
        *,
        backends: Sequence[AuthenticationBackend[UP, ID]] | None = None,
    ) -> BaseUserManager[UP, ID]:
        user_db_factory = self.config.resolve_user_db_factory()
        user_db = ScopedUserDatabaseProxyImpl(
            user_db_factory(session),
            oauth_token_encryption=self._oauth_token_encryption,
        )
        bound_backends = tuple(backends or self._session_bound_backends(session))
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
        """Return the configured manager-class account-state validator contract."""
        return resolve_user_manager_account_state_validator(self.config.user_manager_class)

    def _register_openapi_security(
        self,
        app_config: AppConfig,
    ) -> list[dict[str, list[str]]] | None:
        """Register OpenAPI security schemes and return the security requirement.

        Returns:
            Security requirement list for annotating guarded routes, or ``None``
            when OpenAPI security is disabled or unavailable.
        """
        if not self.config.include_openapi_security:
            return None
        from litestar_auth._plugin.openapi import build_security_requirement, register_openapi_security  # noqa: PLC0415

        backend_inventory = _plugin_config.resolve_backend_inventory(self.config)
        schemes = register_openapi_security(app_config, backend_inventory.startup_backends())
        return build_security_requirement(schemes) or None

    def _register_controllers(
        self,
        app_config: AppConfig,
        *,
        security: list[dict[str, list[str]]] | None = None,
    ) -> list[ControllerRouterHandler]:
        controllers = build_controllers(self.config, security=security)
        if self.config.controller_hook is not None:
            controllers = self.config.controller_hook(controllers)
        app_config.route_handlers.extend(controllers)
        return controllers

    def _register_exception_handlers(self, route_handlers: Sequence[ControllerRouterHandler]) -> None:
        """Register ClientException handlers for litestar-auth-generated routes only."""
        register_exception_handlers(
            route_handlers,
            exception_response_hook=self.config.exception_response_hook,
        )

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
        backend_inventory = _plugin_config.resolve_backend_inventory(self.config)
        cookie_transports = get_cookie_transports(backend_inventory.startup_backends())
        if cookie_transports:
            app_config.csrf_config = build_csrf_config(self.config, cookie_transports)

        auth_cookie_names = frozenset(
            {
                *(transport.cookie_name.encode() for transport in cookie_transports),
                *(transport.refresh_cookie_name.encode() for transport in cookie_transports),
            },
        )
        middleware = DefineMiddleware(
            LitestarAuthMiddleware[UP, ID],
            config=LitestarAuthMiddlewareConfig[UP, ID](
                get_request_session=partial(get_or_create_scoped_session, session_maker=self._session_maker),
                authenticator_factory=self._build_authenticator,
                auth_cookie_names=auth_cookie_names,
                superuser_role_name=self.config.superuser_role_name,
            ),
        )
        if self.config.middleware_hook is not None:
            middleware = self.config.middleware_hook(middleware)
        app_config.middleware.insert(0, middleware)

    def _provide_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        return _plugin_config.resolve_backend_inventory(self.config).startup_backends()

    def _provide_config(self) -> object:
        return self.config

    def _provide_user_model(self) -> object:
        return self.config.user_model

    def _totp_backend(self) -> StartupBackendTemplate[UP, ID]:
        backend_inventory = _plugin_config.resolve_backend_inventory(self.config)
        return totp_backend(self.config, backend_inventory=backend_inventory)


__all__ = (
    "DatabaseTokenAuthConfig",
    "FernetKeyringConfig",
    "LitestarAuth",
    "LitestarAuthConfig",
    "OAuthConfig",
    "OAuthProviderConfig",
    "StartupBackendTemplate",
    "TotpConfig",
)


def _build_oauth_token_encryption[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> OAuthTokenEncryption | None:
    """Return the plugin-scoped OAuth token encryption policy for a config."""
    oauth_config = config.oauth_config
    if oauth_config is None:
        return None
    keyring = oauth_config.oauth_token_encryption_keyring
    if keyring is not None:
        return OAuthTokenEncryption(
            unsafe_testing=config.unsafe_testing,
            active_key_id=keyring.active_key_id,
            keys=keyring.keys,
        )
    return OAuthTokenEncryption(
        oauth_config.oauth_token_encryption_key,
        unsafe_testing=config.unsafe_testing,
    )
