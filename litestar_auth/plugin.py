"""Litestar plugin/orchestrator facade for wiring the auth library into an app."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, override

from litestar.middleware import DefineMiddleware
from litestar.plugins import CLIPlugin, InitPlugin

from litestar_auth._plugin import config as _plugin_config
from litestar_auth._plugin._hooks import iter_feature_wiring
from litestar_auth._plugin.advanced_alchemy import (
    AlchemyAuthSessionBinding,
    bind_auth_session_to_alchemy,
)
from litestar_auth._plugin.controllers import (
    build_controllers,
)
from litestar_auth._plugin.dependencies import (
    DependencyProviders,
    _make_backends_dependency_provider,
    _make_user_manager_dependency_provider,
    _resolve_session_scope_key,
    register_dependencies,
)
from litestar_auth._plugin.exception_handlers import register_exception_handlers
from litestar_auth._plugin.middleware import build_csrf_config, get_cookie_transports, has_api_key_transport
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session
from litestar_auth._plugin.session_binding import (
    _AccountStateValidator as PluginAccountStateValidator,
)
from litestar_auth._plugin.session_binding import (
    _ScopedUserDatabaseProxy as ScopedUserDatabaseProxyImpl,
)
from litestar_auth._plugin.startup import (
    run_before_startup_wiring,
)
from litestar_auth._plugin.validation import (
    resolve_user_manager_account_state_validator,
    validate_config,
)
from litestar_auth.authentication import Authenticator, LitestarAuthMiddleware, LitestarAuthMiddlewareConfig
from litestar_auth.config import OAuthProviderConfig
from litestar_auth.oauth_encryption import (
    _build_oauth_token_encryption,
    require_oauth_token_encryption,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping, Sequence

    from litestar.cli._utils import Group
    from litestar.config.app import AppConfig
    from litestar.types import ControllerRouterHandler
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._manager.hooks import ExtensionManagerHookSubscriber
    from litestar_auth._plugin.extensions import ExtensionRegistrationContext, ExtensionRegistrationContributions
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

ApiKeyConfig = _plugin_config.ApiKeyConfig
DatabaseTokenAuthConfig = _plugin_config.DatabaseTokenAuthConfig
ControllerHook = _plugin_config.ControllerHook
ExceptionResponseHook = _plugin_config.ExceptionResponseHook
LitestarAuthConfig = _plugin_config.LitestarAuthConfig
MiddlewareHook = _plugin_config.MiddlewareHook
OAuthConfig = _plugin_config.OAuthConfig
OrganizationConfig = _plugin_config.OrganizationConfig
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
        self._session_scope_key = _resolve_session_scope_key(self.config)
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
        self._extension_registration_context: ExtensionRegistrationContext[UP, ID] | None = None
        self._manager_hook_subscribers: tuple[ExtensionManagerHookSubscriber, ...] = ()

    @override
    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Register auth middleware, controllers, and dependencies on the app.

        Returns:
            The updated application config.
        """
        run_before_startup_wiring(
            config=self.config,
            app_config=app_config,
            require_oauth_key=partial(require_oauth_token_encryption, self._oauth_token_encryption),
        )
        self._run_after_startup_wiring(app_config)
        return app_config

    @override
    def on_cli_init(self, cli: Group) -> None:
        """Register plugin-owned CLI commands without affecting app startup wiring."""
        from litestar_auth._plugin.extensions import (  # noqa: PLC0415
            build_extension_validation_context,
            resolve_version_gated_extensions,
        )
        from litestar_auth._plugin.role_cli import register_roles_cli  # noqa: PLC0415
        from litestar_auth.extensions import AuthCliExtension  # noqa: PLC0415

        extensions = resolve_version_gated_extensions(self.config)
        validation_context = build_extension_validation_context(self.config)
        cli_extensions = tuple(extension for extension in extensions if isinstance(extension, AuthCliExtension))
        for extension in cli_extensions:
            extension.validate(validation_context)

        register_roles_cli(cli, self.config)
        for extension in cli_extensions:
            extension.register_cli(cli, self.config)

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
        manager = self._user_manager_factory(
            session=session,
            user_db=user_db,
            config=self.config,
            backends=bound_backends,
        )
        self._attach_extension_manager_hook_subscribers(manager)
        return manager

    def _attach_extension_manager_hook_subscribers(self, manager: BaseUserManager[UP, ID]) -> None:
        from litestar_auth._plugin.user_manager_builder import (  # noqa: PLC0415
            attach_extension_manager_hook_subscribers,
        )

        attach_extension_manager_hook_subscribers(manager, self._manager_hook_subscribers)

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

        backend_inventory = self.config.resolve_feature_registry().backend_inventory
        schemes = register_openapi_security(app_config, backend_inventory.startup_backends())
        self._register_extension_openapi_security(app_config, core_security_scheme_names=schemes.keys())
        return build_security_requirement(schemes) or None

    def _register_controllers(
        self,
        app_config: AppConfig,
        *,
        security: list[dict[str, list[str]]] | None = None,
    ) -> list[ControllerRouterHandler]:
        controllers = [*build_controllers(self.config, security=security), *self._build_extension_controllers()]
        if self.config.controller_hook is not None:
            controllers = self.config.controller_hook(controllers)
        app_config.route_handlers.extend(controllers)
        return controllers

    def _register_exception_handlers(self, route_handlers: Sequence[ControllerRouterHandler]) -> None:
        """Register ClientException handlers for litestar-auth-generated routes only."""
        self._register_extension_exception_handlers()
        register_exception_handlers(
            route_handlers,
            exception_response_hook=self.config.exception_response_hook,
        )

    def _run_after_startup_wiring(self, app_config: AppConfig) -> None:
        """Run app-config wiring phases in descriptor order.

        Raises:
            RuntimeError: If the wiring table names an unknown app-init hook.
        """
        security: list[dict[str, list[str]]] | None = None

        def register_openapi_security() -> None:
            nonlocal security
            security = self._register_openapi_security(app_config)

        def register_controllers() -> None:
            self._register_controllers(app_config, security=security)

        app_init_phases: Mapping[str, Callable[[], None]] = {
            "register_extensions": lambda: self._register_extensions(app_config),
            "register_dependencies": lambda: self._register_dependencies(app_config),
            "register_middleware": lambda: self._register_middleware(app_config),
            "register_openapi_security": register_openapi_security,
            "register_controllers": register_controllers,
        }
        exception_handler_phases: Mapping[str, Callable[[], None]] = {
            "register_exception_handlers": lambda: self._register_exception_handlers(app_config.route_handlers),
        }
        for wiring in iter_feature_wiring(self.config):
            for hook_name in wiring.after_startup:
                phase = app_init_phases.get(hook_name)
                if phase is None:
                    msg = f"Unknown auth app-init wiring hook: {hook_name}"
                    raise RuntimeError(msg)
                phase()

            for hook_name in wiring.exception_handlers:
                phase = exception_handler_phases.get(hook_name)
                if phase is None:
                    msg = f"Unknown auth exception-handler wiring hook: {hook_name}"
                    raise RuntimeError(msg)
                phase()

    def _register_dependencies(self, app_config: AppConfig) -> None:
        contributions = self._extension_contributions()
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
            extension_dependencies=contributions.dependencies,
        )

    def _register_middleware(self, app_config: AppConfig) -> None:
        backend_inventory = self.config.resolve_feature_registry().backend_inventory
        startup_backends = backend_inventory.startup_backends()
        cookie_transports = get_cookie_transports(startup_backends)
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
                get_request_session=partial(
                    get_or_create_scoped_session,
                    session_maker=self._session_maker,
                    session_scope_key=self._session_scope_key,
                ),
                authenticator_factory=self._build_authenticator,
                auth_cookie_names=auth_cookie_names,
                api_key_use_rate_limit=(
                    self.config.rate_limit_config.api_key_use if self.config.rate_limit_config is not None else None
                ),
                api_key_backend_present=has_api_key_transport(startup_backends),
                api_key_signed_body_max_bytes=self.config.api_keys.signed_body_max_bytes,
                api_key_signed_body_max_messages=self.config.api_keys.signed_body_max_messages,
                superuser_role_name=self.config.superuser_role_name,
                permission_resolver=self.config.resolve_permission_resolver(),
                organization_store_factory=(
                    self.config.organization_config.store_factory if self.config.organization_config.enabled else None
                ),
                tenant_resolver=(
                    self.config.organization_config.tenant_resolver if self.config.organization_config.enabled else None
                ),
            ),
        )
        if self.config.middleware_hook is not None:
            middleware = self.config.middleware_hook(middleware)
        app_config.middleware.insert(0, middleware)
        self._register_extension_middleware(app_config, after_index=1)

    def _register_extensions(self, app_config: AppConfig) -> None:
        from litestar_auth._plugin.extensions import register_extensions  # noqa: PLC0415

        self._extension_registration_context = register_extensions(app_config=app_config, config=self.config)
        self._manager_hook_subscribers = tuple(
            self._extension_registration_context.contributions.manager_hook_subscribers,
        )

    def _extension_contributions(self) -> ExtensionRegistrationContributions:
        from litestar_auth._plugin.extensions import ExtensionRegistrationContributions  # noqa: PLC0415

        if self._extension_registration_context is None:
            return ExtensionRegistrationContributions()
        return self._extension_registration_context.contributions

    def _register_extension_middleware(self, app_config: AppConfig, *, after_index: int) -> None:
        from litestar_auth._plugin.extensions import apply_extension_middleware  # noqa: PLC0415

        apply_extension_middleware(
            app_config,
            contributions=self._extension_contributions(),
            after_index=after_index,
        )

    def _register_extension_openapi_security(
        self,
        app_config: AppConfig,
        *,
        core_security_scheme_names: Collection[str] = (),
    ) -> dict[str, object]:
        from litestar_auth._plugin.extensions import register_extension_openapi_security  # noqa: PLC0415

        return register_extension_openapi_security(
            app_config,
            contributions=self._extension_contributions(),
            core_security_scheme_names=core_security_scheme_names,
        )

    def _build_extension_controllers(self) -> list[ControllerRouterHandler]:
        from litestar_auth._plugin.extensions import build_extension_controllers  # noqa: PLC0415

        return build_extension_controllers(contributions=self._extension_contributions())

    def _register_extension_exception_handlers(self) -> None:
        if self._extension_registration_context is None:
            return
        from litestar_auth._plugin.extensions import register_extension_exception_handlers  # noqa: PLC0415

        register_extension_exception_handlers(
            self._extension_registration_context.app_config,
            contributions=self._extension_contributions(),
        )

    def _provide_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        return self.config.resolve_feature_registry().startup_backends()

    def _provide_config(self) -> object:
        return self.config

    def _provide_user_model(self) -> object:
        return self.config.user_model

    def _totp_backend(self) -> StartupBackendTemplate[UP, ID]:
        backend_inventory = self.config.resolve_feature_registry().backend_inventory
        from litestar_auth._plugin.totp_controller import totp_backend  # noqa: PLC0415

        return totp_backend(self.config, backend_inventory=backend_inventory)


__all__ = (
    "AlchemyAuthSessionBinding",
    "ApiKeyConfig",
    "DatabaseTokenAuthConfig",
    "FernetKeyringConfig",
    "LitestarAuth",
    "LitestarAuthConfig",
    "OAuthConfig",
    "OAuthProviderConfig",
    "OrganizationConfig",
    "StartupBackendTemplate",
    "TotpConfig",
    "bind_auth_session_to_alchemy",
)
