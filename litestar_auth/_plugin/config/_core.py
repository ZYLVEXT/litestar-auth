"""Configuration contracts for the plugin facade."""

from __future__ import annotations

from collections.abc import Callable, Mapping  # noqa: TC003
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from litestar_auth._permissions import StaticRolePermissionResolver
from litestar_auth._plugin import _hooks as _plugin_hooks
from litestar_auth._plugin import features as _features
from litestar_auth._plugin.config._defaults import ResolvedAuthConfigDefaults, _resolve_config_defaults
from litestar_auth._plugin.config._protocols import (  # noqa: TC001
    PasswordValidatorFactory,
    UserDatabaseFactory,
    UserManagerFactory,
)
from litestar_auth._plugin.config._resolvers import (
    _build_default_user_db,
    _normalize_config_superuser_role_name,
    _resolve_plugin_managed_totp_secret_storage_policy,
    require_session_maker,
    resolve_backend_inventory,
)
from litestar_auth._plugin.config._validation import _VALID_LOGIN_IDENTIFIERS, _ConfigValidationMixin
from litestar_auth._plugin.scoped_session import SessionFactory  # noqa: TC001
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME
from litestar_auth.config import UnsetType
from litestar_auth.controllers._response_timing import DEFAULT_MINIMUM_RESPONSE_SECONDS
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.types import (
    DbSessionDependencyKey,
    LoginIdentifier,
    PermissionResolver,
    UserProtocol,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    import msgspec
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy._jwt_denylist import JWTDenylistStore
    from litestar_auth.manager import BaseUserManager, UserManagerSecurity
    from litestar_auth.ratelimit import AuthRateLimitConfig

__all__ = (
    "_VALID_LOGIN_IDENTIFIERS",
    "ConfigurationError",
    "_normalize_config_superuser_role_name",
    "_resolve_plugin_managed_totp_secret_storage_policy",
    "require_session_maker",
    "resolve_backend_inventory",
)

DEFAULT_CONFIG_DEPENDENCY_KEY = "litestar_auth_config"
DEFAULT_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_user_manager"
DEFAULT_BACKENDS_DEPENDENCY_KEY = "litestar_auth_backends"
DEFAULT_USER_MODEL_DEPENDENCY_KEY = "litestar_auth_user_model"
DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY = "litestar_auth_permissions"
DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY = "litestar_auth_current_organization"
DEFAULT_ORGANIZATION_STORE_DEPENDENCY_KEY = "litestar_auth_organization_store"
DEFAULT_DB_SESSION_DEPENDENCY_KEY = "db_session"
DEFAULT_CSRF_COOKIE_NAME = "litestar_auth_csrf"
OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_oauth_associate_user_manager"
DEFAULT_DATABASE_TOKEN_BACKEND_NAME = _features.DEFAULT_DATABASE_TOKEN_BACKEND_NAME
DEFAULT_DATABASE_TOKEN_MAX_AGE = _features.DEFAULT_DATABASE_TOKEN_MAX_AGE
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = _features.DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
DEFAULT_DATABASE_TOKEN_BYTES = _features.DEFAULT_DATABASE_TOKEN_BYTES
DEFAULT_API_KEY_BACKEND_NAME = _features.DEFAULT_API_KEY_BACKEND_NAME
DEFAULT_API_KEY_TTL = _features.DEFAULT_API_KEY_TTL
DEFAULT_API_KEY_MAX_KEYS_PER_USER = _features.DEFAULT_API_KEY_MAX_KEYS_PER_USER
DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS = _features.DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES = _features.DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS = DEFAULT_MINIMUM_RESPONSE_SECONDS
DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS = DEFAULT_MINIMUM_RESPONSE_SECONDS
DEFAULT_VERIFY_MINIMUM_RESPONSE_SECONDS = DEFAULT_MINIMUM_RESPONSE_SECONDS
DEFAULT_REQUEST_VERIFY_MINIMUM_RESPONSE_SECONDS = DEFAULT_MINIMUM_RESPONSE_SECONDS
DEFAULT_TOTP_STEPUP_TTL_SECONDS = _features.DEFAULT_TOTP_STEPUP_TTL_SECONDS
ApiKeyConfig = _features.ApiKeyConfig
DatabaseTokenAuthConfig = _features.DatabaseTokenAuthConfig
FeatureRegistry = _features.FeatureRegistry
OAuthConfig = _features.OAuthConfig
OrganizationConfig = _features.OrganizationConfig
ResolvedFeatureDefaults = _features.ResolvedFeatureDefaults
TotpConfig = _features.TotpConfig
TotpStepUpPolicyMode = _features.TotpStepUpPolicyMode
ControllerHook = _plugin_hooks.ControllerHook
ExceptionResponseHook = _plugin_hooks.ExceptionResponseHook
MiddlewareHook = _plugin_hooks.MiddlewareHook
StartupBackendInventory = _features.StartupBackendInventory
StartupBackendTemplate = _features.StartupBackendTemplate


@dataclass(slots=True)
class LitestarAuthConfig[UP: UserProtocol[Any], ID](_ConfigValidationMixin):
    """Configuration for the :class:`~litestar_auth.plugin.LitestarAuth` plugin.

    Field declarations below hold defaults and types for manager construction,
    authentication backends, plugin routes, optional TOTP/OAuth/API-key surfaces,
    request timing floors, OpenAPI security, and DB-session dependency injection.
    """

    user_model: type[UP]
    # Default path: concrete BaseUserManager subclass constructed by the plugin with the
    # default keyword-only surface (see "User Manager Customization" above).
    user_manager_class: type[BaseUserManager[UP, ID]] | None = None
    backends: Sequence[AuthenticationBackend[UP, ID]] = field(default_factory=tuple)
    database_token_auth: DatabaseTokenAuthConfig | None = None
    api_keys: ApiKeyConfig = field(default_factory=ApiKeyConfig)
    session_maker: SessionFactory | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] | None = None
    user_manager_security: UserManagerSecurity[ID] | None = None
    # Optional shared denylist (e.g. RedisJWTDenylistStore) that makes verify/reset
    # account tokens single-use server-side by consuming their ``jti`` on success.
    account_token_denylist_store: JWTDenylistStore | None = None
    password_validator_factory: PasswordValidatorFactory[UP, ID] | None = None
    # Advanced path: callable that fully constructs the manager per request. Use when the
    # constructor is not the default BaseUserManager surface or you need custom DI.
    user_manager_factory: UserManagerFactory[UP, ID] | None = None
    rate_limit_config: AuthRateLimitConfig | None = None
    exception_response_hook: ExceptionResponseHook | None = None
    middleware_hook: MiddlewareHook | None = None
    controller_hook: ControllerHook | None = None
    auth_path: str = "/auth"
    users_path: str = "/users"
    include_register: bool = True
    include_verify: bool = True
    include_reset_password: bool = True
    include_users: bool = False
    include_session_devices: bool = False
    include_openapi_security: bool = True
    enable_refresh: bool = False
    requires_verification: bool = True
    hard_delete: bool = False
    totp_config: TotpConfig | None = None
    totp_stepup_ttl_seconds: int = DEFAULT_TOTP_STEPUP_TTL_SECONDS
    totp_stepup_allow_recovery: bool = False
    totp_stepup_policy: dict[str, TotpStepUpPolicyMode] = field(default_factory=dict)
    oauth_config: OAuthConfig | None = None
    organization_config: OrganizationConfig = field(default_factory=OrganizationConfig)
    # Security: CSRF signing material should not be exposed by autogenerated repr output.
    csrf_secret: str | None = field(default=None, repr=False)
    csrf_header_name: str = "X-CSRF-Token"
    unsafe_testing: bool = False
    # Defense-in-depth against lower-tail registration timing enumeration. This is
    # independent of rate limiting and only pads after the normal side effects run.
    login_minimum_response_seconds: float = DEFAULT_LOGIN_MINIMUM_RESPONSE_SECONDS
    register_minimum_response_seconds: float = DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS
    verify_minimum_response_seconds: float = DEFAULT_VERIFY_MINIMUM_RESPONSE_SECONDS
    request_verify_minimum_response_seconds: float = DEFAULT_REQUEST_VERIFY_MINIMUM_RESPONSE_SECONDS
    deployment_worker_count: int | None = None
    id_parser: Callable[[str], ID] | None = None
    user_read_schema: type[msgspec.Struct] | None = None
    user_create_schema: type[msgspec.Struct] | None = None
    user_update_schema: type[msgspec.Struct] | None = None
    db_session_dependency_key: DbSessionDependencyKey = DEFAULT_DB_SESSION_DEPENDENCY_KEY
    db_session_dependency_provided_externally: bool = False
    session_scope_key: str | None = None
    """Advanced Alchemy scope key for request sessions.

    When omitted, LitestarAuth uses Advanced Alchemy's ``SESSION_SCOPE_KEY`` default.
    With ``SQLAlchemyPlugin``, set this to ``SQLAlchemyAsyncConfig.session_scope_key``
    (for example via :func:`~litestar_auth.plugin.bind_auth_session_to_alchemy`).
    """
    login_identifier: LoginIdentifier = "email"
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME
    role_permissions: Mapping[str, object] = field(default_factory=dict)
    permission_resolver: PermissionResolver | None = None
    _memoized_default_password_helper: PasswordHelper | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _feature_registry: FeatureRegistry[UP, ID] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def resolve_backends(
        self,
        session: AsyncSession,
    ) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return authentication backends bound to the current request session.

        This is the runtime backend accessor for every supported backend
        configuration. Use :meth:`resolve_startup_backends` only for plugin setup,
        validation, OpenAPI registration, and route assembly.

        Returns:
            Request-scoped backends aligned with the provided SQLAlchemy session.
        """
        return self.resolve_feature_registry().bind_request_backends(session)

    def resolve_startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return startup-only backends for plugin setup, validation, and route assembly.

        Returns:
            Startup-only backend templates for the current config.
        """
        return self.resolve_feature_registry().startup_backends()

    def resolve_feature_registry(self) -> FeatureRegistry[UP, ID]:
        """Return the cached canonical registry of enabled features and startup backends.

        Returns:
            Feature registry resolved from this config on first use.
        """
        if self._feature_registry is None:
            self._feature_registry = _features.resolve_feature_registry(self)
        return self._feature_registry

    def resolve_defaults(self) -> ResolvedAuthConfigDefaults[UP, ID]:
        """Return the canonical resolved-default snapshot for this config.

        Public dataclass fields keep explicit caller input, including ``None``
        values with product meaning. This snapshot is the startup-time view that
        normalizes omitted fallback targets to a typed unset marker once before
        plugin feature wiring consumes them.
        """
        return _resolve_config_defaults(self)

    def resolve_openapi_security_schemes(self) -> dict[str, SecurityScheme]:
        """Return OpenAPI security schemes derived from the configured auth backends.

        Use this helper when your application defines additional protected
        routes or manages OpenAPI registration manually.

        Returns:
            Mapping of backend name to OpenAPI security scheme.
        """
        from litestar_auth._plugin.openapi import build_openapi_security_schemes  # noqa: PLC0415

        return build_openapi_security_schemes(self.resolve_startup_backends())

    def resolve_openapi_security_requirements(self) -> list[SecurityRequirement]:
        """Return OpenAPI security requirements for app-owned protected routes.

        Pair the returned value with Litestar guards such as
        ``guards=[is_authenticated]`` on handlers, controllers, or routers that
        your application defines outside the plugin-owned route table.

        Returns:
            Operation-level security requirements with OR semantics across the
            configured auth backends.
        """
        from litestar_auth._plugin.openapi import build_security_requirement  # noqa: PLC0415

        return build_security_requirement(self.resolve_openapi_security_schemes())

    def resolve_password_helper(self) -> PasswordHelper:
        """Return the helper aligned with this config, memoizing default construction.

        An explicit ``user_manager_security.password_helper`` wins. When the user did
        not provide one, the first call constructs a shared default and subsequent
        calls return that same instance.

        Returns:
            The configured typed password helper when present, otherwise a shared
            default helper memoized on the config instance.
        """
        if self.user_manager_security is not None and self.user_manager_security.password_helper is not None:
            return self.user_manager_security.password_helper
        if self._memoized_default_password_helper is None:
            self._memoized_default_password_helper = PasswordHelper.from_defaults()
        return self._memoized_default_password_helper

    def get_default_password_helper(self) -> PasswordHelper | None:
        """Return the memoized default helper when :meth:`resolve_password_helper` has been called.

        This accessor lets the plugin's manager construction path observe the
        same default helper that app-owned code received from
        :meth:`resolve_password_helper`.

        Returns:
            The shared default helper, or ``None`` when
            :meth:`resolve_password_helper` has not been invoked yet.
        """
        return self._memoized_default_password_helper

    def resolve_permission_resolver(self) -> PermissionResolver:
        """Return the configured permission resolver, falling back to the static role map.

        An explicit ``permission_resolver`` owns permission resolution. Otherwise
        ``role_permissions`` is normalized into the default static resolver using
        this config's superuser role name.
        """
        if self.permission_resolver is not None:
            return self.permission_resolver
        return StaticRolePermissionResolver(
            self.role_permissions,
            superuser_role_name=self.superuser_role_name,
            organization_role_precedence=self.organization_config.role_precedence,
            require_organization_context=self.organization_config.require_authorization_context,
        )

    def resolve_user_db_factory(self) -> UserDatabaseFactory[UP, ID]:
        """Return the configured factory, falling back to the lazy default.

        When ``user_db_factory`` is omitted, a SQLAlchemy-backed default is built
        on demand using :attr:`user_model`. The default's underlying adapter
        module is only imported on the first call.

        Returns:
            The user-provided factory or a lazy SQLAlchemy-backed default.
        """
        defaults = self.resolve_defaults()
        if not isinstance(defaults.user_db_factory, UnsetType):
            return defaults.user_db_factory
        return cast(
            "UserDatabaseFactory[UP, ID]",
            partial(_build_default_user_db, user_model=self.user_model),
        )
