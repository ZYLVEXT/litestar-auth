"""Configuration contracts for the plugin facade."""

# Test-suite reload-coverage pattern note:
# Several helpers below keep cross-module class identity coherent after tests
# call `importlib.reload(...)`. The reload pattern is load-bearing for the 100%
# coverage gate; removing these helpers requires first replacing the
# coverage-startup mechanism. See the investigation outcome at
# refactoring-test-reload-investigation.json (REFAC-001): a naive
# `coverage.run.parallel = true` configuration drops import-time coverage of
# `_plugin/oauth_contract.py` from 100% to 70.8%.

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol, cast, get_args

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin import _hooks as _plugin_hooks
from litestar_auth._plugin import backend_inventory as _backend_inventory
from litestar_auth._plugin import feature_configs as _feature_configs
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth._plugin.security_policy import (
    _describe_totp_secret_storage_policy,
    _PluginSecurityNotice,
)
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME, normalize_superuser_role_name
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import (
    DbSessionDependencyKey,
    LoginIdentifier,
    UserProtocol,
    _valid_python_identifier_validator,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    import msgspec
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.manager import BaseUserManager, FernetKeyringConfig, UserManagerSecurity
    from litestar_auth.password import PasswordHelper
    from litestar_auth.ratelimit import AuthRateLimitConfig

type UserDatabaseFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], BaseUserStore[UP, ID]]
_SESSION_FACTORY_CONTRACT = SessionFactory
PasswordHelper = cast("Any", import_module("litestar_auth.password").PasswordHelper)
FernetKeyringConfig = cast("Any", import_module("litestar_auth.manager").FernetKeyringConfig)

DEFAULT_CONFIG_DEPENDENCY_KEY = "litestar_auth_config"
DEFAULT_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_user_manager"
DEFAULT_BACKENDS_DEPENDENCY_KEY = "litestar_auth_backends"
DEFAULT_USER_MODEL_DEPENDENCY_KEY = "litestar_auth_user_model"
DEFAULT_DB_SESSION_DEPENDENCY_KEY = "db_session"
DEFAULT_CSRF_COOKIE_NAME = "litestar_auth_csrf"
OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_oauth_associate_user_manager"
DEFAULT_DATABASE_TOKEN_BACKEND_NAME = _feature_configs.DEFAULT_DATABASE_TOKEN_BACKEND_NAME
DEFAULT_DATABASE_TOKEN_MAX_AGE = _feature_configs.DEFAULT_DATABASE_TOKEN_MAX_AGE
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = _feature_configs.DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
DEFAULT_DATABASE_TOKEN_BYTES = _feature_configs.DEFAULT_DATABASE_TOKEN_BYTES
DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS = 0.4
DatabaseTokenAuthConfig = _feature_configs.DatabaseTokenAuthConfig
OAuthConfig = _feature_configs.OAuthConfig
TotpConfig = _feature_configs.TotpConfig
ControllerHook = _plugin_hooks.ControllerHook
ExceptionResponseHook = _plugin_hooks.ExceptionResponseHook
MiddlewareHook = _plugin_hooks.MiddlewareHook
StartupBackendInventory = _backend_inventory.StartupBackendInventory
StartupBackendTemplate = _backend_inventory.StartupBackendTemplate


def _resync_after_test_reload() -> None:
    """Resync backend-inventory aliases after a test reloads the source module.

    Without this, cross-module ``isinstance`` and class-identity checks would see
    stale ``StartupBackendInventory`` and ``StartupBackendTemplate`` class
    objects after ``importlib.reload(_backend_inventory)``. Test-infrastructure
    helper -- see the module-level note above.
    """
    global StartupBackendInventory, StartupBackendTemplate  # noqa: PLW0603
    StartupBackendInventory = _backend_inventory.StartupBackendInventory
    StartupBackendTemplate = _backend_inventory.StartupBackendTemplate
    StartupBackendInventory.__module__ = __name__
    StartupBackendTemplate.__module__ = __name__


_resync_after_test_reload()


def resolve_backend_inventory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> StartupBackendInventory[UP, ID]:
    """Refresh test-reload-safe aliases and return the resolved backend inventory.

    Returns:
        The current startup backend inventory for ``config``.
    """
    _resync_after_test_reload()
    return _backend_inventory.resolve_backend_inventory(config)


def _current_password_helper_type() -> type[PasswordHelper]:
    """Resolve ``PasswordHelper`` lazily for the memoized default helper.

    This lets ``LitestarAuthConfig._memoized_default_password_helper`` pick up
    the post-reload class identity if a test calls
    ``importlib.reload(litestar_auth.password)``. Test-infrastructure helper --
    see the module-level note above.

    Returns:
        The current PasswordHelper type from ``litestar_auth.password``.
    """
    return cast("type[PasswordHelper]", import_module("litestar_auth.password").PasswordHelper)


def _build_default_user_db(session: AsyncSession, *, user_model: type[Any]) -> BaseUserStore[Any, Any]:
    """Build a ``SQLAlchemyUserDatabase`` with a deferred adapter import.

    Used by :meth:`LitestarAuthConfig.resolve_user_db_factory` via ``functools.partial`` so the
    SQLAlchemy adapter module is loaded only at first request-scoped call, not at
    configuration time.

    Returns:
        A :class:`~litestar_auth.db.sqlalchemy.SQLAlchemyUserDatabase` bound to ``session``.
    """
    from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase  # noqa: PLC0415

    return SQLAlchemyUserDatabase(session, user_model=user_model)


def _resolve_plugin_managed_totp_secret_storage_policy[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _PluginSecurityNotice | None:
    """Resolve the TOTP storage policy owned by plugin-managed manager wiring.

    Returns:
        The plugin-managed TOTP storage notice when the plugin owns manager
        secret wiring for the active config, otherwise ``None``.
    """
    if config.totp_config is None:
        return None
    if config.user_manager_factory is not None and config.user_manager_security is None:
        return None
    manager_inputs = ManagerConstructorInputs(
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    effective_security = manager_inputs.effective_security
    return _describe_totp_secret_storage_policy(
        totp_secret_key=effective_security.totp_secret_key or None,
        keyring_configured=effective_security.totp_secret_keyring is not None,
    )


_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset(get_args(LoginIdentifier.__value__))


def _normalize_config_superuser_role_name(role_name: str) -> str:
    """Normalize the config-owned superuser role name as a configuration error.

    Returns:
        The normalized role name.

    Raises:
        ConfigurationError: If the value is not a non-empty role name string.
    """
    try:
        return normalize_superuser_role_name(role_name)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(str(exc)) from exc


def require_session_maker[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> SessionFactory:
    """Return the configured session factory or fail when it is omitted.

    Raises:
        ValueError: When ``session_maker`` is omitted.
    """
    maker = config.session_maker
    if maker is None:
        msg = "LitestarAuth requires session_maker."
        raise ValueError(msg)
    return maker


class PasswordValidatorFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a password validator callable for a plugin configuration."""

    def __call__(
        self,
        config: LitestarAuthConfig[UP, ID],
        /,
    ) -> Callable[[str], None] | None: ...  # pragma: no cover


class UserManagerFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a request-scoped user manager for the plugin.

    Implementations receive ``backends`` session-bound to the current request; pass them
    through to ``BaseUserManager`` (or equivalent) so credential changes revoke persisted
    sessions consistently. Plugin validation remains authoritative for the
    ``user_manager_security`` surface. If a factory builds ``BaseUserManager`` with a
    divergent manager-owned secret surface, the manager constructor enforces the same
    distinct-secret validation for the roles it actually wires.
    """

    def __call__(
        self,
        *,
        session: AsyncSession,
        user_db: BaseUserStore[UP, ID],
        config: LitestarAuthConfig[UP, ID],
        backends: tuple[object, ...] = (),
    ) -> BaseUserManager[UP, ID]: ...  # pragma: no cover


@dataclass(slots=True)
class LitestarAuthConfig[UP: UserProtocol[Any], ID]:
    """Configuration for the :class:`~litestar_auth.plugin.LitestarAuth` plugin.

    Field declarations below hold defaults and types; this overview groups names for
    navigation across a large surface area.

    User Manager Customization:
        Request-scoped :class:`~litestar_auth.manager.BaseUserManager` instances are built
        either by the plugin's default constructor path or by a factory you provide.
        Set ``user_manager_class`` when a ``BaseUserManager`` subclass accepts the
        default builder surface, including ``user_manager_security`` for secrets,
        password helpers, validators, and ID parsing. Set
        ``user_manager_factory`` when the manager constructor needs custom
        dependencies, a custom signature, or caller-owned construction.

    Core:
        ``user_model``, ``user_manager_class``, ``backends``, ``database_token_auth``,
        ``session_maker``, ``user_db_factory``, ``user_manager_security``,
        ``password_validator_factory``, ``user_manager_factory``, ``rate_limit_config``.
    Plugin customization hooks:
        ``exception_response_hook``, ``middleware_hook``, ``controller_hook``.
    Paths and endpoint flags:
        ``auth_path``, ``users_path``, ``include_register``, ``include_verify``,
        ``include_reset_password``, ``include_users``, ``enable_refresh``,
        ``requires_verification``, ``hard_delete``.
    TOTP:
        ``totp_config`` (`TotpConfig | None`) enables and configures TOTP flows.
    OAuth and account linking:
        ``oauth_config`` (`OAuthConfig | None`) enables OAuth login/linking and
        provider-specific settings.
    Security and token policy:
        ``csrf_secret``, ``csrf_header_name``, ``unsafe_testing``,
        ``register_minimum_response_seconds``, ``deployment_worker_count``, ``id_parser``,
        ``superuser_role_name``.
        ``register_minimum_response_seconds`` pads plugin-owned registration
        success and domain-failure responses as defense-in-depth against
        lower-tail timing enumeration; it is independent of rate limiting.
        ``deployment_worker_count`` is an explicit deployment-posture declaration
        for startup validation. ``None`` means unknown topology, ``1`` means known
        single-worker, and values greater than ``1`` mean known multi-worker. It
        does not launch or configure ASGI server workers.
    API schemas and DB-session dependency injection:
        ``user_read_schema``, ``user_create_schema``, ``user_update_schema``,
        ``db_session_dependency_key``, ``db_session_dependency_provided_externally``.
        ``db_session_dependency_key`` must be a valid non-keyword Python identifier
        because Litestar resolves dependencies by matching keys to callable parameter names.
    Login identifier:
        ``login_identifier`` (``'email'`` | ``'username'``) selects which user-model
        field is used for credential lookup (default ``'email'``).
    """

    user_model: type[UP]
    # Default path: concrete BaseUserManager subclass constructed by the plugin with the
    # default keyword-only surface (see "User Manager Customization" above).
    user_manager_class: type[BaseUserManager[UP, ID]] | None = None
    backends: Sequence[AuthenticationBackend[UP, ID]] = field(default_factory=tuple)
    database_token_auth: DatabaseTokenAuthConfig | None = None
    session_maker: SessionFactory | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] | None = None
    user_manager_security: UserManagerSecurity[ID] | None = None
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
    include_openapi_security: bool = True
    enable_refresh: bool = False
    requires_verification: bool = True
    hard_delete: bool = False
    totp_config: TotpConfig | None = None
    oauth_config: OAuthConfig | None = None
    # Security: CSRF signing material should not be exposed by autogenerated repr output.
    csrf_secret: str | None = field(default=None, repr=False)
    csrf_header_name: str = "X-CSRF-Token"
    unsafe_testing: bool = False
    # Defense-in-depth against lower-tail registration timing enumeration. This is
    # independent of rate limiting and only pads after the normal side effects run.
    register_minimum_response_seconds: float = DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS
    deployment_worker_count: int | None = None
    id_parser: Callable[[str], ID] | None = None
    user_read_schema: type[msgspec.Struct] | None = None
    user_create_schema: type[msgspec.Struct] | None = None
    user_update_schema: type[msgspec.Struct] | None = None
    db_session_dependency_key: DbSessionDependencyKey = DEFAULT_DB_SESSION_DEPENDENCY_KEY
    db_session_dependency_provided_externally: bool = False
    login_identifier: LoginIdentifier = "email"
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME
    _memoized_default_password_helper: PasswordHelper | None = field(
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
        return resolve_backend_inventory(self).bind_request_backends(session)

    def resolve_startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return startup-only backends for plugin setup, validation, and route assembly.

        Returns:
            Startup-only backend templates for the current config.
        """
        return resolve_backend_inventory(self).startup_backends()

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
            self._memoized_default_password_helper = _current_password_helper_type().from_defaults()
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

    def __post_init__(self) -> None:
        """Validate configuration fields and build defaults that depend on other fields."""
        self.superuser_role_name = _normalize_config_superuser_role_name(self.superuser_role_name)
        self._validate_user_manager_configuration()
        self._inherit_user_manager_id_parser()
        self._validate_backend_configuration()
        self._validate_timing_configuration()
        self._validate_login_identifier()
        self._validate_db_session_dependency_key()

    def _validate_user_manager_configuration(self) -> None:
        """Reject conflicting or invalid user-manager construction options.

        Raises:
            ConfigurationError: If manager construction paths conflict or a custom factory is not callable.
        """
        if self.user_manager_class is not None and self.user_manager_factory is not None:
            msg = (
                "user_manager_class and user_manager_factory are mutually exclusive. "
                "Set user_manager_class for the default manager path or "
                "user_manager_factory for a custom factory."
            )
            raise ConfigurationError(msg)
        if self.user_manager_factory is not None and not callable(self.user_manager_factory):
            msg = "user_manager_factory must be callable when provided."
            raise ConfigurationError(msg)

    def _inherit_user_manager_id_parser(self) -> None:
        """Use the manager security ID parser when the config did not set one."""
        if self.user_manager_security is not None and self.id_parser is None:
            self.id_parser = self.user_manager_security.id_parser

    def _validate_backend_configuration(self) -> None:
        """Reject invalid mixed preset/manual backend configuration.

        Raises:
            ValueError: If both ``backends`` and ``database_token_auth`` are configured.
        """
        if self.database_token_auth is not None and self.backends:
            msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
            raise ValueError(msg)

    def _validate_timing_configuration(self) -> None:
        """Validate registration timing and deployment worker settings.

        Raises:
            ConfigurationError: If registration timing or worker-count settings are invalid.
        """
        if self.register_minimum_response_seconds < 0:
            msg = "register_minimum_response_seconds must be non-negative."
            raise ConfigurationError(msg)
        if self.deployment_worker_count is None:
            return
        if not isinstance(self.deployment_worker_count, int) or isinstance(self.deployment_worker_count, bool):
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)
        if self.deployment_worker_count < 1:
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)

    def _validate_login_identifier(self) -> None:
        """Validate runtime login identifier values accepted by dataclass construction.

        Raises:
            ConfigurationError: If the login identifier is not supported.
        """
        # Static typing covers ordinary callers, but dataclass construction still receives runtime values.
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)

    def _validate_db_session_dependency_key(self) -> None:
        """Validate Litestar dependency key syntax.

        Raises:
            ValueError: If the dependency key is not a valid Python identifier.
        """
        try:
            _valid_python_identifier_validator(self.db_session_dependency_key)
        except ValueError as exc:
            raise ValueError(*exc.args) from None

    def resolve_user_db_factory(self) -> UserDatabaseFactory[UP, ID]:
        """Return the configured factory, falling back to the lazy default.

        When ``user_db_factory`` is omitted, a SQLAlchemy-backed default is built
        on demand using :attr:`user_model`. The default's underlying adapter
        module is only imported on the first call.

        Returns:
            The user-provided factory or a lazy SQLAlchemy-backed default.
        """
        if self.user_db_factory is not None:
            return self.user_db_factory
        return cast(
            "UserDatabaseFactory[UP, ID]",
            partial(_build_default_user_db, user_model=self.user_model),
        )
