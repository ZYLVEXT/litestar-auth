"""Configuration contracts for the plugin facade."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol, cast, get_args

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._manager.construction import ManagerConstructorInputs
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
    from collections.abc import Mapping, Sequence

    import msgspec
    from litestar.connection import Request
    from litestar.middleware import DefineMiddleware
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme
    from litestar.response import Response
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.exceptions import LitestarAuthError
    from litestar_auth.manager import BaseUserManager, FernetKeyringConfig, UserManagerSecurity
    from litestar_auth.password import PasswordHelper
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore
    from litestar_auth.types import StrategyProtocol, TransportProtocol

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
DEFAULT_DATABASE_TOKEN_BACKEND_NAME = "database"  # noqa: S105
DEFAULT_DATABASE_TOKEN_MAX_AGE = timedelta(hours=1)
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = timedelta(days=30)
DEFAULT_DATABASE_TOKEN_BYTES = 32
DEFAULT_REGISTER_MINIMUM_RESPONSE_SECONDS = 0.4


def _current_password_helper_type() -> type[PasswordHelper]:
    """Resolve PasswordHelper lazily so cross-test module reloads stay coherent.

    Returns:
        The current PasswordHelper type from ``litestar_auth.password``.
    """
    return cast("type[PasswordHelper]", import_module("litestar_auth.password").PasswordHelper)


@dataclass(frozen=True, slots=True, eq=False)
class StartupBackendTemplate[UP: UserProtocol[Any], ID]:
    """Startup-only backend template used for plugin assembly and validation."""

    name: str
    transport: TransportProtocol
    strategy: StrategyProtocol[UP, ID]
    _runtime_backend_factory: Callable[[AsyncSession], AuthenticationBackend[UP, ID]] = field(
        repr=False,
    )

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, StartupBackendTemplate):
            return NotImplemented
        return self.name == other.name and self.transport is other.transport and self.strategy is other.strategy

    def __hash__(self) -> int:
        return hash((self.name, id(self.transport), id(self.strategy)))

    @classmethod
    def from_runtime_backend(
        cls,
        backend: AuthenticationBackend[UP, ID],
    ) -> StartupBackendTemplate[UP, ID]:
        """Wrap a runtime backend in the startup-only template type.

        Returns:
            Startup-only template carrying the runtime backend's public surface and
            session-binding factory.
        """
        return cls(
            name=backend.name,
            transport=backend.transport,
            strategy=backend.strategy,
            _runtime_backend_factory=backend.with_session,
        )

    def bind_runtime_backend(self, session: AsyncSession) -> AuthenticationBackend[UP, ID]:
        """Materialize the request-scoped runtime backend for ``session``.

        Returns:
            Runtime authentication backend rebound to ``session``.
        """
        return self._runtime_backend_factory(session)


@dataclass(frozen=True, slots=True)
class StartupBackendInventory[UP: UserProtocol[Any], ID]:
    """Central startup inventory reused by plugin assembly and request binding."""

    startup_backend_templates: tuple[StartupBackendTemplate[UP, ID], ...]

    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return the startup-only backend templates in configured order."""
        return self.startup_backend_templates

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return request-scoped runtime backends aligned with the startup inventory."""
        return tuple(backend.bind_runtime_backend(session) for backend in self.startup_backend_templates)

    def primary(self) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the primary startup backend and its startup-order index."""
        return 0, self.startup_backend_templates[0]

    def resolve_named(self, backend_name: str) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the startup backend matching ``backend_name`` plus its index.

        Raises:
            ValueError: If ``backend_name`` is not part of the startup inventory.
        """
        for index, backend in enumerate(self.startup_backend_templates):
            if backend.name == backend_name:
                return index, backend

        msg = f"Unknown TOTP backend: {backend_name}"
        raise ValueError(msg)

    def resolve_request_backend(
        self,
        request_backends: object,
        *,
        backend_index: int,
    ) -> AuthenticationBackend[UP, ID]:
        """Return the request-scoped backend matching ``backend_index`` from startup.

        Raises:
            RuntimeError: If the request-time backend inventory diverges from plugin startup.
        """
        expected_backend = self.startup_backend_templates[backend_index]
        backends = cast("Sequence[AuthenticationBackend[UP, ID]]", request_backends)
        if len(backends) <= backend_index:
            msg = (
                "litestar_auth_backends did not provide the backend sequence expected by the plugin. "
                f"Missing backend index {backend_index} for {expected_backend.name!r}."
            )
            raise RuntimeError(msg)

        backend = backends[backend_index]
        if backend.name != expected_backend.name:
            msg = (
                "litestar_auth_backends no longer matches the plugin startup backend order. "
                f"Expected backend {expected_backend.name!r} at index {backend_index}, got {backend.name!r}."
            )
            raise RuntimeError(msg)
        return backend

    def resolve_totp(self, *, backend_name: str | None) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the TOTP startup backend, defaulting to the primary backend."""
        if backend_name is None:
            return self.primary()
        return self.resolve_named(backend_name)


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


class ExceptionResponseHook(Protocol):
    """Format plugin-owned auth errors as Litestar responses."""

    def __call__(
        self,
        exc: LitestarAuthError,
        request: Request[Any, Any, Any],
        /,
    ) -> Response[Any]: ...  # pragma: no cover


class MiddlewareHook(Protocol):
    """Adjust the constructed auth middleware before plugin insertion."""

    def __call__(self, middleware: DefineMiddleware, /) -> DefineMiddleware: ...  # pragma: no cover


class ControllerHook(Protocol):
    """Adjust the built plugin controller list before registration."""

    def __call__(
        self,
        controllers: list[ControllerRouterHandler],
        /,
    ) -> list[ControllerRouterHandler]: ...  # pragma: no cover


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


@dataclass(slots=True)
class TotpConfig:
    """TOTP-specific plugin settings.

    Includes recovery-code storage flow configuration and default-on
    pending-token client binding for plugin-owned TOTP routes.
    """

    # Security: hide the pending-token signing secret from debug repr output.
    totp_pending_secret: str = field(repr=False)
    totp_backend_name: str | None = None
    totp_issuer: str = "litestar-auth"
    totp_algorithm: TotpAlgorithm = "SHA256"
    totp_used_tokens_store: UsedTotpCodeStore | None = None
    totp_pending_jti_store: JWTDenylistStore | None = None
    totp_enrollment_store: TotpEnrollmentStore | None = None
    totp_require_replay_protection: bool = True
    totp_enable_requires_password: bool = True
    totp_pending_require_client_binding: bool = True


@dataclass(slots=True)
class OAuthConfig:
    """OAuth-specific plugin settings."""

    oauth_cookie_secure: bool = True
    oauth_providers: Sequence[OAuthProviderConfig] | None = None
    oauth_provider_scopes: Mapping[str, Sequence[str]] = field(default_factory=dict)
    oauth_associate_by_email: bool = False
    oauth_trust_provider_email_verified: bool = False
    include_oauth_associate: bool = False
    oauth_redirect_base_url: str = ""
    # Security: never leak the Fernet key through repr/str when configs are logged.
    oauth_token_encryption_key: str | None = field(default=None, repr=False)
    oauth_token_encryption_keyring: FernetKeyringConfig | None = field(default=None, repr=False)
    # Security: transient state + PKCE verifier material must be encrypted with
    # server-side secret material before it is placed in the browser flow cookie.
    oauth_flow_cookie_secret: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject ambiguous OAuth token-at-rest key inputs.

        Raises:
            ConfigurationError: If both one-key and keyring inputs are configured.
        """
        if self.oauth_token_encryption_key is None or self.oauth_token_encryption_keyring is None:
            return
        msg = (
            "Configure OAuth token encryption with oauth_token_encryption_key or "
            "oauth_token_encryption_keyring, not both."
        )
        raise ConfigurationError(msg)

    @property
    def has_oauth_token_encryption(self) -> bool:
        """Return whether OAuth token-at-rest encryption material is configured."""
        return self.oauth_token_encryption_key is not None or self.oauth_token_encryption_keyring is not None


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
class DatabaseTokenAuthConfig:
    """DB-token bearer preset settings owned by ``LitestarAuthConfig``."""

    # Security: HMAC token-hash material must stay out of repr/str output.
    token_hash_secret: str = field(repr=False)
    backend_name: str = DEFAULT_DATABASE_TOKEN_BACKEND_NAME
    max_age: timedelta = DEFAULT_DATABASE_TOKEN_MAX_AGE
    refresh_max_age: timedelta = DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
    token_bytes: int = DEFAULT_DATABASE_TOKEN_BYTES


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
        """Validate configuration fields and build defaults that depend on other fields.

        Raises:
            ConfigurationError: When manager construction paths conflict, ``login_identifier`` is outside
                :data:`LoginIdentifier`, ``superuser_role_name`` is not a non-empty role name, or
                ``register_minimum_response_seconds`` is negative, or ``deployment_worker_count`` is not a
                positive integer when provided.
            ValueError: When ``db_session_dependency_key`` is not a valid Python identifier or is a
                reserved keyword, or when ``backends`` and ``database_token_auth`` are both configured.
        """
        self.superuser_role_name = _normalize_config_superuser_role_name(self.superuser_role_name)
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
        if self.user_manager_security is not None and self.id_parser is None:
            self.id_parser = self.user_manager_security.id_parser
        self._validate_backend_configuration()
        if self.register_minimum_response_seconds < 0:
            msg = "register_minimum_response_seconds must be non-negative."
            raise ConfigurationError(msg)
        if self.deployment_worker_count is not None and (
            not isinstance(self.deployment_worker_count, int) or isinstance(self.deployment_worker_count, bool)
        ):
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)
        if self.deployment_worker_count is not None and self.deployment_worker_count < 1:
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)
        # Static typing covers ordinary callers, but dataclass construction still receives runtime values.
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)
        try:
            _valid_python_identifier_validator(self.db_session_dependency_key)
        except ValueError as exc:
            raise ValueError(*exc.args) from None

    def _validate_backend_configuration(self) -> None:
        """Reject invalid mixed preset/manual backend configuration.

        Raises:
            ValueError: If both ``backends`` and ``database_token_auth`` are configured.
        """
        if self.database_token_auth is not None and self.backends:
            msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
            raise ValueError(msg)

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


def resolve_backend_inventory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> StartupBackendInventory[UP, ID]:
    """Return the centralized startup inventory for plugin assembly and request binding.

    Returns:
        Startup inventory for the current config, including stable slot metadata used to
        resolve request-scoped backends.

    Raises:
        ValueError: If both ``database_token_auth`` and manual ``backends`` are configured.
    """
    if config.database_token_auth is not None and config.backends:
        msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
        raise ValueError(msg)
    startup_backends: tuple[StartupBackendTemplate[UP, ID], ...]
    if config.database_token_auth is not None:
        from litestar_auth._plugin import database_token as _database_token_module  # noqa: PLC0415

        startup_backends = (
            _database_token_module._build_database_token_backend_template(  # noqa: SLF001
                config.database_token_auth,
                unsafe_testing=config.unsafe_testing,
            ),
        )
    else:
        startup_backends = tuple(StartupBackendTemplate.from_runtime_backend(backend) for backend in config.backends)
    return StartupBackendInventory(startup_backends)
