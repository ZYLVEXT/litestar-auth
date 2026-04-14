"""Configuration contracts and manager-builder helpers for the plugin facade."""

from __future__ import annotations

import keyword
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol, cast

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth._plugin.security_policy import (
    _describe_totp_secret_storage_policy,
    _PluginSecurityNotice,
)
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.types import LoginIdentifier, UserProtocol

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
    from litestar_auth.manager import BaseUserManager, UserManagerSecurity
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, UsedTotpCodeStore
    from litestar_auth.types import StrategyProtocol, TransportProtocol

type UserDatabaseFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], BaseUserStore[UP, ID]]
_SESSION_FACTORY_CONTRACT = SessionFactory

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
class _BackendSlot[UP: UserProtocol[Any], ID]:
    """Stable index-and-name metadata shared across startup and request backend flows."""

    index: int
    name: str

    def resolve_request_backend(
        self,
        request_backends: object,
    ) -> AuthenticationBackend[UP, ID]:
        """Return the request-scoped backend matching this startup slot.

        Raises:
            RuntimeError: If the request-time backend inventory diverges from plugin startup.
        """
        backends = cast("Sequence[AuthenticationBackend[UP, ID]]", request_backends)
        if len(backends) <= self.index:
            msg = (
                "litestar_auth_backends did not provide the backend sequence expected by the plugin. "
                f"Missing backend index {self.index} for {self.name!r}."
            )
            raise RuntimeError(msg)

        backend = backends[self.index]
        if backend.name != self.name:
            msg = (
                "litestar_auth_backends no longer matches the plugin startup backend order. "
                f"Expected backend {self.name!r} at index {self.index}, got {backend.name!r}."
            )
            raise RuntimeError(msg)
        return backend


@dataclass(frozen=True, slots=True)
class _StartupBackendInventoryEntry[UP: UserProtocol[Any], ID]:
    """One startup backend plus the slot metadata used to resolve runtime backends."""

    startup_backend: StartupBackendTemplate[UP, ID]
    slot: _BackendSlot[UP, ID]

    @property
    def index(self) -> int:
        """Return the startup-order index for this backend."""
        return self.slot.index

    @property
    def name(self) -> str:
        """Return the backend name preserved across startup and request inventories."""
        return self.slot.name

    def bind_runtime_backend(self, session: AsyncSession) -> AuthenticationBackend[UP, ID]:
        """Materialize the request-scoped backend for ``session``.

        Returns:
            Runtime authentication backend rebound to ``session``.
        """
        return self.startup_backend.bind_runtime_backend(session)


@dataclass(frozen=True, slots=True)
class _StartupBackendInventory[UP: UserProtocol[Any], ID]:
    """Central startup inventory reused by plugin assembly and request binding."""

    entries: tuple[_StartupBackendInventoryEntry[UP, ID], ...]

    @classmethod
    def from_startup_backends(
        cls,
        startup_backends: tuple[StartupBackendTemplate[UP, ID], ...],
    ) -> _StartupBackendInventory[UP, ID]:
        """Build a centralized inventory from startup-only backend templates.

        Returns:
            Startup inventory with stable per-backend slot metadata.
        """
        return cls(
            entries=tuple(
                _StartupBackendInventoryEntry(
                    startup_backend=backend,
                    slot=_BackendSlot(index=index, name=backend.name),
                )
                for index, backend in enumerate(startup_backends)
            ),
        )

    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return the startup-only backend templates in configured order."""
        return tuple(entry.startup_backend for entry in self.entries)

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return request-scoped runtime backends aligned with the startup inventory."""
        return tuple(entry.bind_runtime_backend(session) for entry in self.entries)

    def primary(self) -> _StartupBackendInventoryEntry[UP, ID]:
        """Return the primary startup backend entry."""
        return self.entries[0]

    def resolve_named(self, backend_name: str) -> _StartupBackendInventoryEntry[UP, ID]:
        """Return the startup backend entry matching ``backend_name``.

        Raises:
            ValueError: If ``backend_name`` is not part of the startup inventory.
        """
        for entry in self.entries:
            if entry.name == backend_name:
                return entry

        msg = f"Unknown TOTP backend: {backend_name}"
        raise ValueError(msg)

    def resolve_totp(self, *, backend_name: str | None) -> _StartupBackendInventoryEntry[UP, ID]:
        """Return the TOTP startup backend entry, defaulting to the primary backend."""
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
        manager_kwargs=config.user_manager_kwargs,
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    return _describe_totp_secret_storage_policy(manager_inputs.effective_security.totp_secret_key or None)


_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset({"email", "username"})


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
    """TOTP-specific plugin settings."""

    totp_pending_secret: str
    totp_backend_name: str | None = None
    totp_issuer: str = "litestar-auth"
    totp_algorithm: TotpAlgorithm = "SHA256"
    totp_used_tokens_store: UsedTotpCodeStore | None = None
    totp_pending_jti_store: JWTDenylistStore | None = None
    totp_require_replay_protection: bool = True
    totp_enable_requires_password: bool = True


@dataclass(slots=True)
class OAuthConfig:
    """OAuth-specific plugin settings."""

    oauth_cookie_secure: bool = True
    oauth_providers: Sequence[OAuthProviderConfig | tuple[str, object]] | None = None
    oauth_provider_scopes: Mapping[str, Sequence[str]] = field(default_factory=dict)
    oauth_associate_by_email: bool = False
    oauth_trust_provider_email_verified: bool = False
    include_oauth_associate: bool = False
    oauth_redirect_base_url: str = ""
    oauth_token_encryption_key: str | None = None


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
    ``user_manager_security`` surface; if a custom factory constructs ``BaseUserManager`` with
    that same verification/reset/TOTP secret bundle, manager construction suppresses the
    duplicate warning. Factories that diverge from the validated config-owned secret surface
    still surface the manager-owned warning for the secrets they actually wire.
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
    """Canonical DB bearer preset settings owned by ``LitestarAuthConfig``."""

    token_hash_secret: str
    backend_name: str = DEFAULT_DATABASE_TOKEN_BACKEND_NAME
    max_age: timedelta = DEFAULT_DATABASE_TOKEN_MAX_AGE
    refresh_max_age: timedelta = DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
    token_bytes: int = DEFAULT_DATABASE_TOKEN_BYTES
    accept_legacy_plaintext_tokens: bool = False


@dataclass(slots=True)
class LitestarAuthConfig[UP: UserProtocol[Any], ID]:
    """Configuration for the :class:`~litestar_auth.plugin.LitestarAuth` plugin.

    Field declarations below hold defaults and types; this overview groups names for
    navigation across a large surface area.

    User Manager Customization:
        Request-scoped :class:`~litestar_auth.manager.BaseUserManager` instances are built
        either by the plugin's default constructor path or by a factory you provide. The
        three fields ``user_manager_class``, ``user_manager_factory``, and
        ``user_manager_kwargs`` overlap in purpose; use the table below to pick **one**
        primary path.

        **Decision table**

        .. code-block:: text

            +----------------------------------+----------------------------+
            | Situation                        | Primary field              |
            +==================================+============================+
            | Subclass BaseUserManager; accept | user_manager_class         |
            | the default builder kwargs       | (+ user_manager_security   |
            | (see build_user_manager).        |   for secrets/id_parser)   |
            +----------------------------------+----------------------------+
            | Non-canonical __init__, extra    | user_manager_factory       |
            | deps, or factory-owned secrets   |                            |
            +----------------------------------+----------------------------+
            | Minor extras for the default     | user_manager_kwargs        |
            | builder (e.g. password_helper)   | (never secrets/id_parser)  |
            +----------------------------------+----------------------------+

    Core:
        ``user_model``, ``user_manager_class``, ``backends``, ``database_token_auth``,
        ``session_maker``, ``user_db_factory``, ``user_manager_security``,
        ``user_manager_kwargs``, ``password_validator_factory``, ``user_manager_factory``,
        ``rate_limit_config``.
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
        ``allow_legacy_plaintext_tokens``, ``allow_nondurable_jwt_revocation``,
        ``id_parser``.
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
    # canonical keyword-only surface (see "User Manager Customization" above).
    user_manager_class: type[BaseUserManager[UP, ID]]
    backends: Sequence[AuthenticationBackend[UP, ID]] = field(default_factory=tuple)
    database_token_auth: DatabaseTokenAuthConfig | None = None
    session_maker: SessionFactory | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] | None = None
    user_manager_security: UserManagerSecurity[ID] | None = None
    # Escape hatch: extra kwargs merged into the default builder's call to user_manager_class.
    # Use for non-security extras (e.g. password_helper); never for secrets or id_parser —
    # those belong in user_manager_security.
    user_manager_kwargs: dict[str, Any] = field(default_factory=dict)
    password_validator_factory: PasswordValidatorFactory[UP, ID] | None = None
    # Advanced path: callable that fully constructs the manager per request. Use when the
    # constructor is not the canonical BaseUserManager surface or you need custom DI.
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
    requires_verification: bool = False
    hard_delete: bool = False
    totp_config: TotpConfig | None = None
    oauth_config: OAuthConfig | None = None
    csrf_secret: str | None = None
    csrf_header_name: str = "X-CSRF-Token"
    unsafe_testing: bool = False
    allow_legacy_plaintext_tokens: bool = False
    allow_nondurable_jwt_revocation: bool = False
    id_parser: Callable[[str], ID] | None = None
    user_read_schema: type[msgspec.Struct] | None = None
    user_create_schema: type[msgspec.Struct] | None = None
    user_update_schema: type[msgspec.Struct] | None = None
    db_session_dependency_key: str = DEFAULT_DB_SESSION_DEPENDENCY_KEY
    db_session_dependency_provided_externally: bool = False
    login_identifier: LoginIdentifier = "email"
    _memoized_default_password_helper: PasswordHelper | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def resolve_backends(self) -> Sequence[AuthenticationBackend[UP, ID]]:
        """Return the explicitly configured manual backends for this config.

        This accessor is intentionally limited to the manual ``backends=...`` surface.
        The canonical ``database_token_auth=...`` preset now exposes an explicit
        startup-vs-request split:
        - :meth:`resolve_startup_backends` for plugin setup and validation.
        - :meth:`resolve_request_backends` for request-scoped runtime backends.

        Returns:
            The explicit manual ``backends`` sequence.

        Raises:
            ValueError: If both ``backends`` and ``database_token_auth`` are configured, or if
                callers attempt to use this manual-backend accessor with
                ``database_token_auth=...``.
        """
        self._validate_backend_configuration()
        if self.database_token_auth is not None:
            msg = (
                "resolve_backends() only returns explicit backends=... entries. "
                "Use resolve_startup_backends() during plugin setup or "
                "resolve_request_backends(session) for request-scoped backend instances when "
                "database_token_auth is configured."
            )
            raise ValueError(msg)
        return self.backends

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

    def resolve_request_backends(
        self,
        session: AsyncSession,
    ) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return authentication backends bound to the current request session.

        Returns:
            Request-scoped backends aligned with the provided SQLAlchemy session.
        """
        return resolve_backend_inventory(self).bind_request_backends(session)

    def resolve_password_helper(self) -> PasswordHelper:
        """Return the helper aligned with this config, memoizing default construction.

        An explicit ``user_manager_kwargs['password_helper']`` always wins. When the
        user did not provide one, the first call constructs a shared default and
        subsequent calls return that same instance. The plugin's manager construction
        path mirrors this resolution so the plugin and app-owned code observe a single
        default helper without the config mutating the user-provided ``user_manager_kwargs``.

        Returns:
            The configured ``user_manager_kwargs['password_helper']`` when present,
            otherwise a shared default helper memoized on the config instance.
        """
        configured_password_helper = cast("PasswordHelper | None", self.user_manager_kwargs.get("password_helper"))
        if configured_password_helper is not None:
            return configured_password_helper
        if self._memoized_default_password_helper is None:
            self._memoized_default_password_helper = PasswordHelper.from_defaults()
        return self._memoized_default_password_helper

    def get_default_password_helper(self) -> PasswordHelper | None:
        """Return the memoized default helper when :meth:`resolve_password_helper` has been called.

        This accessor lets the plugin's manager construction path observe the
        same default helper that app-owned code received from
        :meth:`resolve_password_helper`, without touching ``user_manager_kwargs``.

        Returns:
            The shared default helper, or ``None`` when
            :meth:`resolve_password_helper` has not been invoked yet.
        """
        return self._memoized_default_password_helper

    def __post_init__(self) -> None:
        """Validate configuration fields and build defaults that depend on other fields.

        Raises:
            ConfigurationError: When ``login_identifier`` is not ``'email'`` or ``'username'``.
            ValueError: When ``db_session_dependency_key`` is not a valid Python identifier or is a
                reserved keyword, or when ``backends`` and ``database_token_auth`` are both configured.
        """
        if self.user_manager_security is not None and self.id_parser is None:
            self.id_parser = self.user_manager_security.id_parser
        self._validate_backend_configuration()
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)
        if not self.db_session_dependency_key.isidentifier() or keyword.iskeyword(self.db_session_dependency_key):
            msg = (
                "db_session_dependency_key must be a valid Python identifier because Litestar matches dependency "
                f"keys to callable parameter names, got {self.db_session_dependency_key!r}"
            )
            raise ValueError(msg)

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


_DATABASE_TOKEN_EXPORTS: frozenset[str] = frozenset(
    {
        "_backend_uses_bundled_database_token_models",
        "_build_database_token_backend",
        "_build_database_token_backend_template",
        "_is_bundled_token_model",
        "_is_database_token_strategy_instance",
        "_uses_bundled_database_token_models",
        "build_database_token_backend",
        "resolve_database_token_strategy_session",
    },
)

_USER_MANAGER_BUILDER_EXPORTS: frozenset[str] = frozenset(
    {
        "PasswordValidatorFactory",
        "UserManagerFactory",
        "_DefaultUserManagerBuilderContract",
        "_build_default_user_manager_contract",
        "_build_default_user_manager_kwargs",
        "_build_default_user_manager_validation_kwargs",
        "build_user_manager",
        "default_password_validator_factory",
        "resolve_password_validator",
        "resolve_user_manager_factory",
    },
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-export optional helpers so ``import litestar_auth._plugin.config`` stays lightweight.

    Returns:
        The requested symbol from :mod:`litestar_auth._plugin.database_token` or
        :mod:`litestar_auth._plugin.user_manager_builder`.

    Raises:
        AttributeError: If ``name`` is not one of the lazy-exported helpers.
    """
    if name in _DATABASE_TOKEN_EXPORTS:
        from litestar_auth._plugin import database_token as _database_token_module  # noqa: PLC0415

        return getattr(_database_token_module, name)
    if name in _USER_MANAGER_BUILDER_EXPORTS:
        from litestar_auth._plugin import user_manager_builder as _user_manager_builder_module  # noqa: PLC0415

        return getattr(_user_manager_builder_module, name)
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


def resolve_backend_inventory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _StartupBackendInventory[UP, ID]:
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
    return _StartupBackendInventory.from_startup_backends(startup_backends)
