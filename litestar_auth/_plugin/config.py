"""Configuration contracts and manager-builder helpers for the plugin facade."""

from __future__ import annotations

import keyword
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Never, Protocol, cast

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    import msgspec

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.manager import BaseUserManager, UserManagerSecurity
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, UsedTotpCodeStore

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


class _StartupOnlyDatabaseTokenSession:
    """Fail-closed sentinel used by startup-only DB-token backends."""

    def __getattr__(self, name: str) -> Never:
        """Raise when startup-only backends are used for request-time DB work.

        Raises:
            RuntimeError: Always, because startup-only backends are not valid for request-time
                database-token strategy work.
        """
        del name
        msg = (
            "DatabaseTokenAuthConfig.startup_backends() returns startup-only backends. "
            "Use LitestarAuthConfig.bind_request_backends(session) to obtain request-scoped "
            "backend instances for runtime login, refresh, logout, or token validation work."
        )
        raise RuntimeError(msg)


_STARTUP_ONLY_DATABASE_TOKEN_SESSION = _StartupOnlyDatabaseTokenSession()


def resolve_database_token_strategy_session(session: AsyncSession | None = None) -> AsyncSession:
    """Return the explicit request session or the startup-only sentinel session.

    Returns:
        The provided request ``AsyncSession`` when available, otherwise the startup-only
        sentinel used by :meth:`LitestarAuthConfig.startup_backends`.
    """
    return session if session is not None else cast("AsyncSession", _STARTUP_ONLY_DATABASE_TOKEN_SESSION)


def build_database_token_backend[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    session: AsyncSession,
    unsafe_testing: bool = False,
) -> AuthenticationBackend[UP, ID]:
    """Return the canonical DB-token backend for the provided request session.

    Returns:
        Authentication backend configured for the canonical DB bearer path.
    """
    return _build_database_token_backend(
        database_token_auth,
        session=session,
        unsafe_testing=unsafe_testing,
    )


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


def _build_database_token_backend[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    session: AsyncSession | None = None,
    unsafe_testing: bool = False,
) -> AuthenticationBackend[UP, ID]:
    """Build the canonical bearer + database-token backend lazily.

    Imports the backend, transport, and strategy only when the ``database_token_auth`` path is used so
    importing ``litestar_auth._plugin.config`` keeps the current lazy-import contract
    without hiding first-party references behind string-based module lookups.

    Returns:
        Authentication backend configured for the canonical DB bearer path.
    """
    from litestar_auth.authentication import AuthenticationBackend  # noqa: PLC0415
    from litestar_auth.authentication.strategy import DatabaseTokenStrategy  # noqa: PLC0415
    from litestar_auth.authentication.transport import BearerTransport  # noqa: PLC0415

    return AuthenticationBackend[UP, ID](
        name=database_token_auth.backend_name,
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            DatabaseTokenStrategy(
                session=resolve_database_token_strategy_session(session),
                token_hash_secret=database_token_auth.token_hash_secret,
                max_age=database_token_auth.max_age,
                refresh_max_age=database_token_auth.refresh_max_age,
                token_bytes=database_token_auth.token_bytes,
                accept_legacy_plaintext_tokens=database_token_auth.accept_legacy_plaintext_tokens,
                unsafe_testing=unsafe_testing,
            ),
        ),
    )


_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset({"email", "username"})


class PasswordValidatorFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a password validator callable for a plugin configuration."""

    def __call__(self, config: LitestarAuthConfig[UP, ID], /) -> Callable[[str], None] | None: ...  # pragma: no cover


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


def default_password_validator_factory[UP: UserProtocol[Any], ID](
    _config: LitestarAuthConfig[UP, ID],
) -> Callable[[str], None]:
    """Build the default plugin password validator.

    Returns:
        A validator enforcing the plugin's default password-length policy.
    """
    return partial(require_password_length, minimum_length=DEFAULT_MINIMUM_PASSWORD_LENGTH)


def _materialize_default_user_manager_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    password_helper: object,
    password_validator: object,
    backends: tuple[object, ...] = (),
) -> dict[str, Any]:
    """Materialize the default-builder constructor kwargs for one concrete call site.

    Returns:
        The concrete constructor kwargs for the requested default-builder surface.

    Raises:
        ConfigurationError: If plugin-managed secrets or ``id_parser`` are supplied
            through ``user_manager_kwargs`` instead of ``user_manager_security``.
    """
    effective_manager_kwargs = dict(config.user_manager_kwargs)
    if "password_helper" not in effective_manager_kwargs:
        effective_manager_kwargs["password_helper"] = password_helper
    manager_inputs = ManagerConstructorInputs(
        manager_kwargs=effective_manager_kwargs,
        manager_security=config.user_manager_security,
        password_validator=cast("Callable[[str], None] | None", password_validator),
        backends=backends,
        login_identifier=config.login_identifier,
        id_parser=config.id_parser,
    )
    if manager_inputs.managed_security_keys:
        invalid_keys = ", ".join(manager_inputs.managed_security_keys)
        msg = (
            "The default plugin user-manager builder only accepts verification/reset/TOTP "
            "secrets and id_parser through user_manager_security. Remove these keys from "
            f"user_manager_kwargs: {invalid_keys}. If you need factory-owned manager "
            "construction, set user_manager_factory."
        )
        raise ConfigurationError(msg)
    manager_kwargs = manager_inputs.build_kwargs()
    if "password_validator" not in manager_kwargs and "password_validator" not in effective_manager_kwargs:
        manager_kwargs["password_validator"] = password_validator
    if "unsafe_testing" not in manager_kwargs:
        manager_kwargs["unsafe_testing"] = config.unsafe_testing
    return manager_kwargs


def _build_default_user_manager_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backends: tuple[object, ...] = (),
) -> dict[str, Any]:
    """Materialize the exact kwargs used by the runtime default manager builder.

    Returns:
        The concrete constructor kwargs that :func:`build_user_manager` passes to
        ``user_manager_class(...)``.
    """
    return _materialize_default_user_manager_kwargs(
        config,
        password_helper=config.build_password_helper(),
        password_validator=resolve_password_validator(config),
        backends=backends,
    )


def _build_default_user_manager_validation_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backends: tuple[object, ...] = (),
) -> dict[str, Any]:
    """Materialize constructor-shape kwargs without executing runtime validator factories.

    Validation only needs the keyword surface, not the runtime validator object. The
    default builder still reserves the ``password_validator`` slot when the caller did
    not explicitly own it through ``user_manager_kwargs``.

    Returns:
        Constructor kwargs matching the startup validation contract for the default
        user-manager builder.
    """
    return _materialize_default_user_manager_kwargs(
        config,
        password_helper=object(),
        password_validator=None,
        backends=backends,
    )


def build_user_manager[UP: UserProtocol[Any], ID](
    *,
    session: AsyncSession,
    user_db: BaseUserStore[UP, ID],
    config: LitestarAuthConfig[UP, ID],
    backends: tuple[object, ...] = (),
) -> BaseUserManager[UP, ID]:
    """Instantiate the configured user manager through the explicit factory contract.

    Args:
        session: Request-local SQLAlchemy session (unused by the default builder; kept
            for custom ``user_manager_factory`` symmetry with the plugin).
        user_db: User persistence adapter for this session.
        config: Plugin configuration.
        backends: Session-bound authentication backends (overrides any ``backends`` key
            in ``user_manager_kwargs``).

    Returns:
        A request-scoped user manager instance built from the plugin config. When
        ``user_manager_factory`` is omitted, the default builder always calls the
        canonical ``BaseUserManager``-style constructor surface, including the
        plugin-managed ``unsafe_testing`` flag, and expects ``user_manager_class`` to
        accept that contract. Custom constructors that narrow or rename that surface
        must be built through ``user_manager_factory``.

    """
    del session
    manager_kwargs = _build_default_user_manager_kwargs(config, backends=backends)
    return config.user_manager_class(user_db, **manager_kwargs)


def resolve_password_validator[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> Callable[[str], None] | None:
    """Resolve the password validator requested by plugin configuration.

    Returns:
        The explicitly configured password validator when present, otherwise the
        plugin-owned default validator for the fixed default builder contract.
    """
    manager_inputs = ManagerConstructorInputs(manager_kwargs=config.user_manager_kwargs)
    explicit_validator = manager_inputs.explicit_password_validator
    if explicit_validator is not None:
        return explicit_validator
    if config.password_validator_factory is not None:
        return config.password_validator_factory(config)
    return default_password_validator_factory(config)


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


def resolve_user_manager_factory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> UserManagerFactory[UP, ID]:
    """Resolve the explicit builder used to create request-scoped user managers.

    Returns:
        The builder callable that the plugin should use for request-scoped managers.
    """
    if config.user_manager_factory is not None:
        return config.user_manager_factory
    return build_user_manager


@dataclass(slots=True)
class TotpConfig:
    """TOTP-specific plugin settings."""

    totp_pending_secret: str
    totp_backend_name: str | None = None
    totp_issuer: str = "litestar-auth"
    totp_algorithm: TotpAlgorithm = "SHA256"
    totp_used_tokens_store: UsedTotpCodeStore | None = None
    totp_require_replay_protection: bool = True
    totp_enable_requires_password: bool = True


@dataclass(slots=True)
class OAuthConfig:
    """OAuth-specific plugin settings."""

    oauth_cookie_secure: bool = True
    oauth_providers: Sequence[OAuthProviderConfig] | None = None
    oauth_associate_by_email: bool = False
    oauth_trust_provider_email_verified: bool = False
    include_oauth_associate: bool = False
    oauth_redirect_base_url: str = ""
    oauth_token_encryption_key: str | None = None


@dataclass(frozen=True, slots=True)
class _OAuthRouteRegistrationContract:
    """Internal contract describing plugin-owned OAuth login and associate routes."""

    providers: tuple[OAuthProviderConfig, ...]
    include_oauth_associate: bool
    oauth_cookie_secure: bool
    oauth_associate_by_email: bool
    oauth_trust_provider_email_verified: bool
    login_path: str
    associate_path: str
    redirect_base_url: str | None

    @property
    def has_configured_providers(self) -> bool:
        """Return whether any plugin-owned OAuth provider inventory was declared."""
        return bool(self.providers)

    @property
    def has_plugin_owned_login_routes(self) -> bool:
        """Return whether the plugin will auto-mount OAuth login routes."""
        return bool(self.providers)

    @property
    def has_plugin_owned_associate_routes(self) -> bool:
        """Return whether the plugin will auto-mount associate routes."""
        return bool(self.providers) and self.include_oauth_associate

    @property
    def login_redirect_base_url(self) -> str | None:
        """Return the absolute OAuth login redirect base URL when routes are mounted."""
        if not self.has_plugin_owned_login_routes or self.redirect_base_url is None:
            return None
        return f"{self.redirect_base_url.rstrip('/')}/oauth"

    @property
    def associate_redirect_base_url(self) -> str | None:
        """Return the absolute OAuth associate redirect base URL when routes are mounted."""
        if not self.has_plugin_owned_associate_routes or self.redirect_base_url is None:
            return None
        return f"{self.redirect_base_url.rstrip('/')}/associate"


def _normalize_oauth_provider_inventory(
    providers: Sequence[OAuthProviderConfig] | None,
) -> tuple[OAuthProviderConfig, ...]:
    """Return a stable tuple view of an OAuth provider inventory."""
    return tuple(providers or ())


def _build_oauth_route_registration_contract(
    *,
    auth_path: str,
    oauth_config: OAuthConfig | None,
) -> _OAuthRouteRegistrationContract:
    """Return the deterministic plugin OAuth route-registration contract.

    ``oauth_providers`` is the single plugin-owned OAuth provider inventory. When it
    is configured, the plugin auto-mounts provider login routes under
    ``{auth_path}/oauth/{provider}/...``. ``include_oauth_associate=True`` extends
    that same provider inventory with authenticated account-linking routes under
    ``{auth_path}/associate/{provider}/...``. Redirect callbacks use the explicit
    public ``oauth_redirect_base_url`` instead of an implicit localhost fallback.
    """
    base_auth_path = auth_path.rstrip("/") or "/"
    login_path = f"{base_auth_path}/oauth" if base_auth_path != "/" else "/oauth"
    associate_path = f"{base_auth_path}/associate" if base_auth_path != "/" else "/associate"
    if oauth_config is None:
        return _OAuthRouteRegistrationContract(
            providers=(),
            include_oauth_associate=False,
            oauth_cookie_secure=True,
            oauth_associate_by_email=False,
            oauth_trust_provider_email_verified=False,
            login_path=login_path,
            associate_path=associate_path,
            redirect_base_url=None,
        )

    providers = _normalize_oauth_provider_inventory(oauth_config.oauth_providers)
    redirect_base_url = oauth_config.oauth_redirect_base_url or None
    return _OAuthRouteRegistrationContract(
        providers=providers,
        include_oauth_associate=oauth_config.include_oauth_associate,
        oauth_cookie_secure=oauth_config.oauth_cookie_secure,
        oauth_associate_by_email=oauth_config.oauth_associate_by_email,
        oauth_trust_provider_email_verified=oauth_config.oauth_trust_provider_email_verified,
        login_path=login_path,
        associate_path=associate_path,
        redirect_base_url=redirect_base_url,
    )


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

    Core:
        ``user_model``, ``user_manager_class``, ``backends``, ``database_token_auth``,
        ``session_maker``, ``user_db_factory``, ``user_manager_security``,
        ``user_manager_kwargs``, ``password_validator_factory``, ``user_manager_factory``,
        ``rate_limit_config``.
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
    Login identifier:
        ``login_identifier`` (``'email'`` | ``'username'``) selects which user-model
        field is used for credential lookup (default ``'email'``).
    """

    user_model: type[UP]
    user_manager_class: type[BaseUserManager[UP, ID]]
    backends: Sequence[AuthenticationBackend[UP, ID]] = field(default_factory=tuple)
    database_token_auth: DatabaseTokenAuthConfig | None = None
    session_maker: SessionFactory | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] | None = None
    user_manager_security: UserManagerSecurity[ID] | None = None
    user_manager_kwargs: dict[str, Any] = field(default_factory=dict)
    password_validator_factory: PasswordValidatorFactory[UP, ID] | None = None
    user_manager_factory: UserManagerFactory[UP, ID] | None = None
    rate_limit_config: AuthRateLimitConfig | None = None
    auth_path: str = "/auth"
    users_path: str = "/users"
    include_register: bool = True
    include_verify: bool = True
    include_reset_password: bool = True
    include_users: bool = False
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
        - :meth:`startup_backends` for plugin setup and validation.
        - :meth:`bind_request_backends` for request-scoped runtime backends.

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
                "Use startup_backends() during plugin setup or bind_request_backends(session) "
                "for request-scoped backend instances when database_token_auth is configured."
            )
            raise ValueError(msg)
        return self.backends

    def startup_backends(self) -> Sequence[AuthenticationBackend[UP, ID]]:
        """Return startup-only backends for plugin setup, validation, and route assembly.

        Returns:
            Startup-only backend templates for the current config.
        """
        self._validate_backend_configuration()
        if self.database_token_auth is not None:
            return (_build_database_token_backend(self.database_token_auth, unsafe_testing=self.unsafe_testing),)
        return self.backends

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return authentication backends bound to the current request session.

        Returns:
            Request-scoped backends aligned with the provided SQLAlchemy session.
        """
        self._validate_backend_configuration()
        if self.database_token_auth is not None:
            return (
                build_database_token_backend(
                    self.database_token_auth,
                    session=session,
                    unsafe_testing=self.unsafe_testing,
                ),
            )
        return tuple(backend.with_session(session) for backend in self.startup_backends())

    def build_password_helper(self) -> PasswordHelper:
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

    def memoized_default_password_helper(self) -> PasswordHelper | None:
        """Return the memoized default helper when :meth:`build_password_helper` has been called.

        This accessor lets the plugin's manager construction path observe the
        same default helper that app-owned code received from
        :meth:`build_password_helper`, without touching ``user_manager_kwargs``.

        Returns:
            The shared default helper, or ``None`` when
            :meth:`build_password_helper` has not been invoked yet.
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
            msg = f"db_session_dependency_key must be a valid Python identifier, got {self.db_session_dependency_key!r}"
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


def _is_database_token_strategy_instance(strategy: object) -> bool:
    """Return whether ``strategy`` is a ``DatabaseTokenStrategy`` instance.

    Performs a lazy ``isinstance`` check that respects the plugin's lazy-import
    contract: when the DB-token strategy module has not been imported yet, no
    such instance can exist in the configured backends, so the function returns
    ``False`` without forcing the SQLAlchemy adapter to load. This keeps
    ``import litestar_auth`` free of mapper side effects (see ``AGENTS.md``).
    """
    db_strategy_module = sys.modules.get("litestar_auth.authentication.strategy.db")
    if db_strategy_module is None:
        return False
    db_strategy_cls = getattr(db_strategy_module, "DatabaseTokenStrategy", None)
    return db_strategy_cls is not None and isinstance(strategy, db_strategy_cls)


def _is_bundled_token_model(model: object, *, attribute_name: str) -> bool:
    """Return whether ``model`` is the bundled token ORM class for ``attribute_name``.

    Uses an identity check against the lazily-loaded class object so that
    plugin startup never forces ``litestar_auth.authentication.strategy.db_models``
    to import. Subclasses are intentionally rejected: only the bundled class
    triggers the bundled-model bootstrap path.
    """
    db_models_module = sys.modules.get("litestar_auth.authentication.strategy.db_models")
    if db_models_module is None:
        return False
    bundled_cls = getattr(db_models_module, attribute_name, None)
    return bundled_cls is not None and model is bundled_cls


def _backend_uses_bundled_database_token_models(backend: object) -> bool:
    """Return whether ``backend``'s strategy is a DB-token strategy with bundled token models."""
    strategy = getattr(backend, "strategy", None)
    if not _is_database_token_strategy_instance(strategy):
        return False
    return _is_bundled_token_model(
        getattr(strategy, "access_token_model", None),
        attribute_name="AccessToken",
    ) and _is_bundled_token_model(
        getattr(strategy, "refresh_token_model", None),
        attribute_name="RefreshToken",
    )


def _uses_bundled_database_token_models(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether plugin startup should bootstrap the bundled DB-token ORM models."""
    if config.database_token_auth is not None:
        return True
    return any(_backend_uses_bundled_database_token_models(backend) for backend in config.backends)
