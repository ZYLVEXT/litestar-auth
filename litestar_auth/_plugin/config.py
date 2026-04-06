"""Configuration contracts and manager-builder helpers for the plugin facade."""

from __future__ import annotations

import importlib
import inspect
import keyword
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol, Self, cast

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    import msgspec

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.manager import BaseUserManager
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
_DATABASE_TOKEN_REQUEST_SESSION: ContextVar[AsyncSession | None] = ContextVar(
    "litestar_auth_database_token_request_session",
    default=None,
)


class _RequestScopedDatabaseTokenSessionProxy:
    """Resolve the active DB session lazily from the current request context."""

    @staticmethod
    def _session() -> AsyncSession:
        """Return the current request-local session for DB-token preset operations.

        Returns:
            The current request-local SQLAlchemy session.

        Raises:
            RuntimeError: When no request-local session has been bound yet.
        """
        session = _DATABASE_TOKEN_REQUEST_SESSION.get()
        if session is not None:
            return session

        msg = (
            "DatabaseTokenAuthConfig requires a LitestarAuth-managed request session at runtime. "
            "Configure session_maker on LitestarAuthConfig or provide the DB session dependency externally."
        )
        raise RuntimeError(msg)

    def __getattr__(self, name: str) -> object:
        """Forward session attribute access to the current request-local session.

        Returns:
            The requested attribute resolved from the active request-local session.
        """
        return getattr(self._session(), name)


_REQUEST_SCOPED_DATABASE_TOKEN_SESSION = _RequestScopedDatabaseTokenSessionProxy()


def bind_database_token_request_session(session: AsyncSession) -> None:
    """Record the current request-local session for DB-token preset backends."""
    _DATABASE_TOKEN_REQUEST_SESSION.set(session)


def resolve_database_token_strategy_session(session: AsyncSession | None = None) -> AsyncSession:
    """Return the explicit request session or the preset's request-scoped session proxy."""
    return session if session is not None else cast("AsyncSession", _REQUEST_SCOPED_DATABASE_TOKEN_SESSION)


def build_database_token_backend[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    session: AsyncSession | None = None,
) -> AuthenticationBackend[UP, ID]:
    """Return the canonical DB-token backend for the provided request session.

    Returns:
        Authentication backend configured for the canonical DB bearer path.
    """
    return _build_database_token_backend(database_token_auth, session=session)


def _build_default_user_db(session: AsyncSession, *, user_model: type[Any]) -> BaseUserStore[Any, Any]:
    """Build a ``SQLAlchemyUserDatabase`` with a deferred adapter import.

    Used by ``LitestarAuthConfig.__post_init__`` via ``functools.partial`` so the
    SQLAlchemy adapter module is loaded only at first request-scoped call, not at
    configuration time.

    Returns:
        A :class:`~litestar_auth.db.sqlalchemy.SQLAlchemyUserDatabase` bound to ``session``.
    """
    mod = importlib.import_module("litestar_auth.db.sqlalchemy")
    return mod.SQLAlchemyUserDatabase(session, user_model=user_model)


def _build_database_token_backend[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    session: AsyncSession | None = None,
) -> AuthenticationBackend[UP, ID]:
    """Build the canonical bearer + database-token backend lazily.

    Imports the backend, transport, and strategy only when the preset builder is used so
    importing ``litestar_auth._plugin.config`` keeps the current lazy-import contract.

    Returns:
        Authentication backend configured for the canonical DB bearer path.
    """
    authentication_package = importlib.import_module("litestar_auth.authentication")
    strategy_package = importlib.import_module("litestar_auth.authentication.strategy")
    transport_package = importlib.import_module("litestar_auth.authentication.transport")

    return authentication_package.AuthenticationBackend[UP, ID](
        name=database_token_auth.backend_name,
        transport=transport_package.BearerTransport(),
        strategy=cast(
            "Any",
            strategy_package.DatabaseTokenStrategy(
                session=resolve_database_token_strategy_session(session),
                token_hash_secret=database_token_auth.token_hash_secret,
                max_age=database_token_auth.max_age,
                refresh_max_age=database_token_auth.refresh_max_age,
                token_bytes=database_token_auth.token_bytes,
                accept_legacy_plaintext_tokens=database_token_auth.accept_legacy_plaintext_tokens,
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
    sessions consistently.
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


def user_manager_accepts_password_validator(user_manager_class: type[BaseUserManager[Any, Any]]) -> bool:
    """Return whether the manager constructor can accept ``password_validator``.

    Checks the class-level ``accepts_password_validator`` attribute first,
    but only when explicitly declared by the subclass (present in its own
    ``__dict__``).  Falls back to ``inspect.signature`` introspection for
    subclasses that inherit the base-class default or predate the attribute.
    """
    if "accepts_password_validator" in user_manager_class.__dict__:
        return bool(user_manager_class.accepts_password_validator)
    init_signature = inspect.signature(user_manager_class.__init__)
    accepts_kwargs = any(param.kind is inspect.Parameter.VAR_KEYWORD for param in init_signature.parameters.values())
    return accepts_kwargs or "password_validator" in init_signature.parameters


def user_manager_accepts_login_identifier(user_manager_class: type[BaseUserManager[Any, Any]]) -> bool:
    """Return whether the manager constructor can accept ``login_identifier``.

    Checks the class-level ``accepts_login_identifier`` attribute first,
    but only when explicitly declared by the subclass (present in its own
    ``__dict__``).  Falls back to ``inspect.signature`` introspection for
    subclasses that inherit the base-class default or predate the attribute.
    """
    if "accepts_login_identifier" in user_manager_class.__dict__:
        return bool(user_manager_class.accepts_login_identifier)
    init_signature = inspect.signature(user_manager_class.__init__)
    accepts_kwargs = any(param.kind is inspect.Parameter.VAR_KEYWORD for param in init_signature.parameters.values())
    return accepts_kwargs or "login_identifier" in init_signature.parameters


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
        A request-scoped user manager instance built from the plugin config.
    """
    del session
    manager_kwargs = dict(config.user_manager_kwargs)
    password_validator = resolve_password_validator(config)
    if password_validator is not None and "password_validator" not in manager_kwargs:
        manager_kwargs["password_validator"] = password_validator
    manager_kwargs["backends"] = backends
    if user_manager_accepts_login_identifier(config.user_manager_class) and "login_identifier" not in manager_kwargs:
        manager_kwargs["login_identifier"] = config.login_identifier
    return config.user_manager_class(user_db, **manager_kwargs)


def resolve_password_validator[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> Callable[[str], None] | None:
    """Resolve the password validator requested by plugin configuration.

    Returns:
        The configured password validator, or ``None`` when this manager should not receive one.
    """
    explicit_validator = cast("Callable[[str], None] | None", config.user_manager_kwargs.get("password_validator"))
    if explicit_validator is not None:
        return explicit_validator
    if config.password_validator_factory is not None:
        return config.password_validator_factory(config)
    if user_manager_accepts_password_validator(config.user_manager_class):
        return default_password_validator_factory(config)
    return None


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
    include_oauth_associate: bool = False
    oauth_associate_providers: Sequence[OAuthProviderConfig] | None = None
    oauth_associate_redirect_base_url: str = ""
    oauth_token_encryption_key: str | None = None


@dataclass(frozen=True, slots=True)
class _OAuthRouteRegistrationContract:
    """Internal contract describing declared and plugin-owned OAuth routes."""

    login_providers: tuple[OAuthProviderConfig, ...]
    declared_associate_providers: tuple[OAuthProviderConfig, ...]
    plugin_associate_providers: tuple[OAuthProviderConfig, ...]
    include_oauth_associate: bool
    oauth_cookie_secure: bool
    oauth_associate_by_email: bool
    associate_path: str
    associate_redirect_base_url: str | None

    @property
    def has_configured_providers(self) -> bool:
        """Return whether any OAuth provider inventory was declared."""
        return bool(self.login_providers or self.declared_associate_providers)

    @property
    def has_plugin_owned_associate_routes(self) -> bool:
        """Return whether the plugin will auto-mount associate routes."""
        return bool(self.plugin_associate_providers)


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

    The current contract keeps OAuth login controller registration explicit even when
    ``oauth_providers`` is declared on ``OAuthConfig``. The plugin auto-mounts only
    associate routes, and only when ``include_oauth_associate=True`` plus a non-empty
    ``oauth_associate_providers`` inventory are both present.
    """
    associate_path = f"{auth_path.rstrip('/')}/associate"
    if oauth_config is None:
        return _OAuthRouteRegistrationContract(
            login_providers=(),
            declared_associate_providers=(),
            plugin_associate_providers=(),
            include_oauth_associate=False,
            oauth_cookie_secure=True,
            oauth_associate_by_email=False,
            associate_path=associate_path,
            associate_redirect_base_url=None,
        )

    login_providers = _normalize_oauth_provider_inventory(oauth_config.oauth_providers)
    declared_associate_providers = _normalize_oauth_provider_inventory(oauth_config.oauth_associate_providers)
    plugin_associate_providers = declared_associate_providers if oauth_config.include_oauth_associate else ()
    associate_redirect_base_url = None
    if plugin_associate_providers:
        associate_redirect_base_url = (
            oauth_config.oauth_associate_redirect_base_url or f"http://localhost{associate_path}"
        )
    return _OAuthRouteRegistrationContract(
        login_providers=login_providers,
        declared_associate_providers=declared_associate_providers,
        plugin_associate_providers=plugin_associate_providers,
        include_oauth_associate=oauth_config.include_oauth_associate,
        oauth_cookie_secure=oauth_config.oauth_cookie_secure,
        oauth_associate_by_email=oauth_config.oauth_associate_by_email,
        associate_path=associate_path,
        associate_redirect_base_url=associate_redirect_base_url,
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
        ``backends``, ``user_model``, ``user_manager_class``, ``session_maker``,
        ``user_db_factory``, ``user_manager_kwargs``, ``password_validator_factory``,
        ``user_manager_factory``, ``rate_limit_config``.
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
        ``csrf_secret``, ``csrf_header_name``, ``allow_legacy_plaintext_tokens``,
        ``allow_nondurable_jwt_revocation``, ``id_parser``.
    API schemas and DB-session dependency injection:
        ``user_read_schema``, ``user_create_schema``, ``user_update_schema``,
        ``db_session_dependency_key``, ``db_session_dependency_provided_externally``.
    Login identifier:
        ``login_identifier`` (``'email'`` | ``'username'``) selects which user-model
        field is used for credential lookup (default ``'email'``).
    """

    backends: Sequence[AuthenticationBackend[UP, ID]]
    user_model: type[UP]
    user_manager_class: type[BaseUserManager[UP, ID]]
    session_maker: SessionFactory | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] | None = None
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
    allow_legacy_plaintext_tokens: bool = False
    allow_nondurable_jwt_revocation: bool = False
    id_parser: Callable[[str], ID] | None = None
    user_read_schema: type[msgspec.Struct] | None = None
    user_create_schema: type[msgspec.Struct] | None = None
    user_update_schema: type[msgspec.Struct] | None = None
    db_session_dependency_key: str = DEFAULT_DB_SESSION_DEPENDENCY_KEY
    db_session_dependency_provided_externally: bool = False
    login_identifier: LoginIdentifier = "email"
    _database_token_auth: DatabaseTokenAuthConfig | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def database_token_auth(self) -> DatabaseTokenAuthConfig | None:
        """Return DB bearer preset metadata when built via ``with_database_token_auth()``."""
        return self._database_token_auth

    @classmethod
    def with_database_token_auth(  # noqa: PLR0913
        cls: type[Self],
        *,
        database_token_auth: DatabaseTokenAuthConfig,
        backends: Sequence[AuthenticationBackend[UP, ID]] | None = None,
        user_model: type[UP],
        user_manager_class: type[BaseUserManager[UP, ID]],
        session_maker: SessionFactory | None = None,
        user_db_factory: UserDatabaseFactory[UP, ID] | None = None,
        user_manager_kwargs: dict[str, Any] | None = None,
        password_validator_factory: PasswordValidatorFactory[UP, ID] | None = None,
        user_manager_factory: UserManagerFactory[UP, ID] | None = None,
        rate_limit_config: AuthRateLimitConfig | None = None,
        auth_path: str = "/auth",
        users_path: str = "/users",
        include_register: bool = True,
        include_verify: bool = True,
        include_reset_password: bool = True,
        include_users: bool = False,
        enable_refresh: bool = False,
        requires_verification: bool = False,
        hard_delete: bool = False,
        totp_config: TotpConfig | None = None,
        oauth_config: OAuthConfig | None = None,
        csrf_secret: str | None = None,
        csrf_header_name: str = "X-CSRF-Token",
        allow_legacy_plaintext_tokens: bool = False,
        allow_nondurable_jwt_revocation: bool = False,
        id_parser: Callable[[str], ID] | None = None,
        user_read_schema: type[msgspec.Struct] | None = None,
        user_create_schema: type[msgspec.Struct] | None = None,
        user_update_schema: type[msgspec.Struct] | None = None,
        db_session_dependency_key: str = DEFAULT_DB_SESSION_DEPENDENCY_KEY,
        db_session_dependency_provided_externally: bool = False,
        login_identifier: LoginIdentifier = "email",
    ) -> Self:
        """Build config for the canonical bearer + database-token plugin path.

        Args:
            database_token_auth: Settings object for the canonical DB bearer preset.
            backends: Must be omitted. This preset builds the canonical backend itself.
            user_model: User ORM or protocol model.
            user_manager_class: User manager implementation for the plugin.
            session_maker: Optional session factory used by the plugin runtime.
            user_db_factory: Optional user database factory override.
            user_manager_kwargs: Additional user manager constructor kwargs.
            password_validator_factory: Optional password validator factory override.
            user_manager_factory: Optional request-scoped user manager factory override.
            rate_limit_config: Optional rate-limit configuration.
            auth_path: Auth controller base path.
            users_path: Users controller base path.
            include_register: Include register endpoint.
            include_verify: Include verify endpoint.
            include_reset_password: Include reset-password endpoints.
            include_users: Include user-management endpoints.
            enable_refresh: Enable refresh-token endpoints.
            requires_verification: Require verified users for login.
            hard_delete: Hard-delete users instead of soft-delete behavior.
            totp_config: Optional TOTP configuration.
            oauth_config: Optional OAuth configuration.
            csrf_secret: Optional CSRF secret.
            csrf_header_name: CSRF header name.
            allow_legacy_plaintext_tokens: Allow the top-level migration acknowledgement for
                manual DB strategies. The canonical DB-token preset normalizes this from
                ``database_token_auth.accept_legacy_plaintext_tokens`` automatically.
            allow_nondurable_jwt_revocation: Allow in-memory JWT revocation in production.
            id_parser: Optional user-id parser.
            user_read_schema: Optional read schema override.
            user_create_schema: Optional create schema override.
            user_update_schema: Optional update schema override.
            db_session_dependency_key: Dependency key for injected DB sessions.
            db_session_dependency_provided_externally: Whether the session dependency is external.
            login_identifier: Credential lookup field for login.

        Returns:
            Configured plugin settings for the canonical DB bearer path.

        Raises:
            ValueError: If ``backends`` is also provided.
        """
        if backends is not None:
            msg = (
                "LitestarAuthConfig.with_database_token_auth() builds the canonical DB bearer backend "
                "automatically; use either this builder or pass backends=... to LitestarAuthConfig(...), not both."
            )
            raise ValueError(msg)
        normalized_allow_legacy_plaintext_tokens = (
            allow_legacy_plaintext_tokens or database_token_auth.accept_legacy_plaintext_tokens
        )
        config = cls(
            backends=[_build_database_token_backend(database_token_auth)],
            user_model=user_model,
            user_manager_class=user_manager_class,
            session_maker=session_maker,
            user_db_factory=user_db_factory,
            user_manager_kwargs={} if user_manager_kwargs is None else dict(user_manager_kwargs),
            password_validator_factory=password_validator_factory,
            user_manager_factory=user_manager_factory,
            rate_limit_config=rate_limit_config,
            auth_path=auth_path,
            users_path=users_path,
            include_register=include_register,
            include_verify=include_verify,
            include_reset_password=include_reset_password,
            include_users=include_users,
            enable_refresh=enable_refresh,
            requires_verification=requires_verification,
            hard_delete=hard_delete,
            totp_config=totp_config,
            oauth_config=oauth_config,
            csrf_secret=csrf_secret,
            csrf_header_name=csrf_header_name,
            allow_legacy_plaintext_tokens=normalized_allow_legacy_plaintext_tokens,
            allow_nondurable_jwt_revocation=allow_nondurable_jwt_revocation,
            id_parser=id_parser,
            user_read_schema=user_read_schema,
            user_create_schema=user_create_schema,
            user_update_schema=user_update_schema,
            db_session_dependency_key=db_session_dependency_key,
            db_session_dependency_provided_externally=db_session_dependency_provided_externally,
            login_identifier=login_identifier,
        )
        config._database_token_auth = database_token_auth
        return config

    def __post_init__(self) -> None:
        """Validate configuration fields and build defaults that depend on other fields.

        Raises:
            ConfigurationError: When ``login_identifier`` is not ``'email'`` or ``'username'``.
            ValueError: When ``db_session_dependency_key`` is not a valid Python identifier or is a
                reserved keyword.
        """
        if self.user_db_factory is None:
            self.user_db_factory = cast(
                "UserDatabaseFactory[UP, ID]",
                partial(_build_default_user_db, user_model=self.user_model),
            )
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)
        if not self.db_session_dependency_key.isidentifier() or keyword.iskeyword(self.db_session_dependency_key):
            msg = f"db_session_dependency_key must be a valid Python identifier, got {self.db_session_dependency_key!r}"
            raise ValueError(msg)
