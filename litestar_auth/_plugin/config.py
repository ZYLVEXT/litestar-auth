"""Configuration contracts and manager-builder helpers for the plugin facade."""

from __future__ import annotations

import inspect
import keyword
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import require_password_length
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import msgspec
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.db.base import BaseUserStore
    from litestar_auth.manager import BaseUserManager
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, UsedTotpCodeStore

type UserDatabaseFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], BaseUserStore[UP, ID]]

DEFAULT_CONFIG_DEPENDENCY_KEY = "litestar_auth_config"
DEFAULT_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_user_manager"
DEFAULT_BACKENDS_DEPENDENCY_KEY = "litestar_auth_backends"
DEFAULT_USER_MODEL_DEPENDENCY_KEY = "litestar_auth_user_model"
DEFAULT_DB_SESSION_DEPENDENCY_KEY = "db_session"
DEFAULT_CSRF_COOKIE_NAME = "litestar_auth_csrf"
OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY = "litestar_auth_oauth_associate_user_manager"
DEFAULT_USER_DB_FACTORY: UserDatabaseFactory[Any, Any] = cast(
    "UserDatabaseFactory[Any, Any]",
    SQLAlchemyUserDatabase,
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
) -> async_sessionmaker[AsyncSession]:
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
    session_maker: async_sessionmaker[AsyncSession] | None = None
    user_db_factory: UserDatabaseFactory[UP, ID] = DEFAULT_USER_DB_FACTORY
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

    def __post_init__(self) -> None:
        """Validate configuration fields that must hold at construction time.

        Raises:
            ConfigurationError: When ``login_identifier`` is not ``'email'`` or ``'username'``.
            ValueError: When ``db_session_dependency_key`` is not a valid Python identifier or is a
                reserved keyword.
        """
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)
        if not self.db_session_dependency_key.isidentifier() or keyword.iskeyword(self.db_session_dependency_key):
            msg = f"db_session_dependency_key must be a valid Python identifier, got {self.db_session_dependency_key!r}"
            raise ValueError(msg)
