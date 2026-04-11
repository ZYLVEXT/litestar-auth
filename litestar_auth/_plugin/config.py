"""Configuration contracts and manager-builder helpers for the plugin facade."""

from __future__ import annotations

import keyword
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, Never, Protocol, TypeGuard, cast

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._manager.totp_secrets import TotpSecretStoragePosture
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.db.base import BaseUserStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from logging import Logger

    import msgspec
    from litestar.openapi.spec import SecurityRequirement, SecurityScheme

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy import DatabaseTokenModels
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.config import OAuthProviderConfig
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

type _PluginSecurityTradeoffKey = Literal["jwt_revocation", "totp_secret_storage"]


@dataclass(frozen=True, slots=True)
class _PluginSecurityTradeoffPolicy:
    """Shared documentation and ownership wording for plugin-managed security tradeoffs."""

    key: _PluginSecurityTradeoffKey
    plugin_surface: str
    contract_reference: str
    docs_summary: str
    production_requirement: str


@dataclass(frozen=True, slots=True)
class _PluginSecurityTradeoffNotice:
    """One concrete runtime tradeoff resolved from a posture contract."""

    policy: _PluginSecurityTradeoffPolicy
    posture_key: str
    requires_explicit_production_opt_in: bool
    production_validation_error: str | None
    startup_warning: str | None


class _JWTRevocationPostureLike(Protocol):
    """Runtime posture contract needed by plugin validation and startup warnings."""

    key: str
    requires_explicit_production_opt_in: bool
    production_validation_error: str | None
    startup_warning: str | None


_JWT_REVOCATION_TRADEOFF_POLICY = _PluginSecurityTradeoffPolicy(
    key="jwt_revocation",
    plugin_surface="allow_nondurable_jwt_revocation=True",
    contract_reference="JWTStrategy.revocation_posture",
    docs_summary=(
        "`JWTStrategy(secret=...)` defaults to the compatibility-grade `compatibility_in_memory` posture "
        "unless you provide a shared denylist store."
    ),
    production_requirement=(
        "Plugin-managed production rejects this posture unless "
        "`allow_nondurable_jwt_revocation=True` or `unsafe_testing=True`; startup still warns when you "
        "explicitly accept the single-process tradeoff."
    ),
)
_TOTP_SECRET_STORAGE_TRADEOFF_POLICY = _PluginSecurityTradeoffPolicy(
    key="totp_secret_storage",
    plugin_surface="user_manager_security.totp_secret_key",
    contract_reference="BaseUserManager.totp_secret_storage_posture",
    docs_summary=(
        "Omitting `totp_secret_key` keeps the compatibility-grade `compatibility_plaintext` posture "
        "so legacy plaintext TOTP secrets still round-trip."
    ),
    production_requirement=(
        "With `totp_config` enabled, plugin-managed production requires `user_manager_security.totp_secret_key` "
        "unless `unsafe_testing=True` or a custom `user_manager_factory` explicitly owns that wiring."
    ),
)


def _is_jwt_revocation_posture_like(posture: object) -> TypeGuard[_JWTRevocationPostureLike]:
    """Return whether ``posture`` matches the JWT revocation posture contract.

    This uses attribute checks instead of ``isinstance()`` so strategy-module reloads in
    test coverage still satisfy the shared posture contract.
    """
    production_validation_error = getattr(posture, "production_validation_error", None)
    startup_warning = getattr(posture, "startup_warning", None)
    return (
        isinstance(getattr(posture, "key", None), str)
        and isinstance(getattr(posture, "requires_explicit_production_opt_in", None), bool)
        and (production_validation_error is None or isinstance(production_validation_error, str))
        and (startup_warning is None or isinstance(startup_warning, str))
    )


def _describe_jwt_revocation_tradeoff(posture: object) -> _PluginSecurityTradeoffNotice | None:
    """Resolve the shared plugin tradeoff notice for a JWT revocation posture.

    Returns:
        The shared plugin notice when ``posture`` satisfies the JWT revocation
        contract, otherwise ``None``.
    """
    if not _is_jwt_revocation_posture_like(posture):
        return None
    return _PluginSecurityTradeoffNotice(
        policy=_JWT_REVOCATION_TRADEOFF_POLICY,
        posture_key=posture.key,
        requires_explicit_production_opt_in=posture.requires_explicit_production_opt_in,
        production_validation_error=posture.production_validation_error,
        startup_warning=posture.startup_warning,
    )


def _describe_totp_secret_storage_tradeoff(totp_secret_key: str | None) -> _PluginSecurityTradeoffNotice:
    """Resolve the shared plugin tradeoff notice for TOTP secret storage.

    Returns:
        The shared plugin notice for the resolved TOTP storage posture.
    """
    posture = TotpSecretStoragePosture.from_secret_key(totp_secret_key)
    return _PluginSecurityTradeoffNotice(
        policy=_TOTP_SECRET_STORAGE_TRADEOFF_POLICY,
        posture_key=posture.key,
        requires_explicit_production_opt_in=posture.requires_explicit_production_opt_in,
        production_validation_error=posture.production_validation_error,
        startup_warning=None,
    )


def _iter_plugin_security_tradeoff_policies() -> tuple[_PluginSecurityTradeoffPolicy, ...]:
    """Return the shared plugin-managed JWT/TOTP tradeoff descriptions."""
    return (
        _JWT_REVOCATION_TRADEOFF_POLICY,
        _TOTP_SECRET_STORAGE_TRADEOFF_POLICY,
    )


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


class _StartupOnlyDatabaseTokenSession:
    """Fail-closed placeholder kept for test helpers and compatibility shims."""

    def __getattr__(self, name: str) -> Never:
        """Raise when startup-only backends are used for request-time DB work."""
        del name
        _raise_startup_only_database_token_runtime_error()


_STARTUP_ONLY_DATABASE_TOKEN_SESSION = _StartupOnlyDatabaseTokenSession()


def _raise_startup_only_database_token_runtime_error() -> Never:
    """Raise the canonical fail-closed error for startup-only DB-token backends.

    Raises:
        RuntimeError: Always, because startup-only DB-token templates are not valid for
            request-time authentication work.
    """
    msg = (
        "DatabaseTokenAuthConfig.startup_backends() returns startup-only backends. "
        "Use LitestarAuthConfig.bind_request_backends(session) to obtain request-scoped "
        "backend instances for runtime login, refresh, logout, or token validation work."
    )
    raise RuntimeError(msg)


def resolve_database_token_strategy_session(session: AsyncSession | None = None) -> AsyncSession:
    """Return ``session`` or a fail-closed placeholder for legacy helper paths.

    Returns:
        The provided request ``AsyncSession`` when available, otherwise a placeholder that
        raises the canonical startup-only runtime error on first use. The
        :meth:`LitestarAuthConfig.startup_backends` path now uses an explicit startup-only
        strategy wrapper instead of this placeholder.
    """
    return session if session is not None else cast("AsyncSession", _STARTUP_ONLY_DATABASE_TOKEN_SESSION)


@dataclass(frozen=True, slots=True)
class _DatabaseTokenStrategySettings:
    """Immutable runtime settings shared by startup-only and bound DB-token strategies."""

    token_hash_secret: str
    max_age: timedelta
    refresh_max_age: timedelta
    token_bytes: int
    accept_legacy_plaintext_tokens: bool
    unsafe_testing: bool


class _StartupOnlyDatabaseTokenStrategyMixin[UP: UserProtocol[Any], ID]:
    """Fail-closed startup-only wrapper for the canonical DB-token strategy settings."""

    def __init__(
        self,
        *,
        settings: _DatabaseTokenStrategySettings,
        token_models: DatabaseTokenModels,
        runtime_strategy_cls: type[Any],
        legacy_warning_message: str,
        database_token_logger: Logger,
    ) -> None:
        self._runtime_strategy_settings = settings
        self._runtime_strategy_cls = runtime_strategy_cls
        self._token_hash_secret = settings.token_hash_secret.encode()
        self.token_models = token_models
        self.access_token_model = token_models.access_token_model
        self.refresh_token_model = token_models.refresh_token_model
        self.max_age = settings.max_age
        self.refresh_max_age = settings.refresh_max_age
        self.token_bytes = settings.token_bytes
        self.accept_legacy_plaintext_tokens = settings.accept_legacy_plaintext_tokens
        self.unsafe_testing = settings.unsafe_testing
        if self.accept_legacy_plaintext_tokens and not self.unsafe_testing:
            database_token_logger.warning(
                legacy_warning_message,
                extra={"event": "db_tokens_accept_legacy_plaintext"},
            )

    def _raise_startup_only_runtime_error(self) -> Never:
        del self
        return _raise_startup_only_database_token_runtime_error()

    def with_session(self, session: AsyncSession) -> StrategyProtocol[UP, ID]:
        settings = self._runtime_strategy_settings
        return cast(
            "StrategyProtocol[UP, ID]",
            self._runtime_strategy_cls(
                session=session,
                token_hash_secret=settings.token_hash_secret,
                token_models=self.token_models,
                max_age=settings.max_age,
                refresh_max_age=settings.refresh_max_age,
                token_bytes=settings.token_bytes,
                accept_legacy_plaintext_tokens=settings.accept_legacy_plaintext_tokens,
                unsafe_testing=settings.unsafe_testing,
            ),
        )

    async def read_token(self, token: str | None, user_manager: object) -> UP | None:
        del token
        del user_manager
        return self._raise_startup_only_runtime_error()

    async def write_token(self, user: UP) -> str:
        del user
        return self._raise_startup_only_runtime_error()

    async def destroy_token(self, token: str, user: UP) -> None:
        del token
        del user
        return self._raise_startup_only_runtime_error()

    async def write_refresh_token(self, user: UP) -> str:
        del user
        return self._raise_startup_only_runtime_error()

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: object,
    ) -> tuple[UP, str] | None:
        del refresh_token
        del user_manager
        return self._raise_startup_only_runtime_error()

    async def invalidate_all_tokens(self, user: UP) -> None:
        del user
        return self._raise_startup_only_runtime_error()

    async def cleanup_expired_tokens(self, session: AsyncSession) -> int:
        del session
        return self._raise_startup_only_runtime_error()


def _build_startup_only_database_token_strategy[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    unsafe_testing: bool = False,
) -> StrategyProtocol[UP, ID]:
    """Build a startup-only DB-token strategy that fails closed until session binding.

    Returns:
        Startup-only strategy carrying DB-token metadata without a placeholder session.
    """
    from litestar_auth.authentication.strategy import (  # noqa: PLC0415
        DatabaseTokenModels,
        DatabaseTokenStrategy,
    )
    from litestar_auth.authentication.strategy.db import (  # noqa: PLC0415
        build_legacy_plaintext_tokens_warning_message,
    )
    from litestar_auth.authentication.strategy.db import (  # noqa: PLC0415
        logger as database_token_logger,
    )

    class _StartupOnlyDatabaseTokenStrategy(_StartupOnlyDatabaseTokenStrategyMixin, DatabaseTokenStrategy):
        """Concrete startup-only DB-token strategy tied to the current strategy module."""

    settings = _DatabaseTokenStrategySettings(
        token_hash_secret=database_token_auth.token_hash_secret,
        max_age=database_token_auth.max_age,
        refresh_max_age=database_token_auth.refresh_max_age,
        token_bytes=database_token_auth.token_bytes,
        accept_legacy_plaintext_tokens=database_token_auth.accept_legacy_plaintext_tokens,
        unsafe_testing=unsafe_testing,
    )
    return cast(
        "StrategyProtocol[UP, ID]",
        _StartupOnlyDatabaseTokenStrategy(
            settings=settings,
            token_models=DatabaseTokenModels(),
            runtime_strategy_cls=DatabaseTokenStrategy,
            legacy_warning_message=build_legacy_plaintext_tokens_warning_message(),
            database_token_logger=database_token_logger,
        ),
    )


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


def _build_database_token_backend_template[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    unsafe_testing: bool = False,
) -> StartupBackendTemplate[UP, ID]:
    """Build the startup-only template for the canonical DB-token backend.

    Returns:
        Startup-only template for the canonical DB-token backend.
    """
    startup_backend = _build_database_token_backend(
        database_token_auth,
        unsafe_testing=unsafe_testing,
    )
    return StartupBackendTemplate.from_runtime_backend(startup_backend)


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


def _resolve_plugin_managed_totp_secret_storage_tradeoff[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> _PluginSecurityTradeoffNotice | None:
    """Resolve the TOTP storage tradeoff owned by plugin-managed manager wiring.

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
    return _describe_totp_secret_storage_tradeoff(manager_inputs.effective_security.totp_secret_key or None)


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

    strategy: StrategyProtocol[UP, ID]
    if session is None:
        strategy = _build_startup_only_database_token_strategy(
            database_token_auth,
            unsafe_testing=unsafe_testing,
        )
    else:
        strategy = cast(
            "StrategyProtocol[UP, ID]",
            DatabaseTokenStrategy(
                session=session,
                token_hash_secret=database_token_auth.token_hash_secret,
                max_age=database_token_auth.max_age,
                refresh_max_age=database_token_auth.refresh_max_age,
                token_bytes=database_token_auth.token_bytes,
                accept_legacy_plaintext_tokens=database_token_auth.accept_legacy_plaintext_tokens,
                unsafe_testing=unsafe_testing,
            ),
        )

    return AuthenticationBackend[UP, ID](
        name=database_token_auth.backend_name,
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )


_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset({"email", "username"})


class PasswordValidatorFactory[UP: UserProtocol[Any], ID](Protocol):
    """Build a password validator callable for a plugin configuration."""

    def __call__(self, config: LitestarAuthConfig[UP, ID], /) -> Callable[[str], None] | None: ...  # pragma: no cover


_DEFAULT_USER_MANAGER_CONSTRUCTOR_DESCRIPTION = (
    "user_manager_class(user_db, *, password_helper=..., security=..., "
    "password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)"
)
_DEFAULT_USER_MANAGER_ID_PARSER_FALLBACK_DESCRIPTION = (
    "When user_manager_security is unset, the plugin passes id_parser=... directly instead of folding it into security."
)
_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE = (
    "Configure user_manager_factory for non-canonical or factory-owned manager construction."
)


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


def _format_default_user_manager_managed_security_error(managed_security_keys: tuple[str, ...]) -> str:
    """Return the shared diagnostic for legacy plugin-managed security kwargs."""
    invalid_keys = ", ".join(managed_security_keys)
    return (
        "The default plugin user-manager builder only accepts verification/reset/TOTP "
        "secrets and id_parser through user_manager_security. "
        "user_manager_security is the canonical plugin-managed path for manager secrets and id_parser. "
        f"Remove these keys from user_manager_kwargs: {invalid_keys}. {_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
    )


@dataclass(frozen=True, slots=True)
class _DefaultUserManagerBuilderContract[UP: UserProtocol[Any], ID]:
    """Shared internal contract for plugin-owned default user-manager construction."""

    config: LitestarAuthConfig[UP, ID]
    password_helper: object
    password_validator: Callable[[str], None] | None
    backends: tuple[object, ...] = ()

    @property
    def effective_manager_kwargs(self) -> dict[str, Any]:
        """Return manager kwargs with the default password helper materialized."""
        effective_manager_kwargs = dict(self.config.user_manager_kwargs)
        if "password_helper" not in effective_manager_kwargs:
            effective_manager_kwargs["password_helper"] = self.password_helper
        return effective_manager_kwargs

    @property
    def manager_inputs(self) -> ManagerConstructorInputs[ID]:
        """Return the normalized constructor inputs for the default builder."""
        return ManagerConstructorInputs(
            manager_kwargs=self.effective_manager_kwargs,
            manager_security=self.config.user_manager_security,
            password_validator=self.password_validator,
            backends=self.backends,
            login_identifier=self.config.login_identifier,
            id_parser=self.config.id_parser,
        )

    def build_kwargs(self) -> dict[str, Any]:
        """Materialize the canonical default-builder kwargs for one call site.

        Returns:
            The concrete constructor kwargs for the requested default-builder surface.

        Raises:
            ConfigurationError: If plugin-managed secrets or ``id_parser`` are supplied
                through ``user_manager_kwargs`` instead of ``user_manager_security``.
        """
        manager_inputs = self.manager_inputs
        if manager_inputs.managed_security_keys:
            msg = _format_default_user_manager_managed_security_error(manager_inputs.managed_security_keys)
            raise ConfigurationError(msg)

        manager_kwargs = manager_inputs.build_kwargs()
        if "password_validator" not in self.effective_manager_kwargs:
            manager_kwargs["password_validator"] = self.password_validator
        if "unsafe_testing" not in manager_kwargs:
            manager_kwargs["unsafe_testing"] = self.config.unsafe_testing
        return manager_kwargs

    @staticmethod
    def build_constructor_mismatch_message(manager_name: str, exc: TypeError) -> str:
        """Return the shared constructor-mismatch diagnostic for the default builder."""
        return (
            f"{manager_name!r} (user_manager_class) is incompatible with the default plugin "
            "builder contract. Without user_manager_factory, the plugin calls "
            f"{_DEFAULT_USER_MANAGER_CONSTRUCTOR_DESCRIPTION}. "
            f"{_DEFAULT_USER_MANAGER_ID_PARSER_FALLBACK_DESCRIPTION} "
            f"{_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE} Original error: {exc}"
        )


def _build_default_user_manager_contract[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    password_helper: object,
    password_validator: Callable[[str], None] | None,
    backends: tuple[object, ...] = (),
) -> _DefaultUserManagerBuilderContract[UP, ID]:
    """Return the shared contract for plugin-owned default manager construction."""
    return _DefaultUserManagerBuilderContract(
        config=config,
        password_helper=password_helper,
        password_validator=password_validator,
        backends=backends,
    )


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
    return _build_default_user_manager_contract(
        config,
        password_helper=config.build_password_helper(),
        password_validator=resolve_password_validator(config),
        backends=backends,
    ).build_kwargs()


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
    return _build_default_user_manager_contract(
        config,
        password_helper=object(),
        password_validator=None,
        backends=backends,
    ).build_kwargs()


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
    totp_pending_jti_store: JWTDenylistStore | None = None
    totp_require_replay_protection: bool = True
    totp_enable_requires_password: bool = True


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
    oauth_token_encryption_key: str | None = None


@dataclass(frozen=True, slots=True)
class _OAuthRouteRegistrationContract:
    """Internal contract describing plugin-owned OAuth login and associate routes."""

    providers: tuple[OAuthProviderConfig, ...]
    oauth_provider_scopes: dict[str, tuple[str, ...]]
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


def _normalize_oauth_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    """Return a normalized tuple of configured OAuth scopes.

    Raises:
        TypeError: If any configured scope is not a string.
        ValueError: If any configured scope is empty or contains whitespace.
    """
    normalized_scopes: list[str] = []
    seen_scopes: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "oauth_provider_scopes values must be strings."
            raise TypeError(msg)
        scope = raw_scope.strip()
        if not scope:
            msg = "oauth_provider_scopes values must be non-empty strings."
            raise ValueError(msg)
        if any(character.isspace() for character in scope):
            msg = "oauth_provider_scopes values must be individual tokens without embedded whitespace."
            raise ValueError(msg)
        if scope not in seen_scopes:
            normalized_scopes.append(scope)
            seen_scopes.add(scope)
    return tuple(normalized_scopes)


def _normalize_oauth_provider_scopes(
    *,
    providers: tuple[OAuthProviderConfig, ...],
    provider_scopes: Mapping[str, Sequence[str]],
) -> dict[str, tuple[str, ...]]:
    """Return normalized per-provider OAuth scopes keyed by provider name.

    Raises:
        ValueError: If provider scopes reference an unknown provider name or contain invalid scopes.
    """
    normalized_provider_scopes: dict[str, tuple[str, ...]] = {}
    configured_provider_names = {provider_name for provider_name, _oauth_client in providers}
    unknown_provider_names = sorted(set(provider_scopes) - configured_provider_names)
    if unknown_provider_names:
        joined_names = ", ".join(unknown_provider_names)
        msg = f"oauth_provider_scopes contains unknown provider names: {joined_names}."
        raise ValueError(msg)

    for provider_name, scopes in provider_scopes.items():
        normalized_scopes = _normalize_oauth_scopes(scopes)
        if normalized_scopes:
            normalized_provider_scopes[provider_name] = normalized_scopes

    return normalized_provider_scopes


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
            oauth_provider_scopes={},
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
        oauth_provider_scopes=_normalize_oauth_provider_scopes(
            providers=providers,
            provider_scopes=oauth_config.oauth_provider_scopes,
        ),
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
        ``db_session_dependency_key`` must be a valid non-keyword Python identifier
        because Litestar resolves dependencies by matching keys to callable parameter names.
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

    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
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

        return build_openapi_security_schemes(self.startup_backends())

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

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return authentication backends bound to the current request session.

        Returns:
            Request-scoped backends aligned with the provided SQLAlchemy session.
        """
        return resolve_backend_inventory(self).bind_request_backends(session)

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
        startup_backends = (
            _build_database_token_backend_template(
                config.database_token_auth,
                unsafe_testing=config.unsafe_testing,
            ),
        )
    else:
        startup_backends = tuple(StartupBackendTemplate.from_runtime_backend(backend) for backend in config.backends)
    return _StartupBackendInventory.from_startup_backends(startup_backends)


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
