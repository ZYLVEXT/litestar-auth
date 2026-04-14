"""Database-token backend construction for the Litestar auth plugin."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never, cast

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from datetime import timedelta  # pragma: no cover
    from logging import Logger  # pragma: no cover

    from sqlalchemy.ext.asyncio import AsyncSession  # pragma: no cover

    from litestar_auth._plugin.config import (  # pragma: no cover
        DatabaseTokenAuthConfig,
        LitestarAuthConfig,
        StartupBackendTemplate,
    )
    from litestar_auth.authentication.backend import AuthenticationBackend  # pragma: no cover
    from litestar_auth.authentication.strategy import DatabaseTokenModels  # pragma: no cover
    from litestar_auth.types import StrategyProtocol  # pragma: no cover


class _StartupOnlyDatabaseTokenSession:
    """Fail-closed placeholder kept for test helpers and compatibility shims.

    Request-time code must use :meth:`LitestarAuthConfig.resolve_request_backends`; the
    startup inventory from :meth:`LitestarAuthConfig.resolve_startup_backends` is not
    sufficient for session-bound database-token operations.
    """

    def __getattr__(self, name: str) -> Never:
        """Raise when startup-only backends are used for request-time DB work."""
        del name
        _raise_startup_only_database_token_runtime_error()


_STARTUP_ONLY_DATABASE_TOKEN_SESSION = _StartupOnlyDatabaseTokenSession()


def _raise_startup_only_database_token_runtime_error() -> Never:
    """Raise the canonical fail-closed error for startup-only DB-token backends.

    Directs operators to :meth:`LitestarAuthConfig.resolve_startup_backends` for startup
    inventory and :meth:`LitestarAuthConfig.resolve_request_backends` for request-bound
    backends.

    Raises:
        RuntimeError: Always, because backends from the startup inventory are not valid for
            request-time authentication work without a request ``AsyncSession``.
    """
    msg = (
        "LitestarAuthConfig.resolve_startup_backends() yields startup-only database-token "
        "backends that cannot run request-time authentication work against a request "
        "AsyncSession. Use LitestarAuthConfig.resolve_request_backends(session) to obtain "
        "request-scoped backend instances for login, refresh, logout, or token validation."
    )
    raise RuntimeError(msg)


def resolve_database_token_strategy_session(session: AsyncSession | None = None) -> AsyncSession:
    """Return ``session`` or a fail-closed placeholder for legacy helper paths.

    Returns:
        The provided request ``AsyncSession`` when available, otherwise a placeholder that
        raises the canonical startup-only runtime error on first use. Prefer obtaining
        request-bound backends via :meth:`LitestarAuthConfig.resolve_request_backends`; the
        startup inventory from :meth:`LitestarAuthConfig.resolve_startup_backends` uses an
        explicit startup-only strategy wrapper instead of this placeholder.
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
    from litestar_auth.authentication.strategy.db import (  # noqa: PLC0415
        DatabaseTokenStrategy,
        build_legacy_plaintext_tokens_warning_message,
    )
    from litestar_auth.authentication.strategy.db import (  # noqa: PLC0415
        logger as database_token_logger,
    )
    from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels  # noqa: PLC0415

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
    from litestar_auth.authentication.backend import AuthenticationBackend  # noqa: PLC0415
    from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy  # noqa: PLC0415
    from litestar_auth.authentication.transport.bearer import BearerTransport  # noqa: PLC0415

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


def build_database_token_backend[UP: UserProtocol[Any], ID](
    database_token_auth: DatabaseTokenAuthConfig,
    *,
    session: AsyncSession,
    unsafe_testing: bool = False,
) -> AuthenticationBackend[UP, ID]:
    """Return the canonical DB-token backend for the provided request session.

    Uses the module-local :func:`_build_database_token_backend` implementation. Tests that need a
    seam should patch that helper on this module (not :mod:`litestar_auth._plugin.config`).

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
    from litestar_auth._plugin.config import StartupBackendTemplate  # noqa: PLC0415

    startup_backend = _build_database_token_backend(
        database_token_auth,
        unsafe_testing=unsafe_testing,
    )
    return StartupBackendTemplate.from_runtime_backend(startup_backend)


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
