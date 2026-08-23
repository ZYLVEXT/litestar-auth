"""Session-source validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.database_token import (
    _is_database_token_strategy_instance,
    _StartupOnlyDatabaseTokenStrategy,
)
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_session_maker_or_external_db_session[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure an HTTP request-session source is configured.

    Raises:
        ValueError: If no request-session source is configured.
    """
    has_session_maker = config.session_maker is not None
    has_external_db_session = config.db_session_dependency_provided_externally
    has_request_session_provider = config.request_session_provider is not None
    if not has_session_maker and not has_external_db_session and not has_request_session_provider:
        msg = (
            "LitestarAuth requires session_maker or db_session_dependency_provided_externally=True, "
            "or request_session_provider "
            f"(inject AsyncSession under dependency key {config.db_session_dependency_key!r})."
        )
        raise ValueError(msg)


def validate_core_session_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate constructor-time runtime-mode, backend, and session prerequisites.

    Raises:
        ValueError: If the plugin lacks a backend or a supported DB-session source.
        TypeError: If the configured backend is not a typed cookie session backend.
    """
    backends = config.resolve_startup_backends()
    if not backends:
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)
    if len(backends) != 1:
        msg = "litestar-auth 7 requires exactly one human session provider profile."
        raise ValueError(msg)
    backend = backends[0]
    supported_strategy = isinstance(
        backend.strategy, (_StartupOnlyDatabaseTokenStrategy, RedisTokenStrategy)
    ) or _is_database_token_strategy_instance(backend.strategy)
    if not isinstance(backend.transport, CookieTransport) or not supported_strategy:
        msg = (
            "litestar-auth 7 human authentication requires CookieTransport with a typed "
            "database or Redis server-side session strategy."
        )
        raise TypeError(msg)

    validate_session_maker_or_external_db_session(config)
