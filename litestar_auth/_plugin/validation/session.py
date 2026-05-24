"""Session-source validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_session_maker_or_external_db_session[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure either a session factory or an external ``db_session`` DI binding exists.

    Raises:
        ValueError: If neither ``session_maker`` nor external session DI is configured.
    """
    has_session_maker = config.session_maker is not None
    has_external_db_session = config.db_session_dependency_provided_externally
    if not has_session_maker and not has_external_db_session:
        msg = (
            "LitestarAuth requires session_maker or db_session_dependency_provided_externally=True "
            f"(inject AsyncSession under dependency key {config.db_session_dependency_key!r})."
        )
        raise ValueError(msg)


def validate_core_session_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate constructor-time runtime-mode, backend, and session prerequisites.

    Raises:
        ValueError: If the plugin lacks a backend or a supported DB-session source.
    """
    if not config.resolve_startup_backends():
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)

    validate_session_maker_or_external_db_session(config)
