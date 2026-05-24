"""Advanced Alchemy session wiring helpers for LitestarAuth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from advanced_alchemy.extensions.litestar import SQLAlchemyAsyncConfig

    from litestar_auth._plugin.scoped_session import SessionFactory


@dataclass(frozen=True, slots=True)
class AlchemyAuthSessionBinding:
    """Session fields that LitestarAuth must share with ``SQLAlchemyPlugin``."""

    session_maker: SessionFactory
    session_scope_key: str


def bind_auth_session_to_alchemy(
    alchemy: SQLAlchemyAsyncConfig,
    *,
    session_maker: SessionFactory | None = None,
) -> AlchemyAuthSessionBinding:
    """Return LitestarAuth session fields aligned with a constructed AA config.

    Call after ``SQLAlchemyAsyncConfig`` is instantiated so ``session_scope_key``
    reflects Advanced Alchemy's post-init value (including registry suffixes such as
    ``_sqlalchemy_db_session_1`` when multiple configs are created in one process).

    Args:
        alchemy: Constructed Advanced Alchemy async plugin configuration.
        session_maker: Optional request session factory. When omitted,
            ``alchemy.create_session_maker()`` is used.

    Returns:
        Session factory and scope key to pass into ``LitestarAuthConfig``.
    """
    resolved_session_maker = session_maker if session_maker is not None else alchemy.create_session_maker()
    return AlchemyAuthSessionBinding(
        session_maker=resolved_session_maker,
        session_scope_key=alchemy.session_scope_key,
    )
