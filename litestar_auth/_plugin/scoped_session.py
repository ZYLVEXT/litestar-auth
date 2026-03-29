"""Request-scoped AsyncSession sharing between middleware and DI (Advanced Alchemy-compatible)."""

from __future__ import annotations

from typing import Any, cast

from litestar.datastructures.state import State  # noqa: TC002
from litestar.types import Scope  # noqa: TC002
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

_AA_SCOPE_NAMESPACE: str = "_aa_connection_state"
SESSION_SCOPE_KEY: str = "_sqlalchemy_db_session"


def _get_aa_namespace(scope: Scope) -> dict[str, Any]:
    """Return the Advanced Alchemy namespace dict from the ASGI scope, creating it if needed."""
    # Scope is a TypedDict with Literal-key overloads; cast to plain dict for dynamic key access.
    raw: dict[str, Any] = cast("dict[str, Any]", scope)
    return raw.setdefault(_AA_SCOPE_NAMESPACE, {})


def get_or_create_scoped_session(
    state: State,
    scope: Scope,
    session_maker: async_sessionmaker[AsyncSession],
) -> AsyncSession:
    """Return the request-scoped session, matching Advanced Alchemy ``provide_session`` semantics.

    If a session already exists in the Advanced Alchemy scope namespace (for example from
    ``SQLAlchemyAsyncConfig.provide_session``), it is reused. Otherwise a new session is created
    from ``session_maker``, stored in scope, and returned. The caller must not close the session;
    lifecycle is handled by ``before_send`` handlers (see ``default_handler_maker`` in Advanced
    Alchemy).

    Args:
        state: Application state (reserved for parity with ``provide_session``; unused when the
            factory is supplied via closure).
        scope: ASGI connection scope.
        session_maker: Async SQLAlchemy session factory.

    Returns:
        The shared ``AsyncSession`` for this request.
    """
    del state
    namespace = _get_aa_namespace(scope)
    session: AsyncSession | None = namespace.get(SESSION_SCOPE_KEY)
    if session is None:
        session = session_maker()
        namespace[SESSION_SCOPE_KEY] = session
    return session
