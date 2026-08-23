"""Request-scoped AsyncSession sharing between middleware and DI (Advanced Alchemy-compatible)."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, cast

from advanced_alchemy.extensions.litestar.plugins.init.config.common import SESSION_SCOPE_KEY
from litestar.datastructures.state import State
from litestar.types import Scope
from sqlalchemy.ext.asyncio import AsyncSession

_AA_SCOPE_NAMESPACE: str = "_aa_connection_state"
_AUTH_REQUEST_SCOPE_NAMESPACE = "_litestar_auth_request_state"
_BORROWED_SESSION_KEY = "borrowed_session"


class SessionFactory(Protocol):
    """Structural contract for plugin-compatible request session factories."""

    def __call__(self) -> AsyncSession:
        """Return the request-local AsyncSession instance."""


type _RequestSessionProvider = Callable[[State, Scope], AsyncSession | Awaitable[AsyncSession]]
type _ResolvedRequestSessionProvider = Callable[[State, Scope], Awaitable[AsyncSession]]


def memoize_request_session_provider(provider: _RequestSessionProvider) -> _ResolvedRequestSessionProvider:
    """Wrap an application provider with request-scope identity memoization.

    The wrapper retains only a request-local reference. Session transaction and
    close ownership remain with the application provider's integration.

    Returns:
        An async provider that resolves and memoizes one session identity per request scope.
    """

    async def provide_request_session(state: State, scope: Scope) -> AsyncSession:
        raw_scope = cast("dict[str, Any]", scope)
        request_state = cast(
            "dict[str, Any]",
            raw_scope.setdefault(_AUTH_REQUEST_SCOPE_NAMESPACE, {}),
        )
        cached_session = request_state.get(_BORROWED_SESSION_KEY)
        if cached_session is not None:
            return cast("AsyncSession", cached_session)

        session_or_awaitable = provider(state, scope)
        session = cast(
            "AsyncSession",
            await session_or_awaitable if inspect.isawaitable(session_or_awaitable) else session_or_awaitable,
        )
        request_state[_BORROWED_SESSION_KEY] = session
        return session

    return provide_request_session


def _get_aa_namespace(scope: Scope) -> dict[str, Any]:
    """Return the Advanced Alchemy namespace dict from the ASGI scope, creating it if needed."""
    # Scope is a TypedDict with Literal-key overloads; cast to plain dict for dynamic key access.
    raw: dict[str, Any] = cast("dict[str, Any]", scope)
    return raw.setdefault(_AA_SCOPE_NAMESPACE, {})


def get_or_create_scoped_session(
    _state: State,
    scope: Scope,
    session_maker: SessionFactory | None,
    *,
    session_scope_key: str = SESSION_SCOPE_KEY,
) -> AsyncSession:
    """Return the request-scoped session, matching Advanced Alchemy ``provide_session`` semantics.

    If a session already exists in the Advanced Alchemy scope namespace (for example from
    ``SQLAlchemyAsyncConfig.provide_session``), it is reused. Otherwise a new session is created
    from ``session_maker``, stored in scope, and returned. The caller must not close the session;
    lifecycle is handled by ``before_send`` handlers (see ``default_handler_maker`` in Advanced
    Alchemy).

    Args:
        _state: Application state (reserved for parity with ``provide_session``; unused when the
            factory is supplied via closure).
        scope: ASGI connection scope.
        session_maker: Callable request-session factory returning an AsyncSession-compatible object.
        session_scope_key: Advanced Alchemy scope key for the request session. Must match
            ``SQLAlchemyAsyncConfig.session_scope_key`` when coexisting with ``SQLAlchemyPlugin``.

    Returns:
        The shared ``AsyncSession`` for this request.

    Raises:
        RuntimeError: If an external session was declared but is absent from request scope.
    """
    namespace = _get_aa_namespace(scope)
    session: AsyncSession | None = namespace.get(session_scope_key)
    if session is None:
        if session_maker is None:
            msg = "The externally provided request session is unavailable in the configured scope."
            raise RuntimeError(msg)
        session = session_maker()
        namespace[session_scope_key] = session
    return session
