"""Authentication backend composition for transport and strategy pairs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.response import Response

from litestar_auth.authentication.strategy.base import (
    ContextualStrategy,
    RefreshSessionAccessTokenStrategy,
    SessionBindable,
    TokenInvalidationCapable,
)
from litestar_auth.authentication.transport.base import LogoutTokenReadable
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import TokenError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_auth.authentication.strategy.base import UserManagerProtocol
    from litestar_auth.types import StrategyProtocol, TransportProtocol


class _AuthenticationResultWithContext[UP: UserProtocol[Any]](Protocol):
    """Structural result returned by contextual strategies."""

    user: UP
    context: object


class AuthenticationBackend[UP: UserProtocol[Any], ID]:
    """Compose a transport and strategy into a reusable auth backend."""

    def __init__(self, *, name: str, transport: TransportProtocol, strategy: StrategyProtocol[UP, ID]) -> None:
        """Store backend components used for auth flows."""
        self.name = name
        self.transport = transport
        self.strategy = strategy

    def with_session[S](self, session: S) -> AuthenticationBackend[UP, ID]:
        """Return a backend whose strategy is rebound to the provided session when supported."""
        bound_strategy = _bind_strategy_session(self.strategy, session)
        if bound_strategy is self.strategy:
            return self

        return type(self)(name=self.name, transport=self.transport, strategy=bound_strategy)

    async def login(self, user: UP, *, session_id: str | None = None) -> Response[Any]:
        """Issue a token through the configured strategy and transport.

        Returns:
            Response mutated by the configured transport for login.

        Raises:
            TypeError: If session binding is requested for an unsupported strategy.
        """
        if session_id is None:
            token = await self.strategy.write_token(user)
        elif isinstance(self.strategy, RefreshSessionAccessTokenStrategy):
            session_strategy = cast("RefreshSessionAccessTokenStrategy[UP]", self.strategy)
            token = await session_strategy.write_token_for_session(user, session_id)
        else:
            msg = "The configured authentication strategy cannot bind access tokens to refresh sessions."
            raise TypeError(msg)
        return self.transport.set_login_token(Response(content=None), token)

    async def logout(self, user: UP, token: str) -> Response[Any]:
        """Invalidate a token and clear transport-managed state.

        When the transport is a :class:`CookieTransport`, the refresh-token
        cookie is also expired so the browser does not retain it after logout.

        Returns:
            Response mutated by the configured transport for logout.

        Raises:
            ClientException: When token revocation cannot be recorded (for example, an
                in-memory denylist at capacity), surfaced as HTTP 503 with the library
                error ``code`` in the JSON body.
        """
        try:
            await self.strategy.destroy_token(token, user)
        except TokenError as exc:
            raise ClientException(
                status_code=503,
                detail=str(exc),
                extra={"code": exc.code},
            ) from exc
        response = self.transport.set_logout(Response(content=None))
        if isinstance(self.transport, CookieTransport):
            self.transport.clear_refresh_token(response)
        return response

    async def terminate_session(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        user: UP,
    ) -> Response[Any]:
        """Terminate the current authenticated session for a connection.

        This method orchestrates logout in one explicit place by reading the
        current transport token and delegating token invalidation plus transport
        cleanup to ``logout``.

        Returns:
            Response mutated by the configured transport for logout.

        Raises:
            NotAuthorizedException: If the current transport token is unavailable.
        """
        read_token = self.transport.read_token
        if isinstance(self.transport, LogoutTokenReadable):
            read_token = self.transport.read_logout_token
        token = await read_token(connection)
        if token is None:
            msg = "Authentication credentials were not provided."
            raise NotAuthorizedException(detail=msg)
        await _invalidate_refresh_artifacts(self.strategy, user)
        return await self.logout(user, token)

    async def authenticate(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        user_manager: UserManagerProtocol[UP, ID],
    ) -> UP | None:
        """Resolve a user from the current request via transport and strategy.

        Returns:
            Authenticated user or ``None`` when no valid token is present.
        """
        result = await self.authenticate_with_context(connection, user_manager)
        return None if result is None else result[0]

    async def authenticate_with_context(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
        user_manager: UserManagerProtocol[UP, ID],
    ) -> tuple[UP, object] | None:
        """Resolve a user and request auth context from the current request.

        Returns:
            Authenticated user plus request auth context, or ``None`` when no valid token is present.
        """
        token = await self.transport.read_token(connection)
        if isinstance(self.strategy, ContextualStrategy):
            # Runtime-checkable generic protocols do not preserve the AuthT parameter after isinstance narrowing.
            contextual_strategy = cast(
                "ContextualStrategy[UP, ID, _AuthenticationResultWithContext[UP]]",
                self.strategy,
            )
            result = await contextual_strategy.read_token_with_context(token, user_manager)
            if result is None:
                return None
            return result.user, result.context

        user = await self.strategy.read_token(token, user_manager)
        if user is None:
            return None
        return user, self.name


def _bind_strategy_session[UP: UserProtocol[Any], ID, S](
    strategy: StrategyProtocol[UP, ID],
    session: S,
) -> StrategyProtocol[UP, ID]:
    """Bind a strategy to a request-local session when the strategy supports it.

    Returns:
        The rebound strategy, or the original strategy when session binding is unsupported.
    """
    if not isinstance(strategy, SessionBindable):
        return strategy

    # SessionBindable is checked structurally at runtime, but the session type parameter is known only to callers.
    bindable = cast("SessionBindable[UP, ID, S]", strategy)
    return bindable.with_session(session)


async def _invalidate_refresh_artifacts[UP: UserProtocol[Any], ID](
    strategy: StrategyProtocol[UP, ID],
    user: UP,
) -> None:
    """Invalidate refresh/session artifacts for strategies that support full revocation."""
    if isinstance(strategy, TokenInvalidationCapable):
        # Runtime-checkable generic protocols narrow their type parameter to Never here.
        revocation_strategy = cast("TokenInvalidationCapable[UP]", strategy)
        await revocation_strategy.invalidate_all_tokens(user)
