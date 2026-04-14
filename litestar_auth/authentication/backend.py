"""Authentication backend composition for transport and strategy pairs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.response import Response

from litestar_auth.authentication.strategy.base import SessionBindable, TokenInvalidationCapable
from litestar_auth.authentication.transport.base import LogoutTokenReadable
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import TokenError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_auth.authentication.strategy.base import UserManagerProtocol
    from litestar_auth.types import StrategyProtocol, TransportProtocol


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

    async def login(self, user: UP) -> Response[Any]:
        """Issue a token through the configured strategy and transport.

        Returns:
            Response mutated by the configured transport for login.
        """
        token = await self.strategy.write_token(user)
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
        token = await self.transport.read_token(connection)
        return await self.strategy.read_token(token, user_manager)


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

    bindable = cast("SessionBindable[UP, ID, S]", strategy)
    return cast("StrategyProtocol[UP, ID]", bindable.with_session(session))


async def _invalidate_refresh_artifacts[UP: UserProtocol[Any], ID](
    strategy: StrategyProtocol[UP, ID],
    user: UP,
) -> None:
    """Invalidate refresh/session artifacts for strategies that support full revocation."""
    if isinstance(strategy, TokenInvalidationCapable):
        revocation_strategy = cast("TokenInvalidationCapable[UP]", strategy)
        await revocation_strategy.invalidate_all_tokens(user)
