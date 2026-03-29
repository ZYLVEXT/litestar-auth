"""Authentication middleware that resolves users without forcing 401 responses."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, override

from litestar.datastructures.state import State
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.types import ASGIApp, Method, Scope, Scopes

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.authentication.authenticator import Authenticator
else:  # pragma: no cover
    # Runtime fallback to avoid importing SQLAlchemy just for type aliases.
    AsyncSession = Any

type AuthenticatorFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], Authenticator[UP, ID]]
type RequestSessionProvider = Callable[[State, Scope], AsyncSession]
logger = logging.getLogger(__name__)


class LitestarAuthMiddleware[UP: UserProtocol[Any], ID](AbstractAuthenticationMiddleware):
    """Resolve request users through an authenticator built with the request-scoped DB session."""

    def __init__(  # noqa: PLR0913
        self,
        app: ASGIApp,
        *,
        get_request_session: RequestSessionProvider,
        authenticator_factory: AuthenticatorFactory[UP, ID],
        auth_cookie_names: frozenset[bytes] = frozenset(),
        exclude: str | list[str] | None = None,
        exclude_from_auth_key: str = "exclude_from_auth",
        exclude_http_methods: Sequence[Method] | None = None,
        scopes: Scopes | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: ASGI app to wrap.
            get_request_session: Returns the shared request ``AsyncSession`` (Advanced Alchemy
                ``provide_session`` semantics); must not close the session.
            authenticator_factory: Factory that binds the request-local session into an authenticator.
            auth_cookie_names: Cookie names that should count as auth credentials when present.
            exclude: Optional route patterns excluded from middleware processing.
            exclude_from_auth_key: Route opt key used to bypass auth.
            exclude_http_methods: Optional HTTP methods excluded from auth.
            scopes: Optional ASGI scope types handled by the middleware.
        """
        super().__init__(
            app=app,
            exclude=exclude,
            exclude_from_auth_key=exclude_from_auth_key,
            exclude_http_methods=exclude_http_methods,
            scopes=scopes,
        )
        self.get_request_session = get_request_session
        self.authenticator_factory = authenticator_factory
        self.auth_cookie_names = auth_cookie_names

    @override
    async def authenticate_request(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
    ) -> AuthenticationResult:
        """Authenticate the request and return the resolved user or ``None``.

        Returns:
            Authentication result containing the resolved user and backend name.
        """
        session = self.get_request_session(connection.app.state, connection.scope)
        authenticator = self.authenticator_factory(session)
        user, backend_name = await authenticator.authenticate(connection)

        if user is None and _request_supplied_auth_credentials(connection, auth_cookie_names=self.auth_cookie_names):
            logger.warning("Authentication token validation failed", extra={"event": "token_validation_failed"})
        return AuthenticationResult(user=user, auth=backend_name)


def _request_supplied_auth_credentials(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    auth_cookie_names: frozenset[bytes],
) -> bool:
    """Return whether the request carried auth credentials that failed to resolve."""
    headers = connection.scope.get("headers", [])
    if any(name == b"authorization" for name, _ in headers):
        return True

    if not auth_cookie_names:
        return False

    for name, value in headers:
        if name != b"cookie":
            continue
        if _cookie_header_contains_any_cookie_name(value, auth_cookie_names):
            return True

    return False


def _cookie_header_contains_any_cookie_name(cookie_header: bytes, cookie_names: frozenset[bytes]) -> bool:
    """Return whether the cookie header contains at least one of the provided cookie names."""
    for raw_pair in cookie_header.split(b";"):
        raw_key, _, _ = raw_pair.strip().partition(b"=")
        if raw_key in cookie_names:
            return True
    return False
