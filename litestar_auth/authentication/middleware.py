"""Authentication middleware that resolves users without forcing 401 responses."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, overload, override

from litestar.datastructures.state import State
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.types import ASGIApp, Method, Scope, Scopes

from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    normalize_superuser_role_name,
    set_scope_superuser_role_name,
)
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


@dataclass(frozen=True, slots=True)
class LitestarAuthMiddlewareConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :class:`LitestarAuthMiddleware`."""

    get_request_session: RequestSessionProvider
    authenticator_factory: AuthenticatorFactory[UP, ID]
    auth_cookie_names: frozenset[bytes] = frozenset()
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME
    exclude: str | list[str] | None = None
    exclude_from_auth_key: str = "exclude_from_auth"
    exclude_http_methods: Sequence[Method] | None = None
    scopes: Scopes | None = None


class LitestarAuthMiddlewareOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :class:`LitestarAuthMiddleware`."""

    get_request_session: Required[RequestSessionProvider]
    authenticator_factory: Required[AuthenticatorFactory[UP, ID]]
    auth_cookie_names: NotRequired[frozenset[bytes]]
    superuser_role_name: NotRequired[str]
    exclude: NotRequired[str | list[str] | None]
    exclude_from_auth_key: NotRequired[str]
    exclude_http_methods: NotRequired[Sequence[Method] | None]
    scopes: NotRequired[Scopes | None]


class LitestarAuthMiddleware[UP: UserProtocol[Any], ID](AbstractAuthenticationMiddleware):
    """Resolve request users through an authenticator built with the request-scoped DB session."""

    @overload
    def __init__(self, app: ASGIApp, *, config: LitestarAuthMiddlewareConfig[UP, ID]) -> None:
        pass  # pragma: no cover

    @overload
    def __init__(  # pragma: no cover
        self,
        app: ASGIApp,
        **options: Unpack[LitestarAuthMiddlewareOptions[UP, ID]],
    ) -> None:
        pass

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: LitestarAuthMiddlewareConfig[UP, ID] | None = None,
        **options: Unpack[LitestarAuthMiddlewareOptions[UP, ID]],
    ) -> None:
        """Initialize the middleware.

        Args:
            app: ASGI app to wrap.
            config: Middleware runtime configuration.
            **options: Individual middleware settings. Do not combine with
                ``config``.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
        """
        if config is not None and options:
            msg = "Pass either LitestarAuthMiddlewareConfig or keyword options, not both."
            raise ValueError(msg)
        settings = LitestarAuthMiddlewareConfig(**options) if config is None else config
        super().__init__(
            app=app,
            exclude=settings.exclude,
            exclude_from_auth_key=settings.exclude_from_auth_key,
            exclude_http_methods=settings.exclude_http_methods,
            scopes=settings.scopes,
        )
        self.get_request_session = settings.get_request_session
        self.authenticator_factory = settings.authenticator_factory
        self.auth_cookie_names = settings.auth_cookie_names
        self.superuser_role_name = normalize_superuser_role_name(settings.superuser_role_name)

    @override
    async def authenticate_request(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
    ) -> AuthenticationResult:
        """Authenticate the request and return the resolved user or ``None``.

        Returns:
            Authentication result containing the resolved user and backend name.
        """
        set_scope_superuser_role_name(connection.scope, self)
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
