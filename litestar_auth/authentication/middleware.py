"""Authentication middleware that resolves users without forcing 401 responses."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, cast, overload, override

from litestar.datastructures.state import State
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.types import ASGIApp, Method, Receive, Scope, Scopes, Send

from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    normalize_superuser_role_name,
    set_scope_superuser_role_name,
)
from litestar_auth.authentication.strategy.api_key import ApiKeyContext, ApiKeyStrategy
from litestar_auth.authentication.transport._api_key_signing import API_KEY_SIGNED_BODY_SCOPE_KEY
from litestar_auth.authentication.transport.api_key import API_KEY_HEADER_NAME, ApiKeyTransport
from litestar_auth.exceptions import ErrorCode
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth.authentication.authenticator import Authenticator
    from litestar_auth.ratelimit import EndpointRateLimit
else:  # pragma: no cover
    # Runtime fallback to avoid importing SQLAlchemy just for type aliases.
    AsyncSession = Any

type AuthenticatorFactory[UP: UserProtocol[Any], ID] = Callable[[AsyncSession], Authenticator[UP, ID]]
type RequestSessionProvider = Callable[[State, Scope], AsyncSession]
logger = logging.getLogger(__name__)

_DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES = 1024 * 1024
_DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES = 1024
_HTTP_REQUEST_ENTITY_TOO_LARGE = 413


@dataclass(frozen=True, slots=True)
class LitestarAuthMiddlewareConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :class:`LitestarAuthMiddleware`."""

    get_request_session: RequestSessionProvider
    authenticator_factory: AuthenticatorFactory[UP, ID]
    auth_cookie_names: frozenset[bytes] = frozenset()
    api_key_use_rate_limit: EndpointRateLimit | None = None
    api_key_backend_present: bool = False
    api_key_signed_body_max_bytes: int = _DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES
    api_key_signed_body_max_messages: int = _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
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
    api_key_use_rate_limit: NotRequired[EndpointRateLimit | None]
    api_key_backend_present: NotRequired[bool]
    api_key_signed_body_max_bytes: NotRequired[int]
    api_key_signed_body_max_messages: NotRequired[int]
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
        self.api_key_use_rate_limit = settings.api_key_use_rate_limit
        self._api_key_backend_present = settings.api_key_backend_present
        self.api_key_signed_body_max_bytes = settings.api_key_signed_body_max_bytes
        self.api_key_signed_body_max_messages = settings.api_key_signed_body_max_messages
        self.superuser_role_name = normalize_superuser_role_name(settings.superuser_role_name)

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Buffer signed request bodies before authentication so signatures cover raw bytes."""
        buffered_signed_body = False
        if self._api_key_backend_present and _has_signed_api_key_authorization_header(scope.get("headers", [])):
            body, receive = await _buffer_body_for_signature(
                receive,
                max_body_bytes=self.api_key_signed_body_max_bytes,
                max_messages=self.api_key_signed_body_max_messages,
            )
            cast("dict[str, Any]", scope)[API_KEY_SIGNED_BODY_SCOPE_KEY] = body
            buffered_signed_body = True
        try:
            await super().__call__(scope, receive, send)
        finally:
            if buffered_signed_body:
                cast("dict[str, Any]", scope).pop(API_KEY_SIGNED_BODY_SCOPE_KEY, None)

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
        user, auth_context = await authenticator.authenticate(connection)

        if user is not None:
            await _record_successful_api_key_use_if_applicable(
                connection,
                authenticator=authenticator,
                auth_context=auth_context,
            )

        if user is None and _request_supplied_auth_credentials(connection, auth_cookie_names=self.auth_cookie_names):
            await _raise_api_key_authentication_failure_if_applicable(
                connection,
                authenticator=authenticator,
                api_key_use_rate_limit=self.api_key_use_rate_limit,
            )
            logger.warning("Authentication token validation failed", extra={"event": "token_validation_failed"})
        return AuthenticationResult(user=user, auth=auth_context)


async def _record_successful_api_key_use_if_applicable[UP: UserProtocol[Any], ID](
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    authenticator: Authenticator[UP, ID],
    auth_context: object | None,
) -> None:
    """Apply API-key use accounting after a successful API-key authentication."""
    if not isinstance(auth_context, ApiKeyContext):
        return
    connection.scope["auth"] = auth_context
    record_api_key_used = getattr(authenticator.user_manager, "record_api_key_used", None)
    if callable(record_api_key_used):
        await record_api_key_used(auth_context.key_id)


async def _raise_api_key_authentication_failure_if_applicable[UP: UserProtocol[Any], ID](
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    authenticator: Authenticator[UP, ID],
    api_key_use_rate_limit: EndpointRateLimit | None,
) -> None:
    """Raise structured API-key auth failures after all backends failed.

    Raises:
        NotAuthorizedException: If a failed credential belongs to the API-key transport.
    """
    backends = getattr(authenticator, "backends", ())
    if not isinstance(backends, list | tuple):
        return
    for backend in backends:
        if not isinstance(backend.transport, ApiKeyTransport) or not isinstance(backend.strategy, ApiKeyStrategy):
            continue
        token = await backend.transport.read_token(connection)
        if token is None:
            continue
        if api_key_use_rate_limit is not None:
            await api_key_use_rate_limit.before_request(cast("Any", connection))
            await api_key_use_rate_limit.increment(cast("Any", connection))
        code = await _resolve_api_key_failure_code(token, backend.strategy)
        raise NotAuthorizedException(detail="API-key authentication failed.", extra={"code": code})


async def _resolve_api_key_failure_code(token: str, strategy: ApiKeyStrategy[Any, Any]) -> ErrorCode:
    return await strategy.classify_failure_code(token)


def _request_supplied_auth_credentials(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    auth_cookie_names: frozenset[bytes],
) -> bool:
    """Return whether the request carried auth credentials that failed to resolve."""
    headers = connection.scope.get("headers", [])
    if any(name in {b"authorization", API_KEY_HEADER_NAME.lower().encode()} for name, _ in headers):
        return True

    if not auth_cookie_names:
        return False

    for name, value in headers:
        if name != b"cookie":
            continue
        if _cookie_header_contains_any_cookie_name(value, auth_cookie_names):
            return True

    return False


def _has_signed_api_key_authorization_header(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    """Return whether any raw Authorization header uses the signed API-key scheme."""
    return any(name.lower() == b"authorization" and value.startswith(b"LSA1-HMAC-SHA256 ") for name, value in headers)


def _cookie_header_contains_any_cookie_name(cookie_header: bytes, cookie_names: frozenset[bytes]) -> bool:
    """Return whether the cookie header contains at least one of the provided cookie names."""
    for raw_pair in cookie_header.split(b";"):
        raw_key, _, _ = raw_pair.strip().partition(b"=")
        if raw_key in cookie_names:
            return True
    return False


async def _buffer_body_for_signature(
    receive: Receive,
    *,
    max_body_bytes: int = _DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES,
    max_messages: int = _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES,
) -> tuple[bytes, Receive]:
    """Read the request body once and return a replayable receive callable.

    Returns:
        Buffered body bytes plus a receive callable that replays the original messages.

    Raises:
        ClientException: If the signed request body exceeds ``max_body_bytes``.
    """
    messages: list[Any] = []
    chunks: list[bytes] = []
    buffered_size = 0
    while True:
        message = await receive()
        messages.append(message)
        if len(messages) > max_messages:
            msg = "Signed API-key request body is too large."
            raise ClientException(
                status_code=_HTTP_REQUEST_ENTITY_TOO_LARGE,
                detail=msg,
                extra={"code": ErrorCode.REQUEST_BODY_INVALID},
            )
        if message.get("type") == "http.request":
            body = message.get("body", b"")
            if isinstance(body, bytes):
                buffered_size += len(body)
                if buffered_size > max_body_bytes:
                    msg = "Signed API-key request body is too large."
                    raise ClientException(
                        status_code=_HTTP_REQUEST_ENTITY_TOO_LARGE,
                        detail=msg,
                        extra={"code": ErrorCode.REQUEST_BODY_INVALID},
                    )
                chunks.append(body)
            if not message.get("more_body", False):
                break
        else:
            break

    async def replay_receive() -> object:
        await asyncio.sleep(0)
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    return b"".join(chunks), cast("Receive", replay_receive)
