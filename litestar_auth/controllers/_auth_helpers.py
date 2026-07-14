"""Internal helpers for generated authentication controllers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from litestar.enums import MediaType

import litestar_auth._schema_fields as schema_fields
from litestar_auth.authentication.strategy.base import (
    RefreshableStrategy,
    RefreshSessionAccessTokenStrategy,
    RefreshSessionIdentifierStrategy,
)
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers._error_responses import raise_invalid_login_payload
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from litestar import Request
    from litestar.response import Response

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.payloads import RefreshTokenRequest
_LOGIN_EMAIL_MAX_LENGTH = schema_fields.LOGIN_IDENTIFIER_MAX_LENGTH
_LOGIN_USERNAME_MAX_LENGTH = 150
_EMAIL_PATTERN = re.compile(schema_fields.EMAIL_PATTERN)


def _get_refresh_strategy[UP: UserProtocol[Any], ID](strategy: object) -> RefreshableStrategy[UP, ID]:
    """Return the refresh-capable strategy or raise a configuration error.

    Raises:
        ConfigurationError: If the configured strategy does not support refresh tokens.
    """
    if isinstance(strategy, RefreshableStrategy):
        return cast("RefreshableStrategy[UP, ID]", strategy)

    msg = "enable_refresh=True requires a strategy with refresh-token support."
    raise ConfigurationError(msg)


@runtime_checkable
class RefreshTokenRequestContextRecorder(Protocol):
    """Optional strategy hook for bounded refresh-token request metadata."""

    def set_refresh_token_request_context(self, request: object) -> None:
        """Capture request context for the next refresh-token write or rotation."""


def _record_refresh_token_request_context(
    refresh_strategy: RefreshableStrategy[Any, Any],
    request: object,
) -> None:
    """Record request metadata when the concrete refresh strategy supports it."""
    if isinstance(refresh_strategy, RefreshTokenRequestContextRecorder):
        refresh_strategy.set_refresh_token_request_context(request)


async def _resolve_access_token_session_id[UP: UserProtocol[Any], ID](
    backend: AuthenticationBackend[UP, ID],
    refresh_strategy: RefreshableStrategy[UP, ID],
    user: UP,
    refresh_token: str,
) -> str | None:
    """Resolve the refresh-session id used to bind a new access token.

    Returns:
        Public refresh-session id, or ``None`` when the access strategy does not
        support session ownership.

    Raises:
        ConfigurationError: If a session-aware strategy cannot resolve the freshly
            issued refresh token.
    """
    if not isinstance(backend.strategy, RefreshSessionAccessTokenStrategy):
        return None
    if not isinstance(refresh_strategy, RefreshSessionIdentifierStrategy):
        msg = "A session-aware access strategy requires refresh-session identification support."
        raise ConfigurationError(msg)

    identifier_strategy = cast("RefreshSessionIdentifierStrategy[UP]", refresh_strategy)
    session_id = await identifier_strategy.identify_refresh_session(user, refresh_token)
    if session_id is None:
        msg = "The freshly issued refresh token could not be resolved to its session."
        raise ConfigurationError(msg)
    return session_id


def _attach_refresh_token(
    response: Response[Any],
    refresh_token: str,
    *,
    cookie_transport: CookieTransport | None = None,
) -> Response[Any]:
    """Merge a refresh token into the controller response payload.

    Returns:
        Response containing the existing access-token payload plus the refresh token.
    """
    if cookie_transport is not None:
        return cookie_transport.set_refresh_token(response, refresh_token)

    content = response.content
    payload = dict(content) if isinstance(content, Mapping) else {}
    payload["refresh_token"] = refresh_token
    response.content = payload
    response.media_type = MediaType.JSON
    return response


def _resolve_cookie_transport[UP: UserProtocol[Any], ID](
    backend: AuthenticationBackend[UP, ID],
) -> CookieTransport | None:
    """Return the backend cookie transport when refresh-cookie behavior is available."""
    transport = backend.transport
    return transport if isinstance(transport, CookieTransport) else None


async def _resolve_refresh_token_value(
    request: Request[Any, Any, Any],
    data: RefreshTokenRequest | None,
    *,
    cookie_transport: CookieTransport | None = None,
) -> str | None:
    """Return a raw refresh token from a request body or refresh cookie.

    Body values take precedence so non-cookie clients keep the same explicit request contract.
    Cookie refresh tokens are only read when the configured backend uses ``CookieTransport``.
    """
    if data is not None:
        return data.refresh_token
    if cookie_transport is None:
        return None
    return await cookie_transport.read_refresh_token(request)


def _validate_manual_cookie_auth_contract(
    backend: AuthenticationBackend[Any, Any],
    *,
    csrf_protection_managed_externally: bool,
    unsafe_testing: bool,
) -> None:
    """Fail closed when manual cookie auth is assembled without an explicit CSRF posture.

    Raises:
        ConfigurationError: If a manual cookie-auth controller lacks an explicit
            external-CSRF or controlled non-browser opt-in.
    """
    transport = backend.transport
    if not isinstance(transport, CookieTransport):
        return
    if csrf_protection_managed_externally or transport.allow_insecure_cookie_auth or unsafe_testing:
        return

    msg = (
        "Manual create_auth_controller(...) with CookieTransport requires "
        "csrf_protection_managed_externally=True, or CookieTransport(allow_insecure_cookie_auth=True) "
        "for controlled non-browser scenarios. Prefer the LitestarAuth plugin with csrf_secret for "
        "browser cookie sessions."
    )
    raise ConfigurationError(msg)


def _resolve_login_identifier(raw_identifier: str, login_identifier: LoginIdentifier) -> str:
    """Normalize and validate the login ``identifier`` for the configured mode.

    In ``email`` mode, enforces the historical email regex and max length (320).
    In ``username`` mode, enforces a stripped string length between 1 and 150.

    Returns:
        The validated identifier string (stripped in username mode).

    """
    if login_identifier == "email":
        if len(raw_identifier) > _LOGIN_EMAIL_MAX_LENGTH or _EMAIL_PATTERN.fullmatch(raw_identifier) is None:
            raise_invalid_login_payload()
        return raw_identifier

    stripped = raw_identifier.strip()
    if not stripped or len(stripped) > _LOGIN_USERNAME_MAX_LENGTH:
        raise_invalid_login_payload()
    return stripped
