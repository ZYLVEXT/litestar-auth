"""Internal helpers for generated authentication controllers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from litestar.enums import MediaType
from litestar.exceptions import ClientException

import litestar_auth._schema_fields as schema_fields
from litestar_auth.authentication.strategy.base import RefreshableStrategy
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from litestar.response import Response

    from litestar_auth.authentication.backend import AuthenticationBackend

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

    Raises:
        ClientException: If validation fails for the selected mode.
    """
    if login_identifier == "email":
        if len(raw_identifier) > _LOGIN_EMAIL_MAX_LENGTH or _EMAIL_PATTERN.fullmatch(raw_identifier) is None:
            msg = "Invalid login payload."
            raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
        return raw_identifier

    stripped = raw_identifier.strip()
    if not stripped or len(stripped) > _LOGIN_USERNAME_MAX_LENGTH:
        msg = "Invalid login payload."
        raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
    return stripped
