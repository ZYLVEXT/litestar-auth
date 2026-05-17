"""Internal helpers for generated authentication controllers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.openapi.datastructures import ResponseSpec
from litestar.openapi.spec import Example

import litestar_auth._schema_fields as schema_fields
from litestar_auth.authentication.strategy.base import RefreshableStrategy
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import ConfigurationError, ErrorCode, totp_stepup_required_exception
from litestar_auth.totp import verify_totp
from litestar_auth.types import LoginIdentifier, TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request
    from litestar.response import Response

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.payloads import RefreshTokenRequest
    from litestar_auth.totp import TotpAlgorithm

type TotpStepUpEndpoint = Literal[
    "totp.disable",
    "totp.regenerate_recovery_codes",
    "api_keys.create",
    "api_keys.update",
    "api_keys.revoke",
    "users.update_self",
    "oauth.associate",
]
type TotpStepUpPolicyMode = Literal["required_when_enrolled", "always_required", "off"]

_LOGIN_EMAIL_MAX_LENGTH = schema_fields.LOGIN_IDENTIFIER_MAX_LENGTH
_LOGIN_USERNAME_MAX_LENGTH = 150
_EMAIL_PATTERN = re.compile(schema_fields.EMAIL_PATTERN)
_DEFAULT_TOTP_STEPUP_POLICY: dict[TotpStepUpEndpoint, TotpStepUpPolicyMode] = {
    "totp.disable": "required_when_enrolled",
    "totp.regenerate_recovery_codes": "required_when_enrolled",
    "api_keys.create": "required_when_enrolled",
    "api_keys.update": "required_when_enrolled",
    "api_keys.revoke": "required_when_enrolled",
    "users.update_self": "required_when_enrolled",
    "oauth.associate": "required_when_enrolled",
}
TOTP_STEPUP_REQUIRED_OPENAPI_RESPONSE = ResponseSpec(
    data_container=dict[str, object],
    generate_examples=False,
    description="The operation requires a recent TOTP verification (`TOTP_STEPUP_REQUIRED`).",
    examples=[
        Example(
            id="totp_stepup_required",
            summary="Recent TOTP verification required",
            value={
                "status_code": 403,
                "detail": "Recent TOTP verification is required.",
                "extra": {"code": ErrorCode.TOTP_STEPUP_REQUIRED.value},
            },
        ),
    ],
)


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


class TotpStepUpVerifierProtocol[UP: UserProtocol[Any]](Protocol):
    """User-manager behavior required by downstream TOTP step-up checks."""

    backends: tuple[object, ...]

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether the current session has a recent TOTP marker."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return the plain TOTP secret for verification."""


@dataclass(frozen=True, slots=True)
class TotpStepUpCheck[UP: UserProtocol[Any]]:
    """Inputs for an endpoint-level TOTP step-up check."""

    endpoint: TotpStepUpEndpoint
    policy: dict[str, TotpStepUpPolicyMode]
    user_manager: TotpStepUpVerifierProtocol[UP]
    totp_code: str | None = None
    totp_algorithm: TotpAlgorithm = "SHA256"


async def require_totp_stepup[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    check: TotpStepUpCheck[UP],
) -> None:
    """Enforce endpoint-level TOTP step-up policy before sensitive mutations."""
    mode = check.policy.get(check.endpoint, _DEFAULT_TOTP_STEPUP_POLICY[check.endpoint])
    if mode == "off":
        return
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        return
    if user.totp_secret is None:
        if mode == "always_required":
            exception = totp_stepup_required_exception()
            raise exception
        return
    secret = await check.user_manager.read_totp_secret(user.totp_secret)
    if secret is None:
        if mode == "always_required":
            exception = totp_stepup_required_exception()
            raise exception
        return
    if check.totp_code is not None and verify_totp(secret, check.totp_code, algorithm=check.totp_algorithm):
        return
    session_id = await _resolve_current_session_id(request, user_manager=check.user_manager)
    if session_id is not None and await check.user_manager.has_recent_totp_verification(cast("UP", user), session_id):
        return
    exception = totp_stepup_required_exception()
    raise exception


async def _resolve_current_session_id[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    *,
    user_manager: TotpStepUpVerifierProtocol[UP],
) -> str | None:
    """Return the current transport token to use as the step-up marker session id."""
    for backend in user_manager.backends:
        transport = getattr(backend, "transport", None)
        read_token = getattr(transport, "read_token", None)
        if read_token is None:
            continue
        token = await read_token(request)
        if isinstance(token, str) and token:
            return token
    return None
