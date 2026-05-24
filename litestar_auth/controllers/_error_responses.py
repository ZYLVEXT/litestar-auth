"""Error-response helpers for generated controller classes."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Never

from litestar.enums import MediaType
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.openapi.spec import Example
from litestar.response import Response

from litestar_auth.exceptions import ErrorCode, TokenError, UserAlreadyExistsError

if TYPE_CHECKING:
    from litestar.background_tasks import BackgroundTask

type AccountStateFailureCallback = Callable[[], Awaitable[None]]
type DomainErrorMap = Mapping[type[Exception], tuple[int, str]]

_HTTP_BAD_REQUEST = 400
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_UNPROCESSABLE_ENTITY = 422
_HTTP_SERVICE_UNAVAILABLE = 503
AUTHENTICATION_REQUIRED_DETAIL = "Authentication credentials were not provided."
INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
INVALID_LOGIN_PAYLOAD_DETAIL = "Invalid login payload."
INVALID_REQUEST_PAYLOAD_DETAIL = "Invalid request payload."
LOGIN_UNAVAILABLE_DETAIL = "Account is not available for sign-in."
TOTP_STEPUP_REQUIRED_DETAIL = "Recent TOTP verification is required."

ERROR_RESPONSE_OPENAPI_EXAMPLES: Mapping[str, Example] = {
    ErrorCode.REQUEST_BODY_INVALID: Example(
        id="request_body_invalid",
        summary="Invalid request body",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": INVALID_REQUEST_PAYLOAD_DETAIL,
            "extra": {"code": ErrorCode.REQUEST_BODY_INVALID.value},
        },
    ),
    ErrorCode.LOGIN_BAD_CREDENTIALS: Example(
        id="login_bad_credentials",
        summary="Invalid credentials",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": INVALID_CREDENTIALS_DETAIL,
            "extra": {"code": ErrorCode.LOGIN_BAD_CREDENTIALS.value},
        },
    ),
    ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE: Example(
        id="login_account_unavailable",
        summary="Account unavailable",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": LOGIN_UNAVAILABLE_DETAIL,
            "extra": {"code": ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE.value},
        },
    ),
    ErrorCode.LOGIN_PAYLOAD_INVALID: Example(
        id="login_payload_invalid",
        summary="Invalid login payload",
        value={
            "status_code": _HTTP_UNPROCESSABLE_ENTITY,
            "detail": INVALID_REQUEST_PAYLOAD_DETAIL,
            "extra": {"code": ErrorCode.LOGIN_PAYLOAD_INVALID.value},
        },
    ),
    ErrorCode.VERIFY_USER_BAD_TOKEN: Example(
        id="verify_user_bad_token",
        summary="Invalid email verification token",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "The email verification token is invalid.",
            "extra": {"code": ErrorCode.VERIFY_USER_BAD_TOKEN.value},
        },
    ),
    ErrorCode.SUPERUSER_CANNOT_DELETE_SELF: Example(
        id="superuser_cannot_delete_self",
        summary="Superuser self-delete denied",
        value={
            "status_code": _HTTP_FORBIDDEN,
            "detail": "Superusers cannot delete their own account.",
            "extra": {"code": ErrorCode.SUPERUSER_CANNOT_DELETE_SELF.value},
        },
    ),
    ErrorCode.OAUTH_STATE_INVALID: Example(
        id="oauth_state_invalid",
        summary="Invalid OAuth state",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "Invalid OAuth state.",
            "extra": {"code": ErrorCode.OAUTH_STATE_INVALID.value},
        },
    ),
    ErrorCode.REFRESH_TOKEN_INVALID: Example(
        id="refresh_token_invalid",
        summary="Invalid refresh token",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "The refresh token is invalid.",
            "extra": {"code": ErrorCode.REFRESH_TOKEN_INVALID.value},
        },
    ),
    ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED: Example(
        id="session_management_unsupported",
        summary="Session management unsupported",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "The configured auth strategy does not support refresh-session management.",
            "extra": {"code": ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED.value},
        },
    ),
    ErrorCode.REFRESH_SESSION_NOT_FOUND: Example(
        id="refresh_session_not_found",
        summary="Refresh session not found",
        value={
            "status_code": 404,
            "detail": "Refresh session not found.",
            "extra": {"code": ErrorCode.REFRESH_SESSION_NOT_FOUND.value},
        },
    ),
    ErrorCode.TOTP_PENDING_BAD_TOKEN: Example(
        id="totp_pending_bad_token",
        summary="Invalid pending TOTP token",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "Invalid or expired 2FA pending token.",
            "extra": {"code": ErrorCode.TOTP_PENDING_BAD_TOKEN.value},
        },
    ),
    ErrorCode.TOTP_CODE_INVALID: Example(
        id="totp_code_invalid",
        summary="Invalid TOTP code",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "Invalid TOTP code.",
            "extra": {"code": ErrorCode.TOTP_CODE_INVALID.value},
        },
    ),
    ErrorCode.TOTP_ALREADY_ENABLED: Example(
        id="totp_already_enabled",
        summary="TOTP already enabled",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "TOTP is already enabled.",
            "extra": {"code": ErrorCode.TOTP_ALREADY_ENABLED.value},
        },
    ),
    ErrorCode.TOTP_ENROLL_BAD_TOKEN: Example(
        id="totp_enroll_bad_token",
        summary="Invalid TOTP enrollment token",
        value={
            "status_code": _HTTP_BAD_REQUEST,
            "detail": "Invalid or expired enrollment token.",
            "extra": {"code": ErrorCode.TOTP_ENROLL_BAD_TOKEN.value},
        },
    ),
    ErrorCode.TOTP_STEPUP_REQUIRED: Example(
        id="totp_stepup_required",
        summary="Recent TOTP verification required",
        value={
            "status_code": _HTTP_FORBIDDEN,
            "detail": TOTP_STEPUP_REQUIRED_DETAIL,
            "extra": {"code": ErrorCode.TOTP_STEPUP_REQUIRED.value},
        },
    ),
}


def _create_error_response(
    *,
    status_code: int,
    detail: str,
    extra: Mapping[str, Any] | None = None,
    background: BackgroundTask | None = None,
    headers: Mapping[str, str] | None = None,
) -> Response[dict[str, object]]:
    """Return the JSON error payload shape used by controller request-body failures."""
    payload: dict[str, object] = {
        "status_code": status_code,
        "detail": detail,
    }
    if extra is not None:
        payload["extra"] = dict(extra)
    return Response(
        content=payload,
        status_code=status_code,
        media_type=MediaType.JSON,
        background=background,
        headers=dict(headers) if headers is not None else None,
    )


def raise_client_error(
    *,
    status_code: int,
    detail: str,
    error_code: str | None = None,
    source: BaseException | None = None,
    suppress_context: bool = False,
) -> Never:
    """Raise a controller ``ClientException`` with the shared error payload shape."""
    exception = ClientException(
        status_code=status_code,
        detail=detail,
        extra=None if error_code is None else {"code": error_code},
    )
    if suppress_context:
        raise exception from None
    if source is None:
        raise exception
    raise exception from source


def raise_not_authorized(
    detail: str = AUTHENTICATION_REQUIRED_DETAIL,
    *,
    source: BaseException | None = None,
) -> Never:
    """Raise the stable unauthenticated request response."""
    exception = NotAuthorizedException(detail=detail)
    if source is None:
        raise exception
    raise exception from source


def raise_authentication_required(*, source: BaseException | None = None) -> Never:
    """Raise the controller authentication-required response."""
    raise_client_error(status_code=_HTTP_UNAUTHORIZED, detail=AUTHENTICATION_REQUIRED_DETAIL, source=source)


def raise_invalid_login_payload(
    detail: str = INVALID_LOGIN_PAYLOAD_DETAIL,
    *,
    source: BaseException | None = None,
) -> Never:
    """Raise the invalid-login-payload response."""
    raise_client_error(
        status_code=_HTTP_UNPROCESSABLE_ENTITY,
        detail=detail,
        error_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
        source=source,
    )


def raise_login_bad_credentials(*, source: BaseException | None = None) -> Never:
    """Raise the invalid-credentials login response."""
    raise_client_error(
        status_code=_HTTP_BAD_REQUEST,
        detail=INVALID_CREDENTIALS_DETAIL,
        error_code=ErrorCode.LOGIN_BAD_CREDENTIALS,
        source=source,
    )


def raise_wrong_current_password(*, source: BaseException | None = None) -> Never:
    """Raise the wrong-current-password response used by step-up checks."""
    raise_login_bad_credentials(source=source)


def raise_login_unavailable(*, source: BaseException | None = None) -> Never:
    """Raise the opaque account-state failure response."""
    raise_client_error(
        status_code=_HTTP_BAD_REQUEST,
        detail=LOGIN_UNAVAILABLE_DETAIL,
        error_code=ErrorCode.LOGIN_ACCOUNT_UNAVAILABLE,
        source=source,
    )


def raise_totp_required(*, source: BaseException | None = None) -> Never:
    """Raise the response used when a TOTP-authenticated user is required."""
    raise_not_authorized(source=source)


def raise_step_up_required(*, source: BaseException | None = None) -> Never:
    """Raise the stable TOTP step-up-required response."""
    raise_client_error(
        status_code=_HTTP_FORBIDDEN,
        detail=TOTP_STEPUP_REQUIRED_DETAIL,
        error_code=ErrorCode.TOTP_STEPUP_REQUIRED,
        source=source,
    )


def raise_request_body_invalid(detail: str, *, source: BaseException | None = None) -> Never:
    """Raise the invalid-request-body response."""
    raise_client_error(
        status_code=_HTTP_BAD_REQUEST,
        detail=detail,
        error_code=ErrorCode.REQUEST_BODY_INVALID,
        source=source,
    )


def raise_transient_token_error(exc: TokenError) -> Never:
    """Raise the token-store unavailable response for token service failures."""
    raise_client_error(status_code=_HTTP_SERVICE_UNAVAILABLE, detail=str(exc), error_code=exc.code, source=exc)


@asynccontextmanager
async def _map_domain_exceptions(
    mapping: DomainErrorMap,
    *,
    on_error: AccountStateFailureCallback | None = None,
    detail: str | None = None,
) -> AsyncIterator[None]:
    """Map configured domain exceptions into ``ClientException`` responses.

    Raises:
        ClientException: If a configured domain exception is raised in the context.
    """
    try:
        yield
    except tuple(mapping) as exc:
        if on_error is not None:
            await on_error()
        status_code, error_code = _resolve_domain_error_response(exc, mapping)
        raise ClientException(
            status_code=status_code,
            detail=detail if detail is not None else _domain_error_public_detail(exc),
            extra={"code": error_code},
        ) from exc


def _domain_error_public_detail(exc: Exception) -> str:
    """Return the client-facing detail for a mapped domain exception."""
    if isinstance(exc, UserAlreadyExistsError):
        return UserAlreadyExistsError.default_message
    return str(exc)


def _resolve_domain_error_response(
    exc: Exception,
    mapping: DomainErrorMap,
) -> tuple[int, str]:
    """Return the first mapped client response for the raised domain exception.

    Raises:
        LookupError: If ``exc`` does not match any configured exception type.
    """
    for exception_type, response in mapping.items():
        if isinstance(exc, exception_type):
            return response

    msg = f"Unmapped domain exception: {type(exc).__name__}"
    raise LookupError(msg)
