"""Business handlers for generated TOTP controller routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never, cast

from litestar_auth._totp_enrollment import (
    _EnrollmentTokenIssueConfig,
    _issue_enrollment_token,
)
from litestar_auth.controllers._error_responses import (
    INVALID_REQUEST_PAYLOAD_DETAIL,
    raise_client_error,
    raise_invalid_login_payload,
    raise_totp_required,
    raise_transient_token_error,
)
from litestar_auth.controllers._step_up import PasswordStepUpCheck, PasswordStepUpUserProtocol, require_password_step_up
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    RequestBodyErrorConfig,
    _decode_request_body,
    _require_account_state,
)
from litestar_auth.exceptions import ErrorCode, TokenError
from litestar_auth.payloads import (
    TotpEnableRequest,
    TotpEnableResponse,
    TotpRegenerateRecoveryCodesRequest,
)
from litestar_auth.totp import (
    generate_totp_secret,
    generate_totp_uri,
)
from litestar_auth.types import TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.totp_context import _TotpControllerContext, _TotpControllerRuntimeContext
    from litestar_auth.controllers.totp_contracts import TotpUserManagerProtocol
    from litestar_auth.ratelimit import TotpSensitiveEndpoint


@dataclass(frozen=True, slots=True)
class _TotpPasswordStepUpRequest[UP: UserProtocol[Any], ID]:
    """Runtime inputs for a TOTP current-password step-up check."""

    request: Request[Any, Any, Any]
    user: TotpUserProtocol[Any]
    endpoint: TotpSensitiveEndpoint
    user_manager: TotpUserManagerProtocol[UP, ID]
    ctx: _TotpControllerContext[UP, ID]


async def _totp_require_authenticated_user[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    user_manager: TotpUserManagerProtocol[UP, ID],
    endpoint: TotpSensitiveEndpoint,
) -> TotpUserProtocol[Any]:
    """Return the authenticated TOTP-capable user after account-state checks.

    Returns:
        Authenticated user narrowed to the TOTP protocol.

    """
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        raise_totp_required()
    await _require_account_state(
        user,
        require_verified=ctx.security.requires_verification,
        user_manager=cast("AccountStateValidatorProvider[TotpUserProtocol[Any]]", user_manager),
        on_failure=lambda: ctx.runtime.rate_limit.on_account_state_failure(endpoint, request),
    )
    return user


def _raise_invalid_totp_payload() -> Never:
    """Raise the stable invalid TOTP request-body response."""
    raise_invalid_login_payload(INVALID_REQUEST_PAYLOAD_DETAIL)


def _totp_request_body_error_config(
    runtime: _TotpControllerRuntimeContext[Any, Any],
    endpoint: TotpSensitiveEndpoint,
) -> RequestBodyErrorConfig:
    """Return the shared invalid-payload rate-limit hooks for a TOTP endpoint.

    Returns:
        Request-body error configuration for Litestar body decoding.
    """
    return RequestBodyErrorConfig(
        validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
        on_validation_error=lambda current_request: runtime.rate_limit.on_invalid_attempt(
            endpoint,
            current_request,
        ),
        on_decode_error=lambda current_request: runtime.rate_limit.on_invalid_attempt(
            endpoint,
            current_request,
        ),
    )


async def _totp_resolve_enable_payload(
    request: Request[Any, Any, Any],
    *,
    runtime: _TotpControllerRuntimeContext[Any, Any],
    data: TotpEnableRequest | None,
) -> TotpEnableRequest:
    """Return the decoded or explicit enable step-up payload.

    Returns:
        Validated enable request payload.
    """
    if data is not None:
        if isinstance(data, TotpEnableRequest):
            return data
        _raise_invalid_totp_payload()
    decoded = await _decode_request_body(
        request,
        schema=TotpEnableRequest,
        error_config=_totp_request_body_error_config(runtime, "enable"),
    )
    if not isinstance(decoded, TotpEnableRequest):
        _raise_invalid_totp_payload()
    return decoded


async def _totp_resolve_regenerate_payload(
    request: Request[Any, Any, Any],
    *,
    runtime: _TotpControllerRuntimeContext[Any, Any],
    data: TotpRegenerateRecoveryCodesRequest | None,
) -> TotpRegenerateRecoveryCodesRequest:
    """Return the decoded or explicit recovery-code rotation step-up payload.

    Returns:
        Validated recovery-code regeneration request payload.
    """
    if data is not None:
        if isinstance(data, TotpRegenerateRecoveryCodesRequest):
            return data
        _raise_invalid_totp_payload()
    decoded = await _decode_request_body(
        request,
        schema=TotpRegenerateRecoveryCodesRequest,
        error_config=_totp_request_body_error_config(runtime, "regenerate_recovery_codes"),
    )
    if not isinstance(decoded, TotpRegenerateRecoveryCodesRequest):
        _raise_invalid_totp_payload()
    return decoded


async def _totp_verify_current_password[UP: UserProtocol[Any], ID](
    step_up: _TotpPasswordStepUpRequest[UP, ID],
    *,
    password: str,
) -> None:
    """Verify the authenticated user's current password before sensitive TOTP changes."""
    await require_password_step_up(
        PasswordStepUpCheck(
            user=cast("PasswordStepUpUserProtocol[Any]", step_up.user),
            user_manager=step_up.user_manager,
            current_password=password,
            on_failure=lambda: step_up.ctx.runtime.rate_limit.on_invalid_attempt(step_up.endpoint, step_up.request),
        ),
    )


async def _totp_raise_already_enabled(
    user: TotpUserProtocol[Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
    endpoint: TotpSensitiveEndpoint,
    request: Request[Any, Any, Any],
) -> None:
    """Raise the stable already-enabled response when the user has a TOTP secret."""
    if user.totp_secret is None:
        return
    await ctx.enrollment.enrollment_store.clear(user_id=str(user.id))
    await ctx.runtime.rate_limit.on_invalid_attempt(endpoint, request)
    raise_client_error(
        status_code=400,
        detail="TOTP is already enabled.",
        error_code=ErrorCode.TOTP_ALREADY_ENABLED,
    )


async def _totp_issue_enable_response(
    user: TotpUserProtocol[Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
) -> TotpEnableResponse:
    """Issue new TOTP enrollment material.

    Returns:
        Secret, authenticator URI, and single-use enrollment token.

    """
    security = ctx.security
    enrollment = ctx.enrollment
    pending_token = ctx.pending_token
    secret = generate_totp_secret(algorithm=security.totp_algorithm)
    uri = generate_totp_uri(secret, user.email, enrollment.totp_issuer, algorithm=security.totp_algorithm)
    try:
        enrollment_token = await _issue_enrollment_token(
            user_id=str(user.id),
            secret=secret,
            config=_EnrollmentTokenIssueConfig(
                signing_key=pending_token.totp_pending_secret,
                cipher=enrollment.enrollment_token_cipher,
                enrollment_store=enrollment.enrollment_store,
            ),
        )
    except TokenError as exc:
        raise_transient_token_error(exc)
    return TotpEnableResponse(secret=secret, uri=uri, enrollment_token=enrollment_token)


async def _totp_handle_enable[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpEnableRequest | None = None,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> TotpEnableResponse:
    """Generate a TOTP secret and associate it with the authenticated user.

    Returns:
        New secret material and ``otpauth://`` URI for authenticator enrollment.
    """
    runtime = ctx.runtime
    security = ctx.security
    await runtime.rate_limit.before_request("enable", request)
    user = await _totp_require_authenticated_user(
        request,
        ctx=ctx,
        user_manager=user_manager,
        endpoint="enable",
    )
    if security.totp_enable_requires_password:
        payload = await _totp_resolve_enable_payload(request, runtime=runtime, data=data)
        await _totp_verify_current_password(
            _TotpPasswordStepUpRequest(
                request=request,
                user=user,
                endpoint="enable",
                user_manager=user_manager,
                ctx=ctx,
            ),
            password=payload.password,
        )

    await _totp_raise_already_enabled(user, ctx=ctx, endpoint="enable", request=request)
    response = await _totp_issue_enable_response(user, ctx=ctx)
    await runtime.rate_limit.on_success("enable", request)
    return response


from litestar_auth.controllers._totp_confirm_handlers import _totp_handle_confirm_enable  # noqa: E402, F401
