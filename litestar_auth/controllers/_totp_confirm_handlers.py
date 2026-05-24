"""TOTP enrollment confirmation handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar_auth._totp_enrollment import _consume_enrollment_secret, _decode_enrollment_token
from litestar_auth.controllers._error_responses import raise_client_error
from litestar_auth.controllers.totp_contracts import (
    INVALID_ENROLL_TOKEN_DETAIL,
    INVALID_TOTP_CODE_DETAIL,
    TotpUserManagerProtocol,
    logger,
)
from litestar_auth.controllers.totp_handlers import _totp_raise_already_enabled, _totp_require_authenticated_user
from litestar_auth.exceptions import ErrorCode
from litestar_auth.payloads import TotpConfirmEnableRequest, TotpConfirmEnableResponse
from litestar_auth.totp import build_recovery_code_index, generate_totp_recovery_codes, verify_totp
from litestar_auth.totp_flow import InvalidTotpPendingTokenError
from litestar_auth.types import TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.totp_context import _TotpControllerContext


async def _totp_consume_confirmed_enrollment_secret(
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
    data: TotpConfirmEnableRequest,
    user: TotpUserProtocol[Any],
) -> str:
    """Decode and consume the server-side enrollment secret for confirmation.

    Returns:
        Plain TOTP secret from the consumed enrollment record.

    """
    try:
        claims = _decode_enrollment_token(
            data.enrollment_token,
            signing_key=ctx.pending_token.totp_pending_secret,
            expected_user_id=str(user.id),
            cipher=ctx.enrollment.enrollment_token_cipher,
        )
        return await _consume_enrollment_secret(
            claims,
            enrollment_store=ctx.enrollment.enrollment_store,
            cipher=ctx.enrollment.enrollment_token_cipher,
        )
    except InvalidTotpPendingTokenError:
        await ctx.runtime.rate_limit.on_invalid_attempt("confirm_enable", request)
        raise_client_error(
            status_code=400,
            detail=INVALID_ENROLL_TOKEN_DETAIL,
            error_code=ErrorCode.TOTP_ENROLL_BAD_TOKEN,
            suppress_context=True,
        )


async def _totp_verify_confirm_enable_code(
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
    secret: str,
    code: str,
) -> None:
    """Validate the enrollment confirmation TOTP code."""
    if verify_totp(secret, code, algorithm=ctx.security.totp_algorithm):
        return
    await ctx.runtime.rate_limit.on_invalid_attempt("confirm_enable", request)
    raise_client_error(
        status_code=400,
        detail=INVALID_TOTP_CODE_DETAIL,
        error_code=ErrorCode.TOTP_CODE_INVALID,
    )


async def _totp_persist_confirmed_secret[UP: UserProtocol[Any], ID](
    user: UP,
    *,
    secret: str,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> tuple[str, ...]:
    """Persist a confirmed TOTP secret and new recovery-code hashes.

    Returns:
        Plaintext recovery codes to show once.

    Raises:
        RuntimeError: If recovery-code lookup secret configuration is missing.
    """
    recovery_codes = generate_totp_recovery_codes()
    lookup_secret = user_manager.recovery_code_lookup_secret
    if lookup_secret is None:
        msg = "totp_recovery_code_lookup_secret is required to persist TOTP recovery codes."
        raise RuntimeError(msg)
    recovery_code_index = build_recovery_code_index(
        recovery_codes,
        password_helper=user_manager.password_helper,
        lookup_secret=lookup_secret,
    )
    try:
        updated_user = await user_manager.set_totp_secret(user, secret)
        await user_manager.set_recovery_code_hashes(updated_user, recovery_code_index)
    except Exception:
        await user_manager.set_totp_secret(user, None)
        raise
    return recovery_codes


async def _totp_handle_confirm_enable[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpConfirmEnableRequest,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> TotpConfirmEnableResponse:
    """Confirm TOTP enrollment by validating the enrollment token and a TOTP code.

    Returns:
        Confirmation response indicating 2FA was enabled plus the one-time
        plaintext recovery codes.
    """
    runtime = ctx.runtime
    enrollment = ctx.enrollment
    await runtime.rate_limit.before_request("confirm_enable", request)
    user = await _totp_require_authenticated_user(
        request,
        ctx=ctx,
        user_manager=user_manager,
        endpoint="confirm_enable",
    )
    await _totp_raise_already_enabled(user, ctx=ctx, endpoint="confirm_enable", request=request)
    secret = await _totp_consume_confirmed_enrollment_secret(request, ctx=ctx, data=data, user=user)
    await _totp_verify_confirm_enable_code(request, ctx=ctx, secret=secret, code=data.code)
    recovery_codes = await _totp_persist_confirmed_secret(cast("UP", user), secret=secret, user_manager=user_manager)
    await enrollment.enrollment_store.clear(user_id=str(user.id))
    logger.info("Issued %d TOTP recovery codes for user_id=%s.", len(recovery_codes), user.id)
    await runtime.rate_limit.on_success("confirm_enable", request)
    return TotpConfirmEnableResponse(enabled=True, recovery_codes=recovery_codes)
