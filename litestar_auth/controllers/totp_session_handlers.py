"""TOTP verify, disable, and recovery-code rotation handlers."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, cast

from litestar.exceptions import ClientException, NotAuthorizedException

from litestar_auth.controllers._utils import AccountStateValidatorProvider, _require_account_state
from litestar_auth.controllers.totp_contracts import (
    INVALID_TOTP_CODE_DETAIL,
    INVALID_TOTP_TOKEN_DETAIL,
    TotpUserManagerProtocol,
    logger,
)
from litestar_auth.controllers.totp_handlers import (
    _totp_require_authenticated_user,
    _totp_resolve_regenerate_payload,
    _totp_verify_current_password,
    _TotpPasswordStepUpContext,
)
from litestar_auth.exceptions import ErrorCode, TokenError
from litestar_auth.payloads import (
    TotpDisableRequest,
    TotpRecoveryCodesResponse,
    TotpRegenerateRecoveryCodesRequest,
    TotpVerifyRequest,
)
from litestar_auth.totp import (
    TotpReplayProtection,
    _consume_matching_recovery_code,
    generate_totp_recovery_codes,
    hash_totp_recovery_codes,
    verify_totp_with_store,
)
from litestar_auth.totp_flow import (
    InvalidTotpCodeError,
    InvalidTotpPendingTokenError,
    PendingTotpClientBinding,
    TotpLoginFlowConfig,
    TotpLoginFlowService,
    build_pending_totp_client_binding,
)
from litestar_auth.types import TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.totp_context import _TotpControllerContext, _TotpPendingTokenContext
    from litestar_auth.ratelimit import TotpRateLimitOrchestrator


async def _totp_fail_invalid_pending(
    request: Request[Any, Any, Any],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> None:
    """Record a failed verify attempt and raise a pending-token client error.

    Raises:
        ClientException: Always, with ``TOTP_PENDING_BAD_TOKEN``.
    """
    await totp_rate_limit.on_invalid_attempt("verify", request)
    raise ClientException(
        status_code=400,
        detail=INVALID_TOTP_TOKEN_DETAIL,
        extra={"code": ErrorCode.TOTP_PENDING_BAD_TOKEN},
    )


def _build_totp_login_flow[ID](
    *,
    ctx: _TotpControllerContext[Any, ID],
    user_manager: TotpUserManagerProtocol[Any, ID],
) -> TotpLoginFlowService[TotpUserProtocol[Any], ID]:
    """Build the pending-login TOTP service for a verify request.

    Returns:
        Login-flow service bound to the request-scoped user manager.
    """
    security = ctx.security
    pending_token = ctx.pending_token
    return TotpLoginFlowService[TotpUserProtocol[Any], ID](
        user_manager=cast("Any", user_manager),
        config=TotpLoginFlowConfig(
            totp_pending_secret=pending_token.totp_pending_secret,
            totp_algorithm=security.totp_algorithm,
            require_replay_protection=security.require_replay_protection,
            used_tokens_store=security.used_tokens_store,
            pending_jti_store=pending_token.effective_pending_jti_store,
            id_parser=pending_token.id_parser,
            require_client_binding=pending_token.totp_pending_require_client_binding,
            unsafe_testing=security.unsafe_testing,
        ),
    )


def _totp_pending_client_binding(
    request: Request[Any, Any, Any],
    *,
    pending_token: _TotpPendingTokenContext[Any],
) -> PendingTotpClientBinding | None:
    """Return the pending-token client binding required for this request.

    Returns:
        Hashed client binding, or ``None`` when binding is disabled.
    """
    if not pending_token.totp_pending_require_client_binding:
        return None
    return build_pending_totp_client_binding(
        request,
        trusted_proxy=pending_token.totp_pending_client_binding_trusted_proxy,
        trusted_headers=pending_token.totp_pending_client_binding_trusted_headers,
    )


async def _totp_validate_pending_user[UP: UserProtocol[Any], ID](
    user: TotpUserProtocol[Any],
    *,
    request: Request[Any, Any, Any],
    ctx: _TotpControllerContext[UP, ID],
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> None:
    """Apply account-state policy to a user resolved from a pending TOTP token."""
    await _require_account_state(
        user,
        require_verified=ctx.security.requires_verification,
        user_manager=cast("AccountStateValidatorProvider[TotpUserProtocol[Any]]", user_manager),
        on_failure=lambda: ctx.runtime.rate_limit.on_account_state_failure("verify", request),
    )


async def _totp_handle_verify[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpVerifyRequest,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> object:
    """Validate TOTP and exchange a pending login token for a full session.

    Returns:
        Backend login response for the verified user.

    Raises:
        ClientException: On invalid pending tokens, codes, or token-store errors.
    """
    runtime = ctx.runtime
    pending_token = ctx.pending_token
    totp_rate_limit = runtime.rate_limit
    totp_login_flow = _build_totp_login_flow(ctx=ctx, user_manager=user_manager)

    try:
        user = await totp_login_flow.authenticate_pending_login(
            pending_token=data.pending_token,
            code=data.code,
            client_binding=_totp_pending_client_binding(request, pending_token=pending_token),
            validate_user=partial(
                _totp_validate_pending_user,
                request=request,
                ctx=ctx,
                user_manager=user_manager,
            ),
        )
    except InvalidTotpPendingTokenError:
        await _totp_fail_invalid_pending(request, totp_rate_limit=totp_rate_limit)
    except InvalidTotpCodeError:
        await totp_rate_limit.on_invalid_attempt("verify", request)
        msg = INVALID_TOTP_CODE_DETAIL
        raise ClientException(
            status_code=400,
            detail=msg,
            extra={"code": ErrorCode.TOTP_CODE_INVALID},
        ) from None
    except TokenError as exc:
        raise ClientException(
            status_code=503,
            detail=str(exc),
            extra={"code": exc.code},
        ) from exc

    verified_user = cast("UP", user)
    await totp_rate_limit.on_success("verify", request)
    response = await runtime.backend.login(verified_user)
    await user_manager.on_after_login(verified_user)
    return response


async def _totp_handle_disable[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpDisableRequest,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> None:
    """Disable TOTP after verifying the current code.

    Raises:
        ClientException: When the TOTP code cannot be verified.
        NotAuthorizedException: When the request lacks an authenticated user with TOTP fields.
    """
    runtime = ctx.runtime
    security = ctx.security
    enrollment = ctx.enrollment
    await runtime.rate_limit.before_request("disable", request)
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    await _require_account_state(
        user,
        require_verified=security.requires_verification,
        user_manager=user_manager,
        on_failure=lambda: runtime.rate_limit.on_account_state_failure("disable", request),
    )
    totp_user = user
    secret = await user_manager.read_totp_secret(totp_user.totp_secret)
    totp_verified = bool(
        secret
        and await verify_totp_with_store(
            secret,
            data.code,
            replay=TotpReplayProtection(
                user_id=user.id,
                used_tokens_store=security.used_tokens_store,
                require_replay_protection=security.require_replay_protection,
                unsafe_testing=security.unsafe_testing,
            ),
            algorithm=security.totp_algorithm,
        ),
    )
    recovery_code_verified = (
        False if totp_verified else await _consume_matching_recovery_code(user_manager, user, data.code)
    )
    if not totp_verified and not recovery_code_verified:
        await runtime.rate_limit.on_invalid_attempt("disable", request)
        msg = INVALID_TOTP_CODE_DETAIL
        raise ClientException(status_code=400, detail=msg, extra={"code": ErrorCode.TOTP_CODE_INVALID})
    await user_manager.set_totp_secret(user, None)
    await user_manager.set_recovery_code_hashes(user, ())
    await enrollment.enrollment_store.clear(user_id=str(user.id))
    await runtime.rate_limit.on_success("disable", request)


async def _totp_handle_regenerate_recovery_codes[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpRegenerateRecoveryCodesRequest | None = None,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> TotpRecoveryCodesResponse:
    """Rotate the authenticated user's active TOTP recovery-code set.

    Returns:
        The new plaintext recovery codes. They are not stored and cannot be
        retrieved again.
    """
    runtime = ctx.runtime
    security = ctx.security
    await runtime.rate_limit.before_request("regenerate_recovery_codes", request)
    user = await _totp_require_authenticated_user(
        request,
        ctx=ctx,
        user_manager=user_manager,
        endpoint="regenerate_recovery_codes",
    )

    if security.totp_enable_requires_password:
        payload = await _totp_resolve_regenerate_payload(request, runtime=runtime, data=data)
        await _totp_verify_current_password(
            _TotpPasswordStepUpContext(
                request=request,
                runtime=runtime,
                user=user,
                user_manager=user_manager,
                endpoint="regenerate_recovery_codes",
            ),
            password=payload.current_password,
        )

    recovery_codes = generate_totp_recovery_codes()
    recovery_code_hashes = hash_totp_recovery_codes(recovery_codes)
    await user_manager.set_recovery_code_hashes(cast("UP", user), recovery_code_hashes)
    logger.info("Regenerated %d TOTP recovery codes for user_id=%s.", len(recovery_codes), user.id)
    await runtime.rate_limit.on_success("regenerate_recovery_codes", request)
    return TotpRecoveryCodesResponse(recovery_codes=recovery_codes)
