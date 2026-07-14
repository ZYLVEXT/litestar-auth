"""TOTP verify, disable, and recovery-code rotation handlers."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._totp_recovery import _consume_matching_recovery_code
from litestar_auth.controllers._auth_helpers import (
    _attach_refresh_token,
    _record_refresh_token_request_context,
    _resolve_access_token_session_id,
    _resolve_cookie_transport,
)
from litestar_auth.controllers._error_responses import (
    INVALID_REQUEST_PAYLOAD_DETAIL,
    raise_client_error,
    raise_invalid_login_payload,
    raise_not_authorized,
    raise_transient_token_error,
)
from litestar_auth.controllers._step_up import TotpStepUpCheck, require_totp_stepup
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
    _TotpPasswordStepUpRequest,
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
    abuild_recovery_code_index,
    generate_totp_recovery_codes,
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


def _extract_login_session_id(response: object) -> str | None:
    """Return the issued bearer access token when exposed in the login response body."""
    content = getattr(response, "content", None)
    if not isinstance(content, dict):
        return None
    token = content.get("access_token")
    return token if isinstance(token, str) and token else None


async def _totp_fail_invalid_pending(
    request: Request[Any, Any, Any],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> None:
    """Record a failed verify attempt and raise a pending-token client error."""
    await totp_rate_limit.on_invalid_attempt("verify", request)
    raise_client_error(
        status_code=400,
        detail=INVALID_TOTP_TOKEN_DETAIL,
        error_code=ErrorCode.TOTP_PENDING_BAD_TOKEN,
    )


def _build_totp_login_flow[ID](
    *,
    ctx: _TotpControllerContext[Any, ID],
    user_manager: TotpUserManagerProtocol[TotpUserProtocol[Any], ID],
) -> TotpLoginFlowService[TotpUserProtocol[Any], ID]:
    """Build the pending-login TOTP service for a verify request.

    Returns:
        Login-flow service bound to the request-scoped user manager.
    """
    security = ctx.security
    pending_token = ctx.pending_token
    return TotpLoginFlowService[TotpUserProtocol[Any], ID](
        user_manager=user_manager,
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
        pending_secret=pending_token.totp_pending_secret,
        trusted_proxy=pending_token.totp_pending_client_binding_trusted_proxy,
        trusted_headers=pending_token.totp_pending_client_binding_trusted_headers,
        trusted_proxy_hops=pending_token.totp_pending_client_binding_trusted_proxy_hops,
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

    """
    runtime = ctx.runtime
    pending_token = ctx.pending_token
    totp_rate_limit = runtime.rate_limit
    totp_login_flow = _build_totp_login_flow(
        ctx=ctx,
        user_manager=cast("TotpUserManagerProtocol[TotpUserProtocol[Any], ID]", user_manager),
    )

    try:
        completed_login = await totp_login_flow.authenticate_pending_login_with_method(
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
        raise_client_error(
            status_code=400,
            detail=INVALID_TOTP_CODE_DETAIL,
            error_code=ErrorCode.TOTP_CODE_INVALID,
            suppress_context=True,
        )
    except TokenError as exc:
        raise_transient_token_error(exc)

    verified_user = cast("UP", completed_login.user)
    await totp_rate_limit.on_success("verify", request)
    if runtime.refresh_strategy is not None:
        _record_refresh_token_request_context(runtime.refresh_strategy, request)
        refresh_token = await runtime.refresh_strategy.write_refresh_token(verified_user)
        refresh_session_id = await _resolve_access_token_session_id(
            runtime.backend,
            runtime.refresh_strategy,
            verified_user,
            refresh_token,
        )
        response = await runtime.backend.login(verified_user, session_id=refresh_session_id)
        response = _attach_refresh_token(
            response,
            refresh_token,
            cookie_transport=_resolve_cookie_transport(runtime.backend),
        )
    else:
        refresh_session_id = None
        response = await runtime.backend.login(verified_user)
    session_id = refresh_session_id or _extract_login_session_id(response)
    if session_id is not None and (not completed_login.used_recovery_code or ctx.security.totp_stepup_allow_recovery):
        await user_manager.issue_totp_stepup_verification(
            verified_user,
            session_id,
            ttl_seconds=ctx.security.totp_stepup_ttl_seconds,
        )
    from litestar_auth._manager.hooks import dispatch_after_login  # noqa: PLC0415

    await dispatch_after_login(user_manager, verified_user)
    return response


async def _totp_handle_disable[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpDisableRequest,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> None:
    """Disable TOTP after verifying the current code."""
    runtime = ctx.runtime
    security = ctx.security
    enrollment = ctx.enrollment
    await runtime.rate_limit.before_request("disable", request)
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        raise_not_authorized()
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
        raise_client_error(status_code=400, detail=INVALID_TOTP_CODE_DETAIL, error_code=ErrorCode.TOTP_CODE_INVALID)
    if not recovery_code_verified:
        await require_totp_stepup(
            request,
            TotpStepUpCheck(
                endpoint="totp.disable",
                policy=security.totp_stepup_policy,
                user_manager=user_manager,
                totp_code=data.code,
                totp_algorithm=security.totp_algorithm,
            ),
        )
    await user_manager.set_totp_secret(user, None)
    await user_manager.set_recovery_code_hashes(user, {})
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

    Raises:
        RuntimeError: If recovery-code lookup secret configuration is missing.
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
        if payload.current_password is None:
            await runtime.rate_limit.on_invalid_attempt("regenerate_recovery_codes", request)
            raise_invalid_login_payload(INVALID_REQUEST_PAYLOAD_DETAIL)
        await _totp_verify_current_password(
            _TotpPasswordStepUpRequest(
                request=request,
                user=user,
                endpoint="regenerate_recovery_codes",
                user_manager=user_manager,
                ctx=ctx,
            ),
            password=payload.current_password,
        )
        totp_code = payload.totp_code
    else:
        payload = (
            await _totp_resolve_regenerate_payload(request, runtime=runtime, data=data) if data is not None else None
        )
        totp_code = None if payload is None else payload.totp_code

    await require_totp_stepup(
        request,
        TotpStepUpCheck(
            endpoint="totp.regenerate_recovery_codes",
            policy=security.totp_stepup_policy,
            user_manager=user_manager,
            totp_code=totp_code,
            totp_algorithm=security.totp_algorithm,
        ),
    )

    recovery_codes = generate_totp_recovery_codes()
    lookup_secret = user_manager.recovery_code_lookup_secret
    if lookup_secret is None:
        msg = "totp_recovery_code_lookup_secret is required to persist TOTP recovery codes."
        raise RuntimeError(msg)
    recovery_code_index = await abuild_recovery_code_index(
        recovery_codes,
        password_helper=user_manager.password_helper,
        lookup_secret=lookup_secret,
    )
    await user_manager.set_recovery_code_hashes(cast("UP", user), recovery_code_index)
    logger.info("Regenerated %d TOTP recovery codes for user_id=%s.", len(recovery_codes), user.id)
    await runtime.rate_limit.on_success("regenerate_recovery_codes", request)
    return TotpRecoveryCodesResponse(recovery_codes=recovery_codes)
