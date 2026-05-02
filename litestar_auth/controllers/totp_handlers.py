"""Business handlers for generated TOTP controller routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never, cast

from litestar.exceptions import ClientException, NotAuthorizedException

from litestar_auth._totp_enrollment import (
    _consume_enrollment_secret,
    _decode_enrollment_token,
    _EnrollmentTokenIssueConfig,
    _issue_enrollment_token,
)
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    RequestBodyErrorConfig,
    _require_account_state,
)
from litestar_auth.controllers._utils import _decode_request_body as _default_decode_request_body
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.controllers.totp_contracts import (
    INVALID_ENROLL_TOKEN_DETAIL,
    INVALID_TOTP_CODE_DETAIL,
    TotpUserManagerProtocol,
    logger,
)
from litestar_auth.exceptions import ErrorCode, TokenError
from litestar_auth.payloads import (
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpRegenerateRecoveryCodesRequest,
)
from litestar_auth.totp import (
    generate_totp_recovery_codes,
    generate_totp_secret,
    generate_totp_uri,
    hash_totp_recovery_codes,
    verify_totp,
)
from litestar_auth.totp_flow import (
    InvalidTotpPendingTokenError,
)
from litestar_auth.types import TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.controllers.totp_context import (
        _TotpControllerContext,
        _TotpControllerRuntimeContext,
    )
    from litestar_auth.ratelimit import TotpSensitiveEndpoint


@dataclass(slots=True)
class _TotpPasswordStepUpContext[UP: UserProtocol[Any], ID]:
    """Runtime inputs for current-password step-up checks."""

    request: Request[Any, Any, Any]
    runtime: _TotpControllerRuntimeContext[UP, ID]
    user: TotpUserProtocol[Any]
    user_manager: TotpUserManagerProtocol[UP, ID]
    endpoint: TotpSensitiveEndpoint


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

    Raises:
        NotAuthorizedException: When the request has no authenticated TOTP user.
    """
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    await _require_account_state(
        user,
        require_verified=ctx.security.requires_verification,
        user_manager=cast("AccountStateValidatorProvider[TotpUserProtocol[Any]]", user_manager),
        on_failure=lambda: ctx.runtime.rate_limit.on_account_state_failure(endpoint, request),
    )
    return user


def _raise_invalid_totp_payload() -> Never:
    """Raise the stable invalid TOTP request-body response.

    Raises:
        ClientException: Always, with ``LOGIN_PAYLOAD_INVALID``.
    """
    msg = "Invalid request payload."
    raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})


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


async def _decode_totp_request_body(
    request: Request[Any, Any, Any],
    *,
    schema: type[Any],
    error_config: RequestBodyErrorConfig,
) -> object:
    """Decode TOTP request bodies through the historical controller monkeypatch seam.

    Returns:
        Decoded request body payload.
    """
    from litestar_auth.controllers import totp as totp_facade  # noqa: PLC0415

    decoder = getattr(totp_facade, "_decode_request_body", _default_decode_request_body)
    return await decoder(request, schema=schema, error_config=error_config)


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
    decoded = await _decode_totp_request_body(
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
    decoded = await _decode_totp_request_body(
        request,
        schema=TotpRegenerateRecoveryCodesRequest,
        error_config=_totp_request_body_error_config(runtime, "regenerate_recovery_codes"),
    )
    if not isinstance(decoded, TotpRegenerateRecoveryCodesRequest):
        _raise_invalid_totp_payload()
    return decoded


async def _totp_verify_current_password[UP: UserProtocol[Any], ID](
    step_up: _TotpPasswordStepUpContext[UP, ID],
    *,
    password: str,
) -> None:
    """Verify the authenticated user's current password before sensitive TOTP changes.

    Raises:
        ClientException: When current-password authentication fails.
    """
    authenticated = await step_up.user_manager.authenticate(
        step_up.user.email,
        password,
        login_identifier="email",
    )
    if authenticated is None or getattr(authenticated, "id", None) != getattr(step_up.user, "id", None):
        await step_up.runtime.rate_limit.on_invalid_attempt(step_up.endpoint, step_up.request)
        raise ClientException(
            status_code=400,
            detail=INVALID_CREDENTIALS_DETAIL,
            extra={"code": ErrorCode.LOGIN_BAD_CREDENTIALS},
        )


async def _totp_raise_already_enabled(
    user: TotpUserProtocol[Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
    endpoint: TotpSensitiveEndpoint,
    request: Request[Any, Any, Any],
) -> None:
    """Raise the stable already-enabled response when the user has a TOTP secret.

    Raises:
        ClientException: When TOTP is already enabled.
    """
    if user.totp_secret is None:
        return
    await ctx.enrollment.enrollment_store.clear(user_id=str(user.id))
    await ctx.runtime.rate_limit.on_invalid_attempt(endpoint, request)
    raise ClientException(
        status_code=400,
        detail="TOTP is already enabled.",
        extra={"code": ErrorCode.TOTP_ALREADY_ENABLED},
    )


async def _totp_issue_enable_response(
    user: TotpUserProtocol[Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
) -> TotpEnableResponse:
    """Issue new TOTP enrollment material.

    Returns:
        Secret, authenticator URI, and single-use enrollment token.

    Raises:
        ClientException: When enrollment-token issuance fails.
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
        raise ClientException(status_code=503, detail=str(exc), extra={"code": exc.code}) from exc
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
            _TotpPasswordStepUpContext(
                request=request,
                runtime=runtime,
                user=user,
                user_manager=user_manager,
                endpoint="enable",
            ),
            password=payload.password,
        )

    await _totp_raise_already_enabled(user, ctx=ctx, endpoint="enable", request=request)
    response = await _totp_issue_enable_response(user, ctx=ctx)
    await runtime.rate_limit.on_success("enable", request)
    return response


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

    Raises:
        ClientException: When the enrollment token is invalid or expired.
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
        raise ClientException(
            status_code=400,
            detail=INVALID_ENROLL_TOKEN_DETAIL,
            extra={"code": ErrorCode.TOTP_ENROLL_BAD_TOKEN},
        ) from None


async def _totp_verify_confirm_enable_code(
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[Any, Any],
    secret: str,
    code: str,
) -> None:
    """Validate the enrollment confirmation TOTP code.

    Raises:
        ClientException: When the TOTP code is invalid.
    """
    if verify_totp(secret, code, algorithm=ctx.security.totp_algorithm):
        return
    await ctx.runtime.rate_limit.on_invalid_attempt("confirm_enable", request)
    raise ClientException(
        status_code=400,
        detail=INVALID_TOTP_CODE_DETAIL,
        extra={"code": ErrorCode.TOTP_CODE_INVALID},
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
    """
    recovery_codes = generate_totp_recovery_codes()
    recovery_code_hashes = hash_totp_recovery_codes(recovery_codes)
    try:
        updated_user = await user_manager.set_totp_secret(user, secret)
        await user_manager.set_recovery_code_hashes(updated_user, recovery_code_hashes)
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
