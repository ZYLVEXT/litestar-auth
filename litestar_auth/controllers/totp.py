"""TOTP (2FA) controller factory for enable/verify/disable endpoints."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Never, Protocol, cast

import jwt
import msgspec  # noqa: TC002
from jwt import ExpiredSignatureError, InvalidTokenError
from litestar import Controller, Request, post
from litestar.exceptions import ClientException, NotAuthorizedException

from litestar_auth.config import TOTP_ENROLL_AUDIENCE, validate_secret_length
from litestar_auth.controllers._utils import (
    AccountStateValidatorProvider,
    _configure_request_body_handler,
    _decode_request_body,
    _mark_litestar_auth_route_handler,
    _require_account_state,
)
from litestar_auth.controllers.auth import INVALID_CREDENTIALS_DETAIL
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import (
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpVerifyRequest,
)
from litestar_auth.totp import (
    TotpAlgorithm,
    UsedTotpCodeStore,
    generate_totp_secret,
    generate_totp_uri,
    verify_totp,
    verify_totp_with_store,
)
from litestar_auth.totp_flow import InvalidTotpCodeError, InvalidTotpPendingTokenError, TotpLoginFlowService
from litestar_auth.types import LoginIdentifier, TotpUserProtocol, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.ratelimit import AuthRateLimitConfig

from litestar_auth.ratelimit import TotpRateLimitOrchestrator, TotpSensitiveEndpoint

INVALID_TOTP_TOKEN_DETAIL = "Invalid or expired 2FA pending token."
INVALID_TOTP_CODE_DETAIL = "Invalid TOTP code."
INVALID_ENROLL_TOKEN_DETAIL = "Invalid or expired enrollment token."
_TOTP_ENROLL_TOKEN_LIFETIME_SECONDS = 300  # 5 minutes
TOTP_SENSITIVE_ENDPOINTS: tuple[TotpSensitiveEndpoint, ...] = ("enable", "confirm_enable", "verify", "disable")
TOTP_RATE_LIMITED_ENDPOINTS: tuple[TotpSensitiveEndpoint, ...] = ("verify", "confirm_enable")
logger = logging.getLogger(__name__)


class TotpUserManagerProtocol[UP: UserProtocol[Any], ID](AccountStateValidatorProvider[UP], Protocol):
    """User-manager behavior required by the TOTP controller."""

    async def get(self, user_id: ID) -> UP | None:
        """Return the user for the given identifier."""

    async def on_after_login(self, user: UP) -> None:
        """Run post-login side effects for a fully authenticated user."""

    async def set_totp_secret(self, user: UP, secret: str | None) -> UP:
        """Set or clear the TOTP secret for a user."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage."""

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UP | None:
        """Re-authenticate the current user (e.g. password step-up for /enable)."""


@dataclass(slots=True)
class _TotpControllerContext[UP: UserProtocol[Any], ID]:
    """Runtime dependencies for generated TOTP controller handlers."""

    backend: AuthenticationBackend[UP, ID]
    used_tokens_store: UsedTotpCodeStore | None
    require_replay_protection: bool
    requires_verification: bool
    totp_enable_requires_password: bool
    totp_issuer: str
    totp_algorithm: TotpAlgorithm
    totp_rate_limit: TotpRateLimitOrchestrator
    totp_pending_secret: str
    effective_pending_jti_store: JWTDenylistStore | None
    id_parser: Callable[[str], ID] | None
    unsafe_testing: bool


def _totp_validate_replay_and_password(
    *,
    used_tokens_store: UsedTotpCodeStore | None,
    require_replay_protection: bool,
    totp_enable_requires_password: bool,
    user_manager: object | None,
    unsafe_testing: bool = False,
) -> None:
    """Validate TOTP controller startup constraints.

    Raises:
        ConfigurationError: When replay protection or password step-up requirements are not met.
    """
    if require_replay_protection and used_tokens_store is None and not unsafe_testing:
        msg = "used_tokens_store is required when require_replay_protection=True."
        raise ConfigurationError(msg)
    if (
        totp_enable_requires_password
        and user_manager is not None
        and not callable(
            getattr(user_manager, "authenticate", None),
        )
    ):
        msg = (
            "totp_enable_requires_password=True requires user_manager.authenticate(identifier, password) "
            "or set totp_enable_requires_password=False explicitly (not recommended)."
        )
        raise ConfigurationError(msg)


def _totp_resolve_pending_jti_store(
    pending_jti_store: JWTDenylistStore | None,
    *,
    unsafe_testing: bool,
) -> JWTDenylistStore | None:
    """Return the configured pending-token JTI store.

    Returns:
        The caller-provided store, or ``None`` in explicit unsafe-testing mode.

    Raises:
        ConfigurationError: If pending-token replay protection storage is omitted
            outside explicit ``unsafe_testing`` mode.
    """
    if pending_jti_store is not None:
        return pending_jti_store
    if unsafe_testing:
        return None

    msg = (
        "pending_jti_store is required when unsafe_testing=False. "
        "Configure a JWTDenylistStore for TOTP pending-token replay protection."
    )
    raise ConfigurationError(msg)


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

    Raises:
        ClientException: On invalid password step-up, duplicate enrollment, or bad payloads.
        NotAuthorizedException: When the request lacks an authenticated user with TOTP fields.
    """
    await ctx.totp_rate_limit.before_request("enable", request)
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    # Security: reject inactive/unverified users before allowing TOTP changes
    await _require_account_state(
        user,
        require_verified=ctx.requires_verification,
        user_manager=user_manager,
        on_failure=lambda: ctx.totp_rate_limit.on_account_state_failure("enable", request),
        prioritize_unverified=True,
    )
    totp_user = user
    if ctx.totp_enable_requires_password:
        if data is None:
            decoded = await _decode_request_body(
                request,
                schema=TotpEnableRequest,
                on_error=lambda current_request: ctx.totp_rate_limit.on_invalid_attempt("enable", current_request),
                validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
            )
            if not isinstance(decoded, TotpEnableRequest):
                msg = "Invalid request payload."
                raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
            payload = decoded
        elif not isinstance(data, TotpEnableRequest):
            msg = "Invalid request payload."
            raise ClientException(status_code=422, detail=msg, extra={"code": ErrorCode.LOGIN_PAYLOAD_INVALID})
        else:
            payload = data
        authenticated = await user_manager.authenticate(
            totp_user.email,
            payload.password,
            login_identifier="email",
        )
        if authenticated is None or getattr(authenticated, "id", None) != getattr(user, "id", None):
            await ctx.totp_rate_limit.on_invalid_attempt("enable", request)
            raise ClientException(
                status_code=400,
                detail=INVALID_CREDENTIALS_DETAIL,
                extra={"code": ErrorCode.LOGIN_BAD_CREDENTIALS},
            )

    if totp_user.totp_secret is not None:
        await ctx.totp_rate_limit.on_invalid_attempt("enable", request)
        raise ClientException(
            status_code=400,
            detail="TOTP is already enabled.",
            extra={"code": ErrorCode.TOTP_ALREADY_ENABLED},
        )

    secret = generate_totp_secret(algorithm=ctx.totp_algorithm)
    uri = generate_totp_uri(secret, totp_user.email, ctx.totp_issuer, algorithm=ctx.totp_algorithm)
    enrollment_token = _sign_enrollment_token(
        user_id=str(user.id),
        secret=secret,
        signing_key=ctx.totp_pending_secret,
    )
    await ctx.totp_rate_limit.on_success("enable", request)
    return TotpEnableResponse(secret=secret, uri=uri, enrollment_token=enrollment_token)


async def _totp_fail_invalid_pending(
    request: Request[Any, Any, Any],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> Never:
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


def _sign_enrollment_token(
    *,
    user_id: str,
    secret: str,
    signing_key: str,
    lifetime_seconds: int = _TOTP_ENROLL_TOKEN_LIFETIME_SECONDS,
) -> str:
    """Sign a short-lived JWT containing the TOTP secret for enrollment confirmation.

    Returns:
        Encoded JWT string.
    """
    issued_at = datetime.now(tz=UTC)
    payload = {
        "sub": user_id,
        "aud": TOTP_ENROLL_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(seconds=lifetime_seconds),
        "jti": secrets.token_hex(16),
        "totp_secret": secret,
    }
    return jwt.encode(payload, signing_key, algorithm="HS256")


def _decode_enrollment_token(
    token: str,
    *,
    signing_key: str,
    expected_user_id: str,
) -> str:
    """Decode and validate an enrollment JWT, returning the embedded TOTP secret.

    Returns:
        Plain-text TOTP secret extracted from the token payload.

    Raises:
        InvalidTotpPendingTokenError: On any validation failure.
    """
    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["HS256"],
            audience=TOTP_ENROLL_AUDIENCE,
            options={"require": ["exp", "aud", "iat", "nbf", "jti", "sub"]},
        )
    except (ExpiredSignatureError, InvalidTokenError) as exc:
        raise InvalidTotpPendingTokenError from exc

    if payload.get("sub") != expected_user_id:
        raise InvalidTotpPendingTokenError

    jti = payload.get("jti")
    if not isinstance(jti, str) or len(jti) != 32:  # noqa: PLR2004
        raise InvalidTotpPendingTokenError
    try:
        bytes.fromhex(jti)
    except ValueError as exc:
        raise InvalidTotpPendingTokenError from exc

    secret = payload.get("totp_secret")
    if not isinstance(secret, str) or not secret:
        raise InvalidTotpPendingTokenError

    return secret


async def _totp_handle_confirm_enable[UP: UserProtocol[Any], ID](
    request: Request[Any, Any, Any],
    *,
    ctx: _TotpControllerContext[UP, ID],
    data: TotpConfirmEnableRequest,
    user_manager: TotpUserManagerProtocol[UP, ID],
) -> TotpConfirmEnableResponse:
    """Confirm TOTP enrollment by validating the enrollment token and a TOTP code.

    Only persists the secret after the user proves they can generate valid codes.

    Returns:
        Confirmation response indicating 2FA was successfully enabled.

    Raises:
        ClientException: On invalid enrollment token, TOTP code, or duplicate enrollment.
        NotAuthorizedException: When the request lacks an authenticated user.
    """
    await ctx.totp_rate_limit.before_request("confirm_enable", request)
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)

    await _require_account_state(
        user,
        require_verified=ctx.requires_verification,
        user_manager=user_manager,
        on_failure=lambda: ctx.totp_rate_limit.on_account_state_failure("confirm_enable", request),
        prioritize_unverified=True,
    )

    if user.totp_secret is not None:
        await ctx.totp_rate_limit.on_invalid_attempt("confirm_enable", request)
        raise ClientException(
            status_code=400,
            detail="TOTP is already enabled.",
            extra={"code": ErrorCode.TOTP_ALREADY_ENABLED},
        )

    try:
        secret = _decode_enrollment_token(
            data.enrollment_token,
            signing_key=ctx.totp_pending_secret,
            expected_user_id=str(user.id),
        )
    except InvalidTotpPendingTokenError:
        await ctx.totp_rate_limit.on_invalid_attempt("confirm_enable", request)
        raise ClientException(
            status_code=400,
            detail=INVALID_ENROLL_TOKEN_DETAIL,
            extra={"code": ErrorCode.TOTP_ENROLL_BAD_TOKEN},
        ) from None

    # Use verify_totp (without replay store) — the idempotency guard
    # (totp_secret is not None) already prevents double-enrollment, and
    # keeping enrollment codes out of the used-tokens store avoids
    # false replay rejections on subsequent /verify calls.
    if not verify_totp(secret, data.code, algorithm=ctx.totp_algorithm):
        await ctx.totp_rate_limit.on_invalid_attempt("confirm_enable", request)
        raise ClientException(
            status_code=400,
            detail=INVALID_TOTP_CODE_DETAIL,
            extra={"code": ErrorCode.TOTP_CODE_INVALID},
        )

    await user_manager.set_totp_secret(user, secret)
    await ctx.totp_rate_limit.on_success("confirm_enable", request)
    return TotpConfirmEnableResponse(enabled=True)


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
        ClientException: On invalid pending tokens, codes, or account-state violations.
    """
    totp_rate_limit = ctx.totp_rate_limit
    totp_login_flow = TotpLoginFlowService[TotpUserProtocol[Any], ID](
        user_manager=cast("Any", user_manager),
        totp_pending_secret=ctx.totp_pending_secret,
        totp_algorithm=ctx.totp_algorithm,
        require_replay_protection=ctx.require_replay_protection,
        used_tokens_store=ctx.used_tokens_store,
        pending_jti_store=ctx.effective_pending_jti_store,
        id_parser=ctx.id_parser,
        unsafe_testing=ctx.unsafe_testing,
    )

    async def validate_pending_user(user: TotpUserProtocol[Any]) -> None:
        await _require_account_state(
            user,
            require_verified=ctx.requires_verification,
            on_failure=lambda: totp_rate_limit.on_account_state_failure("verify", request),
            prioritize_unverified=True,
        )

    try:
        user = await totp_login_flow.authenticate_pending_login(
            pending_token=data.pending_token,
            code=data.code,
            validate_user=validate_pending_user,
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

    verified_user = cast("UP", user)
    await totp_rate_limit.on_success("verify", request)
    response = await ctx.backend.login(verified_user)
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
    await ctx.totp_rate_limit.before_request("disable", request)
    user = request.user
    if not isinstance(user, TotpUserProtocol):
        msg = "Authentication credentials were not provided."
        raise NotAuthorizedException(detail=msg)
    # Security: reject inactive/unverified users before allowing TOTP changes
    await _require_account_state(
        user,
        require_verified=ctx.requires_verification,
        user_manager=user_manager,
        on_failure=lambda: ctx.totp_rate_limit.on_account_state_failure("disable", request),
        prioritize_unverified=True,
    )
    totp_user = user
    secret = await user_manager.read_totp_secret(totp_user.totp_secret)
    if not secret or not await verify_totp_with_store(
        secret,
        data.code,
        user_id=user.id,
        used_tokens_store=ctx.used_tokens_store,
        algorithm=ctx.totp_algorithm,
        require_replay_protection=ctx.require_replay_protection,
        unsafe_testing=ctx.unsafe_testing,
    ):
        await ctx.totp_rate_limit.on_invalid_attempt("disable", request)
        msg = INVALID_TOTP_CODE_DETAIL
        raise ClientException(status_code=400, detail=msg, extra={"code": ErrorCode.TOTP_CODE_INVALID})
    await user_manager.set_totp_secret(user, None)
    await ctx.totp_rate_limit.on_success("disable", request)


def _define_totp_controller_class_di[UP: UserProtocol[Any], ID](
    ctx: _TotpControllerContext[UP, ID],
    *,
    totp_verify_before_request: Callable[[Request[Any, Any, Any]], Any] | None,
) -> type[Controller]:
    """Build the TOTP controller with enable, confirm, verify, and disable routes (DI user manager).

    Returns:
        Controller subclass exposing ``/enable``, ``/enable/confirm``, ``/verify``,
        and ``/disable`` routes.
    """

    class _TotpControllerBase(Controller):
        """TOTP 2FA management endpoints."""

        @post("/enable/confirm", guards=[is_authenticated])
        async def confirm_enable(
            self,
            request: Request[Any, Any, Any],
            data: TotpConfirmEnableRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> TotpConfirmEnableResponse:
            del self
            return await _totp_handle_confirm_enable(
                request,
                ctx=ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

        @post("/verify", before_request=totp_verify_before_request)
        async def verify(
            self,
            request: Request[Any, Any, Any],
            data: TotpVerifyRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> object:
            del self
            return await _totp_handle_verify(
                request,
                ctx=ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

        @post("/disable", guards=[is_authenticated])
        async def disable(
            self,
            request: Request[Any, Any, Any],
            data: TotpDisableRequest,
            litestar_auth_user_manager: Any,  # noqa: ANN401
        ) -> None:
            del self
            await _totp_handle_disable(
                request,
                ctx=ctx,
                data=data,
                user_manager=litestar_auth_user_manager,
            )

    if ctx.totp_enable_requires_password:

        async def _on_enable_request_body_error(request: Request[Any, Any, Any]) -> None:
            await ctx.totp_rate_limit.on_invalid_attempt("enable", request)

        class TotpController(_TotpControllerBase):
            """TOTP 2FA management endpoints."""

            @post("/enable", guards=[is_authenticated])
            async def enable(
                self,
                request: Request[Any, Any, Any],
                litestar_auth_user_manager: Any,  # noqa: ANN401
                data: msgspec.Struct | None = None,
            ) -> TotpEnableResponse:
                del self
                return await _totp_handle_enable(
                    request,
                    ctx=ctx,
                    data=cast("TotpEnableRequest | None", data),
                    user_manager=litestar_auth_user_manager,
                )

        _configure_request_body_handler(
            TotpController.enable,
            schema=TotpEnableRequest,
            validation_code=ErrorCode.LOGIN_PAYLOAD_INVALID,
            on_validation_error=_on_enable_request_body_error,
            on_decode_error=_on_enable_request_body_error,
        )
    else:

        class TotpController(_TotpControllerBase):
            """TOTP 2FA management endpoints."""

            @post("/enable", guards=[is_authenticated])
            async def enable(
                self,
                request: Request[Any, Any, Any],
                litestar_auth_user_manager: Any,  # noqa: ANN401
            ) -> TotpEnableResponse:
                del self
                return await _totp_handle_enable(request, ctx=ctx, user_manager=litestar_auth_user_manager)

    TotpController.__module__ = __name__
    TotpController.__qualname__ = TotpController.__name__
    return TotpController


def create_totp_controller[UP: UserProtocol[Any], ID](  # noqa: PLR0913
    *,
    backend: AuthenticationBackend[UP, ID],
    user_manager_dependency_key: str,
    used_tokens_store: UsedTotpCodeStore | None = None,
    pending_jti_store: JWTDenylistStore | None = None,
    require_replay_protection: bool = True,
    rate_limit_config: AuthRateLimitConfig | None = None,
    requires_verification: bool = False,
    totp_pending_secret: str,
    totp_enable_requires_password: bool = True,
    totp_issuer: str = "litestar-auth",
    totp_algorithm: TotpAlgorithm = "SHA256",
    totp_pending_lifetime: timedelta | None = None,
    id_parser: Callable[[str], ID] | None = None,
    path: str = "/auth/2fa",
    unsafe_testing: bool = False,
) -> type[Controller]:
    """Return a controller with TOTP enable/verify/disable endpoints.

    Args:
        backend: Auth backend used to issue tokens after successful TOTP verification.
        user_manager_dependency_key: Litestar DI key / handler parameter name for the
            request-scoped user manager.
        used_tokens_store: Optional replay-protection cache for successful `/verify`
            attempts. When omitted, same-window replay protection stays disabled.
        pending_jti_store: Optional denylist store used to reject replayed
            pending-token JTIs after successful `/verify`. Required unless
            ``unsafe_testing=True``.
        require_replay_protection: When enabled, the controller refuses to start
            without a used-token replay store unless ``unsafe_testing=True``.
        rate_limit_config: Optional auth-endpoint rate-limiter configuration.
        requires_verification: When ``True``, `/2fa/verify` applies the same
            account-state policy as `/login`, rejecting inactive users and
            users with `is_verified=False`.
        totp_pending_secret: Shared secret for signing and verifying pending-2FA JWTs.
            Must match the value passed to ``create_auth_controller``.
        totp_enable_requires_password: When ``True`` (default), `/enable` requires a JSON body
            with the user's current password and re-authenticates before storing
            a new TOTP secret. Set to ``False`` only if you accept the session-hijack
            escalation risk (not recommended).
        totp_issuer: Issuer label shown inside authenticator-app QR codes.
        totp_algorithm: Hash algorithm used for TOTP generation and verification.
        totp_pending_lifetime: Unused; kept for API symmetry with
            ``create_auth_controller``.
        id_parser: Optional callable that converts the JWT ``sub`` string into the
            application's user ID type (e.g. ``UUID`` for UUID-keyed users).
        path: Base route prefix for the generated controller.
        unsafe_testing: Explicit test-only escape hatch that keeps the previous
            single-process shortcuts instance-scoped instead of process-global.

    Returns:
        Controller subclass with TOTP management endpoints.

    Examples:
        ```python
        from litestar_auth.controllers.totp import create_totp_controller

        totp_controller_cls = create_totp_controller(
            backend=backend,
            user_manager_dependency_key="litestar_auth_user_manager",
            totp_pending_secret=settings.totp_pending_secret,
        )
        ```
    """
    del user_manager_dependency_key
    del totp_pending_lifetime  # symmetry param; lifetime is set on the issuer side
    if not unsafe_testing:
        validate_secret_length(totp_pending_secret, label="totp_pending_secret")
    _totp_validate_replay_and_password(
        used_tokens_store=used_tokens_store,
        require_replay_protection=require_replay_protection,
        totp_enable_requires_password=totp_enable_requires_password,
        user_manager=None,
        unsafe_testing=unsafe_testing,
    )
    effective_pending_jti_store = _totp_resolve_pending_jti_store(
        pending_jti_store,
        unsafe_testing=unsafe_testing,
    )

    totp_rate_limit = TotpRateLimitOrchestrator(
        enable=rate_limit_config.totp_enable if rate_limit_config else None,
        confirm_enable=rate_limit_config.totp_confirm_enable if rate_limit_config else None,
        verify=rate_limit_config.totp_verify if rate_limit_config else None,
        disable=rate_limit_config.totp_disable if rate_limit_config else None,
    )
    ctx = _TotpControllerContext(
        backend=backend,
        used_tokens_store=used_tokens_store,
        require_replay_protection=require_replay_protection,
        requires_verification=requires_verification,
        totp_enable_requires_password=totp_enable_requires_password,
        totp_issuer=totp_issuer,
        totp_algorithm=totp_algorithm,
        totp_rate_limit=totp_rate_limit,
        totp_pending_secret=totp_pending_secret,
        effective_pending_jti_store=effective_pending_jti_store,
        id_parser=id_parser,
        unsafe_testing=unsafe_testing,
    )

    async def totp_verify_before_request(request: Request[Any, Any, Any]) -> None:
        await totp_rate_limit.before_request("verify", request)

    before = totp_verify_before_request if totp_rate_limit.verify is not None else None
    totp_controller_cls = _define_totp_controller_class_di(
        ctx,
        totp_verify_before_request=before,
    )
    totp_controller_cls.__name__ = "TotpController"
    totp_controller_cls.__qualname__ = "TotpController"
    totp_controller_cls.path = path
    return _mark_litestar_auth_route_handler(totp_controller_cls)
