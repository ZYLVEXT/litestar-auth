"""TOTP (2FA) controller factory for enable/verify/disable endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack

from litestar_auth._totp_enrollment import _resolve_enrollment_token_cipher
from litestar_auth.config import validate_secret_length
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.controllers.totp_context import (
    _build_totp_controller_context,
    _totp_resolve_enrollment_store,
    _totp_resolve_pending_jti_store,
    _totp_validate_replay_and_password,
    _TotpControllerContext,
    _TotpControllerContextSettings,
    _warn_totp_pending_client_binding_disabled,
)
from litestar_auth.controllers.totp_contracts import (
    INVALID_ENROLL_TOKEN_DETAIL,
    INVALID_TOTP_CODE_DETAIL,
    INVALID_TOTP_TOKEN_DETAIL,
    TOTP_ENROLL_AUDIENCE,
    TOTP_RATE_LIMITED_ENDPOINTS,
    TOTP_SENSITIVE_ENDPOINTS,
    TotpUserManagerProtocol,
    logger,
)
from litestar_auth.controllers.totp_handlers import (
    _totp_handle_confirm_enable,
    _totp_handle_enable,
)
from litestar_auth.controllers.totp_routes import _define_totp_controller_class_di
from litestar_auth.controllers.totp_session_handlers import (
    _totp_handle_disable,
    _totp_handle_regenerate_recovery_codes,
    _totp_handle_verify,
)
from litestar_auth.payloads import (
    TotpConfirmEnableRequest,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpRegenerateRecoveryCodesRequest,
    TotpVerifyRequest,
)
from litestar_auth.ratelimit import TotpRateLimitOrchestrator
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import timedelta

    from litestar import Controller, Request
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore

__all__ = (
    "INVALID_ENROLL_TOKEN_DETAIL",
    "INVALID_TOTP_CODE_DETAIL",
    "INVALID_TOTP_TOKEN_DETAIL",
    "TOTP_ENROLL_AUDIENCE",
    "TOTP_RATE_LIMITED_ENDPOINTS",
    "TOTP_SENSITIVE_ENDPOINTS",
    "TotpConfirmEnableRequest",
    "TotpControllerOptions",
    "TotpDisableRequest",
    "TotpEnableRequest",
    "TotpRegenerateRecoveryCodesRequest",
    "TotpUserManagerProtocol",
    "TotpVerifyRequest",
    "_TotpControllerContext",
    "_TotpControllerContextSettings",
    "_build_totp_controller_context",
    "_resolve_totp_controller_factory_settings",
    "_totp_handle_confirm_enable",
    "_totp_handle_disable",
    "_totp_handle_enable",
    "_totp_handle_regenerate_recovery_codes",
    "_totp_handle_verify",
    "_totp_resolve_enrollment_store",
    "_totp_resolve_pending_jti_store",
    "_totp_validate_replay_and_password",
    "create_totp_controller",
    "logger",
)


class TotpControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :func:`create_totp_controller`."""

    backend: Required[AuthenticationBackend[UP, ID]]
    user_manager_dependency_key: Required[str]
    totp_pending_secret: Required[str]
    used_tokens_store: NotRequired[UsedTotpCodeStore | None]
    pending_jti_store: NotRequired[JWTDenylistStore | None]
    enrollment_store: NotRequired[TotpEnrollmentStore | None]
    require_replay_protection: NotRequired[bool]
    rate_limit_config: NotRequired[AuthRateLimitConfig | None]
    requires_verification: NotRequired[bool]
    totp_secret_key: NotRequired[str | None]
    totp_secret_keyring: NotRequired[FernetKeyringConfig | None]
    totp_enable_requires_password: NotRequired[bool]
    totp_issuer: NotRequired[str]
    totp_algorithm: NotRequired[TotpAlgorithm]
    totp_pending_lifetime: NotRequired[timedelta | None]
    totp_pending_require_client_binding: NotRequired[bool]
    id_parser: NotRequired[Callable[[str], ID] | None]
    path: NotRequired[str]
    unsafe_testing: NotRequired[bool]
    security: NotRequired[Sequence[SecurityRequirement] | None]


@dataclass(slots=True)
class _TotpControllerFactorySettings[UP: UserProtocol[Any], ID]:
    """Raw public factory inputs before validation and default resolution."""

    backend: AuthenticationBackend[UP, ID]
    used_tokens_store: UsedTotpCodeStore | None
    pending_jti_store: JWTDenylistStore | None
    enrollment_store: TotpEnrollmentStore | None
    require_replay_protection: bool
    rate_limit_config: AuthRateLimitConfig | None
    requires_verification: bool
    totp_pending_secret: str
    totp_secret_key: str | None
    totp_secret_keyring: FernetKeyringConfig | None
    totp_enable_requires_password: bool
    totp_issuer: str
    totp_algorithm: TotpAlgorithm
    totp_pending_require_client_binding: bool
    id_parser: Callable[[str], ID] | None
    unsafe_testing: bool


def _build_totp_rate_limit(rate_limit_config: AuthRateLimitConfig | None) -> TotpRateLimitOrchestrator:
    """Build the TOTP endpoint rate-limit orchestrator.

    Returns:
        TOTP endpoint rate-limit orchestrator.
    """
    return TotpRateLimitOrchestrator(
        enable=rate_limit_config.totp_enable if rate_limit_config else None,
        confirm_enable=rate_limit_config.totp_confirm_enable if rate_limit_config else None,
        verify=rate_limit_config.totp_verify if rate_limit_config else None,
        disable=rate_limit_config.totp_disable if rate_limit_config else None,
        regenerate_recovery_codes=rate_limit_config.totp_regenerate_recovery_codes if rate_limit_config else None,
    )


def _validate_totp_factory_settings[UP: UserProtocol[Any], ID](
    settings: _TotpControllerFactorySettings[UP, ID],
) -> None:
    """Validate public TOTP controller factory settings."""
    if not settings.unsafe_testing:
        validate_secret_length(settings.totp_pending_secret, label="totp_pending_secret")
    if not settings.totp_pending_require_client_binding:
        _warn_totp_pending_client_binding_disabled()
    _totp_validate_replay_and_password(
        used_tokens_store=settings.used_tokens_store,
        require_replay_protection=settings.require_replay_protection,
        totp_enable_requires_password=settings.totp_enable_requires_password,
        user_manager=None,
        unsafe_testing=settings.unsafe_testing,
    )


def _create_totp_context_settings[UP: UserProtocol[Any], ID](
    settings: _TotpControllerFactorySettings[UP, ID],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> _TotpControllerContextSettings[UP, ID]:
    """Resolve optional dependencies into grouped TOTP controller context settings.

    Returns:
        Raw context settings for grouped TOTP controller assembly.
    """
    totp_verify_rate_limit = settings.rate_limit_config.totp_verify if settings.rate_limit_config else None
    effective_pending_jti_store = _totp_resolve_pending_jti_store(
        settings.pending_jti_store,
        unsafe_testing=settings.unsafe_testing,
    )
    effective_enrollment_store = _totp_resolve_enrollment_store(
        settings.enrollment_store,
        unsafe_testing=settings.unsafe_testing,
    )
    enrollment_token_cipher = _resolve_enrollment_token_cipher(
        totp_secret_key=settings.totp_secret_key,
        totp_secret_keyring=settings.totp_secret_keyring,
        unsafe_testing=settings.unsafe_testing,
    )
    return _TotpControllerContextSettings(
        backend=settings.backend,
        used_tokens_store=settings.used_tokens_store,
        require_replay_protection=settings.require_replay_protection,
        requires_verification=settings.requires_verification,
        totp_enable_requires_password=settings.totp_enable_requires_password,
        totp_issuer=settings.totp_issuer,
        totp_algorithm=settings.totp_algorithm,
        totp_rate_limit=totp_rate_limit,
        totp_pending_secret=settings.totp_pending_secret,
        totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
        totp_pending_client_binding_trusted_proxy=(
            False if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_proxy
        ),
        totp_pending_client_binding_trusted_headers=(
            ("X-Forwarded-For",) if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_headers
        ),
        effective_pending_jti_store=effective_pending_jti_store,
        id_parser=settings.id_parser,
        unsafe_testing=settings.unsafe_testing,
        enrollment_token_cipher=enrollment_token_cipher,
        enrollment_store=effective_enrollment_store,
    )


def _build_totp_controller_context_from_factory_settings[UP: UserProtocol[Any], ID](
    settings: _TotpControllerFactorySettings[UP, ID],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> _TotpControllerContext[UP, ID]:
    """Validate public factory settings and build the generated controller context.

    Returns:
        Grouped TOTP controller context consumed by generated route handlers.
    """
    return _build_totp_controller_context(
        _create_totp_context_settings(settings, totp_rate_limit=totp_rate_limit),
    )


def _create_totp_verify_before_request(
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> Callable[[Request[Any, Any, Any]], Any] | None:
    """Create the optional TOTP verify rate-limit preflight hook.

    Returns:
        Litestar ``before_request`` handler when verify rate limiting is enabled.
    """
    if totp_rate_limit.verify is None:
        return None

    async def totp_verify_before_request(request: Request[Any, Any, Any]) -> None:
        await totp_rate_limit.before_request("verify", request)

    return totp_verify_before_request


def _finalize_totp_controller[UP: UserProtocol[Any], ID](
    settings: _TotpControllerFactorySettings[UP, ID],
    *,
    path: str,
    security: Sequence[SecurityRequirement] | None,
) -> type[Controller]:
    """Build and finalize the generated TOTP controller class.

    Returns:
        Marked Litestar controller subclass.
    """
    totp_rate_limit = _build_totp_rate_limit(settings.rate_limit_config)
    _validate_totp_factory_settings(settings)
    ctx = _build_totp_controller_context_from_factory_settings(settings, totp_rate_limit=totp_rate_limit)
    totp_controller_cls = _define_totp_controller_class_di(
        ctx,
        totp_verify_before_request=_create_totp_verify_before_request(totp_rate_limit),
        security=security,
    )
    totp_controller_cls.__name__ = "TotpController"
    totp_controller_cls.__qualname__ = "TotpController"
    totp_controller_cls.path = path
    return _mark_litestar_auth_route_handler(totp_controller_cls)


def _resolve_totp_controller_factory_settings[UP: UserProtocol[Any], ID](
    options: TotpControllerOptions[UP, ID],
) -> tuple[_TotpControllerFactorySettings[UP, ID], str, Sequence[SecurityRequirement] | None]:
    """Resolve public TOTP controller options into internal factory settings.

    Returns:
        Internal settings, route path, and OpenAPI security metadata.
    """
    _ = options["user_manager_dependency_key"]
    options.pop("totp_pending_lifetime", None)  # symmetry param; lifetime is set on the issuer side
    path = options.get("path", "/auth/2fa")
    security = options.get("security")
    return (
        _TotpControllerFactorySettings(
            backend=options["backend"],
            used_tokens_store=options.get("used_tokens_store"),
            pending_jti_store=options.get("pending_jti_store"),
            enrollment_store=options.get("enrollment_store"),
            require_replay_protection=options.get("require_replay_protection", True),
            rate_limit_config=options.get("rate_limit_config"),
            requires_verification=options.get("requires_verification", True),
            totp_pending_secret=options["totp_pending_secret"],
            totp_secret_key=options.get("totp_secret_key"),
            totp_secret_keyring=options.get("totp_secret_keyring"),
            totp_enable_requires_password=options.get("totp_enable_requires_password", True),
            totp_issuer=options.get("totp_issuer", "litestar-auth"),
            totp_algorithm=options.get("totp_algorithm", "SHA256"),
            totp_pending_require_client_binding=options.get("totp_pending_require_client_binding", True),
            id_parser=options.get("id_parser"),
            unsafe_testing=options.get("unsafe_testing", False),
        ),
        path,
        security,
    )


def create_totp_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[TotpControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a controller with TOTP management and login-completion endpoints.

    Returns:
        Controller subclass with TOTP management endpoints.
    """
    settings, path, security = _resolve_totp_controller_factory_settings(options)
    return _finalize_totp_controller(settings, path=path, security=security)
