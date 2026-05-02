"""Runtime context assembly for generated TOTP controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar_auth.controllers.totp_contracts import logger
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import InMemoryTotpEnrollmentStore, TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth._totp_enrollment import _EnrollmentTokenCipher
    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.ratelimit import TotpRateLimitOrchestrator


@dataclass(slots=True)
class _TotpControllerRuntimeContext[UP: UserProtocol[Any], ID]:
    """Backend and rate-limit dependencies shared by generated TOTP handlers."""

    backend: AuthenticationBackend[UP, ID]
    rate_limit: TotpRateLimitOrchestrator


@dataclass(slots=True)
class _TotpControllerSecurityContext:
    """Account-state and replay-protection policy for generated TOTP handlers."""

    used_tokens_store: UsedTotpCodeStore | None
    require_replay_protection: bool
    requires_verification: bool
    totp_enable_requires_password: bool
    totp_algorithm: TotpAlgorithm
    unsafe_testing: bool


@dataclass(slots=True)
class _TotpPendingTokenContext[ID]:
    """Pending-login token signing, replay storage, and client-binding settings."""

    totp_pending_secret: str
    totp_pending_require_client_binding: bool
    totp_pending_client_binding_trusted_proxy: bool
    totp_pending_client_binding_trusted_headers: tuple[str, ...]
    effective_pending_jti_store: JWTDenylistStore | None
    id_parser: Callable[[str], ID] | None


@dataclass(slots=True)
class _TotpEnrollmentContext:
    """TOTP enrollment token and server-side secret storage dependencies."""

    totp_issuer: str
    enrollment_token_cipher: _EnrollmentTokenCipher | None
    enrollment_store: TotpEnrollmentStore


@dataclass(slots=True)
class _TotpControllerContext[UP: UserProtocol[Any], ID]:
    """Runtime dependencies for generated TOTP controller handlers."""

    runtime: _TotpControllerRuntimeContext[UP, ID]
    security: _TotpControllerSecurityContext
    pending_token: _TotpPendingTokenContext[ID]
    enrollment: _TotpEnrollmentContext


@dataclass(slots=True)
class _TotpControllerContextSettings[UP: UserProtocol[Any], ID]:
    """Raw TOTP controller dependencies before they are grouped by concern."""

    backend: AuthenticationBackend[UP, ID]
    used_tokens_store: UsedTotpCodeStore | None
    require_replay_protection: bool
    requires_verification: bool
    totp_enable_requires_password: bool
    totp_issuer: str
    totp_algorithm: TotpAlgorithm
    totp_rate_limit: TotpRateLimitOrchestrator
    totp_pending_secret: str
    totp_pending_require_client_binding: bool
    totp_pending_client_binding_trusted_proxy: bool
    totp_pending_client_binding_trusted_headers: tuple[str, ...]
    effective_pending_jti_store: JWTDenylistStore | None
    id_parser: Callable[[str], ID] | None
    unsafe_testing: bool
    enrollment_token_cipher: _EnrollmentTokenCipher | None
    enrollment_store: TotpEnrollmentStore


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


def _totp_resolve_enrollment_store(
    enrollment_store: TotpEnrollmentStore | None,
    *,
    unsafe_testing: bool,
) -> TotpEnrollmentStore:
    """Return the configured TOTP enrollment store.

    Raises:
        ConfigurationError: If no server-side enrollment store is configured
            outside explicit ``unsafe_testing`` mode.
    """
    if enrollment_store is not None:
        return enrollment_store
    if unsafe_testing:
        return InMemoryTotpEnrollmentStore()

    msg = (
        "totp_enrollment_store is required when unsafe_testing=False. "
        "Configure a TotpEnrollmentStore so enrollment tokens are single-use and latest-only."
    )
    raise ConfigurationError(msg)


def _warn_totp_pending_client_binding_disabled() -> None:
    """Log the weaker posture when pending-token client binding is explicitly disabled."""
    logger.warning(
        "TOTP pending-token client binding is disabled; leaked pending tokens can be replayed from another client.",
        extra={"event": "totp_pending_client_binding_disabled"},
    )


def _build_totp_controller_context[UP: UserProtocol[Any], ID](
    settings: _TotpControllerContextSettings[UP, ID],
) -> _TotpControllerContext[UP, ID]:
    """Assemble grouped TOTP controller dependencies.

    Returns:
        Grouped controller context consumed by generated TOTP handlers.
    """
    return _TotpControllerContext(
        runtime=_TotpControllerRuntimeContext(
            backend=settings.backend,
            rate_limit=settings.totp_rate_limit,
        ),
        security=_TotpControllerSecurityContext(
            used_tokens_store=settings.used_tokens_store,
            require_replay_protection=settings.require_replay_protection,
            requires_verification=settings.requires_verification,
            totp_enable_requires_password=settings.totp_enable_requires_password,
            totp_algorithm=settings.totp_algorithm,
            unsafe_testing=settings.unsafe_testing,
        ),
        pending_token=_TotpPendingTokenContext(
            totp_pending_secret=settings.totp_pending_secret,
            totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
            totp_pending_client_binding_trusted_proxy=settings.totp_pending_client_binding_trusted_proxy,
            totp_pending_client_binding_trusted_headers=settings.totp_pending_client_binding_trusted_headers,
            effective_pending_jti_store=settings.effective_pending_jti_store,
            id_parser=settings.id_parser,
        ),
        enrollment=_TotpEnrollmentContext(
            totp_issuer=settings.totp_issuer,
            enrollment_token_cipher=settings.enrollment_token_cipher,
            enrollment_store=settings.enrollment_store,
        ),
    )
