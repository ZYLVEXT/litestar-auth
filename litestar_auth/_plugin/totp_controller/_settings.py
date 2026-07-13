"""Settings and validation for plugin-managed TOTP controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, cast

from litestar_auth._totp_enrollment import _resolve_enrollment_token_cipher
from litestar_auth.config import validate_production_secret
from litestar_auth.controllers.totp import (
    _build_totp_controller_context,
    _totp_resolve_enrollment_store,
    _totp_resolve_pending_jti_store,
    _totp_validate_replay_and_password,
    _TotpControllerContext,
    _TotpControllerContextSettings,
    _warn_totp_pending_client_binding_disabled,
)
from litestar_auth.ratelimit import TotpRateLimitOrchestrator
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import timedelta

    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth._plugin.config import StartupBackendInventory, StartupBackendTemplate
    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.controllers._step_up import TotpStepUpPolicyMode
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore


@dataclass(slots=True)
class _PluginTotpControllerSettings[UP: UserProtocol[Any], ID]:
    """Raw plugin TOTP controller factory inputs."""

    backend: StartupBackendTemplate[UP, ID]
    enable_refresh: bool
    backend_inventory: StartupBackendInventory[UP, ID]
    backend_index: int
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
    totp_stepup_ttl_seconds: int
    totp_stepup_allow_recovery: bool
    totp_stepup_policy: dict[str, TotpStepUpPolicyMode]
    totp_pending_require_client_binding: bool
    id_parser: Callable[[str], ID] | None
    path: str
    unsafe_testing: bool
    security: Sequence[SecurityRequirement] | None


class PluginTotpControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by plugin-managed ``create_totp_controller``."""

    backend: Required[StartupBackendTemplate[UP, ID]]
    enable_refresh: NotRequired[bool]
    backend_inventory: Required[StartupBackendInventory[UP, ID]]
    backend_index: Required[int]
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
    totp_stepup_ttl_seconds: NotRequired[int]
    totp_stepup_allow_recovery: NotRequired[bool]
    totp_stepup_policy: NotRequired[dict[str, TotpStepUpPolicyMode]]
    totp_pending_lifetime: NotRequired[timedelta | None]
    totp_pending_require_client_binding: NotRequired[bool]
    id_parser: NotRequired[Callable[[str], ID] | None]
    path: NotRequired[str]
    unsafe_testing: NotRequired[bool]
    security: NotRequired[Sequence[SecurityRequirement] | None]


def _build_plugin_totp_rate_limit(
    rate_limit_config: AuthRateLimitConfig | None,
) -> TotpRateLimitOrchestrator:
    """Build the plugin TOTP rate-limit orchestrator.

    Returns:
        Endpoint-specific TOTP rate-limit orchestrator.
    """
    return TotpRateLimitOrchestrator(
        enable=rate_limit_config.totp_enable if rate_limit_config else None,
        confirm_enable=rate_limit_config.totp_confirm_enable if rate_limit_config else None,
        verify=rate_limit_config.totp_verify if rate_limit_config else None,
        disable=rate_limit_config.totp_disable if rate_limit_config else None,
        regenerate_recovery_codes=rate_limit_config.totp_regenerate_recovery_codes if rate_limit_config else None,
    )


def _validate_plugin_totp_controller_settings[UP: UserProtocol[Any], ID](
    settings: _PluginTotpControllerSettings[UP, ID],
) -> None:
    """Validate plugin TOTP controller factory settings."""
    validate_production_secret(
        settings.totp_pending_secret,
        label="totp_pending_secret",
        unsafe_testing=settings.unsafe_testing,
    )
    if not settings.totp_pending_require_client_binding:
        _warn_totp_pending_client_binding_disabled()
    _totp_validate_replay_and_password(
        used_tokens_store=settings.used_tokens_store,
        require_replay_protection=settings.require_replay_protection,
        totp_enable_requires_password=settings.totp_enable_requires_password,
        user_manager=None,
        unsafe_testing=settings.unsafe_testing,
    )


def _build_plugin_totp_context_settings[UP: UserProtocol[Any], ID](
    settings: _PluginTotpControllerSettings[UP, ID],
    *,
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> _TotpControllerContextSettings[UP, ID]:
    """Build grouped TOTP controller context settings.

    Returns:
        Settings consumed by the shared TOTP controller context builder.
    """
    totp_verify_rate_limit = None if settings.rate_limit_config is None else settings.rate_limit_config.totp_verify
    return _TotpControllerContextSettings(
        backend=cast("AuthenticationBackend[UP, ID]", settings.backend),
        enable_refresh=settings.enable_refresh,
        used_tokens_store=settings.used_tokens_store,
        require_replay_protection=settings.require_replay_protection,
        requires_verification=settings.requires_verification,
        totp_enable_requires_password=settings.totp_enable_requires_password,
        totp_issuer=settings.totp_issuer,
        totp_algorithm=settings.totp_algorithm,
        totp_stepup_ttl_seconds=settings.totp_stepup_ttl_seconds,
        totp_stepup_allow_recovery=settings.totp_stepup_allow_recovery,
        totp_stepup_policy=settings.totp_stepup_policy,
        totp_rate_limit=totp_rate_limit,
        totp_pending_secret=settings.totp_pending_secret,
        totp_pending_require_client_binding=settings.totp_pending_require_client_binding,
        totp_pending_client_binding_trusted_proxy=(
            False if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_proxy
        ),
        totp_pending_client_binding_trusted_headers=(
            ("X-Forwarded-For",) if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_headers
        ),
        totp_pending_client_binding_trusted_proxy_hops=(
            1 if totp_verify_rate_limit is None else totp_verify_rate_limit.trusted_proxy_hops
        ),
        effective_pending_jti_store=_totp_resolve_pending_jti_store(
            settings.pending_jti_store,
            unsafe_testing=settings.unsafe_testing,
        ),
        id_parser=settings.id_parser,
        unsafe_testing=settings.unsafe_testing,
        enrollment_token_cipher=_resolve_enrollment_token_cipher(
            totp_secret_key=settings.totp_secret_key,
            totp_secret_keyring=settings.totp_secret_keyring,
            unsafe_testing=settings.unsafe_testing,
        ),
        enrollment_store=_totp_resolve_enrollment_store(
            settings.enrollment_store,
            unsafe_testing=settings.unsafe_testing,
        ),
    )


def _build_plugin_totp_startup_context[UP: UserProtocol[Any], ID](
    settings: _PluginTotpControllerSettings[UP, ID],
) -> tuple[_TotpControllerContext[UP, ID], TotpRateLimitOrchestrator]:
    """Build plugin startup-scoped TOTP context.

    Returns:
        Startup TOTP context and the rate-limit orchestrator it owns.
    """
    _validate_plugin_totp_controller_settings(settings)
    totp_rate_limit = _build_plugin_totp_rate_limit(settings.rate_limit_config)
    return (
        _build_totp_controller_context(
            _build_plugin_totp_context_settings(settings, totp_rate_limit=totp_rate_limit),
        ),
        totp_rate_limit,
    )
