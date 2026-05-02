"""Plugin-managed TOTP controller assembly."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, cast

from litestar_auth._plugin.config import (
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
    StartupBackendInventory,
    StartupBackendTemplate,
    resolve_backend_inventory,
)
from litestar_auth._plugin.totp_route_handlers import define_plugin_totp_controller_class
from litestar_auth._totp_enrollment import _resolve_enrollment_token_cipher
from litestar_auth.config import validate_secret_length
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

    from litestar import Controller, Request
    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ControllerRouterHandler

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.ratelimit import AuthRateLimitConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore


def _resolve_request_backend[UP: UserProtocol[Any], ID](
    backend_inventory: StartupBackendInventory[UP, ID],
    request_backends: object,
    *,
    backend_index: int,
) -> AuthenticationBackend[UP, ID]:
    """Return the request-scoped backend matching the startup controller slot.

    Returns:
        Request-scoped backend aligned with the startup controller slot.
    """
    return backend_inventory.resolve_request_backend(request_backends, backend_index=backend_index)


@dataclass(slots=True)
class _PluginTotpControllerSettings[UP: UserProtocol[Any], ID]:
    """Raw plugin TOTP controller factory inputs."""

    backend: StartupBackendTemplate[UP, ID]
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
    totp_pending_require_client_binding: bool
    id_parser: Callable[[str], ID] | None
    path: str
    unsafe_testing: bool
    security: Sequence[SecurityRequirement] | None


class PluginTotpControllerOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by plugin-managed ``create_totp_controller``."""

    backend: Required[StartupBackendTemplate[UP, ID]]
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
        backend=cast("Any", settings.backend),
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


def _totp_verify_before_request_handler(
    totp_rate_limit: TotpRateLimitOrchestrator,
) -> Callable[[Request[Any, Any, Any]], Any] | None:
    """Return the verify preflight hook when the verify endpoint is rate-limited."""
    if totp_rate_limit.verify is None:
        return None

    async def totp_verify_before_request(request: Request[Any, Any, Any]) -> None:
        await totp_rate_limit.before_request("verify", request)

    return totp_verify_before_request


def _create_plugin_totp_controller_from_settings[UP: UserProtocol[Any], ID](
    settings: _PluginTotpControllerSettings[UP, ID],
) -> type[Controller]:
    """Create the plugin TOTP controller from grouped settings.

    Returns:
        Generated controller type.
    """
    startup_ctx, totp_rate_limit = _build_plugin_totp_startup_context(settings)
    totp_controller_cls = define_plugin_totp_controller_class(
        startup_ctx,
        backend_inventory=settings.backend_inventory,
        backend_index=settings.backend_index,
        totp_verify_before_request=_totp_verify_before_request_handler(totp_rate_limit),
        security=settings.security,
    )
    totp_controller_cls.__name__ = "TotpController"
    totp_controller_cls.__qualname__ = "TotpController"
    totp_controller_cls.path = settings.path
    return totp_controller_cls


def _resolve_plugin_totp_controller_settings[UP: UserProtocol[Any], ID](
    options: PluginTotpControllerOptions[UP, ID],
) -> _PluginTotpControllerSettings[UP, ID]:
    """Resolve public plugin TOTP options into internal factory settings.

    Returns:
        Internal plugin TOTP controller settings.
    """
    _ = options["user_manager_dependency_key"]
    options.pop("totp_pending_lifetime", None)
    return _PluginTotpControllerSettings(
        backend=cast("Any", options["backend"]),
        backend_inventory=options["backend_inventory"],
        backend_index=options["backend_index"],
        used_tokens_store=options.get("used_tokens_store"),
        pending_jti_store=options.get("pending_jti_store"),
        enrollment_store=options.get("enrollment_store"),
        require_replay_protection=options.get("require_replay_protection", True),
        rate_limit_config=options.get("rate_limit_config"),
        requires_verification=options.get("requires_verification", True),
        totp_enable_requires_password=options.get("totp_enable_requires_password", True),
        totp_issuer=options.get("totp_issuer", "litestar-auth"),
        totp_algorithm=options.get("totp_algorithm", "SHA256"),
        totp_pending_secret=options["totp_pending_secret"],
        totp_secret_key=options.get("totp_secret_key"),
        totp_secret_keyring=options.get("totp_secret_keyring"),
        totp_pending_require_client_binding=options.get("totp_pending_require_client_binding", True),
        id_parser=options.get("id_parser"),
        path=options.get("path", "/auth/2fa"),
        unsafe_testing=options.get("unsafe_testing", False),
        security=options.get("security"),
    )


def create_totp_controller[UP: UserProtocol[Any], ID](
    **options: Unpack[PluginTotpControllerOptions[UP, ID]],
) -> type[Controller]:
    """Return a plugin TOTP controller that resolves its backend from request DI."""
    return _create_plugin_totp_controller_from_settings(
        _resolve_plugin_totp_controller_settings(options),
    )


def build_totp_controller[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
    security: Sequence[SecurityRequirement] | None = None,
) -> ControllerRouterHandler:
    """Build the configured TOTP controller surface.

    Returns:
        The mounted TOTP controller.

    Raises:
        ValueError: If ``totp_config`` is not configured.
    """
    totp_config = config.totp_config
    if totp_config is None:
        msg = "totp_config must be configured to build TOTP controller."
        raise ValueError(msg)
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    backend_index, backend = inventory.resolve_totp(backend_name=totp_config.totp_backend_name)
    totp_secret_key = config.user_manager_security.totp_secret_key if config.user_manager_security is not None else None
    totp_secret_keyring = (
        config.user_manager_security.totp_secret_keyring if config.user_manager_security is not None else None
    )
    return create_totp_controller(
        backend=backend,
        backend_inventory=inventory,
        backend_index=backend_index,
        user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        used_tokens_store=totp_config.totp_used_tokens_store,
        pending_jti_store=totp_config.totp_pending_jti_store,
        enrollment_store=totp_config.totp_enrollment_store,
        require_replay_protection=totp_config.totp_require_replay_protection,
        rate_limit_config=config.rate_limit_config,
        requires_verification=config.requires_verification,
        totp_pending_secret=totp_config.totp_pending_secret,
        totp_secret_key=totp_secret_key,
        totp_secret_keyring=totp_secret_keyring,
        totp_enable_requires_password=totp_config.totp_enable_requires_password,
        totp_issuer=totp_config.totp_issuer,
        totp_algorithm=totp_config.totp_algorithm,
        totp_pending_require_client_binding=totp_config.totp_pending_require_client_binding,
        id_parser=config.id_parser,
        path=totp_path(config.auth_path),
        unsafe_testing=config.unsafe_testing,
        security=security,
    )


def totp_backend[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backend_inventory: StartupBackendInventory[UP, ID] | None = None,
) -> StartupBackendTemplate[UP, ID]:
    """Return the configured TOTP backend or the primary backend.

    Returns:
        The backend that should service TOTP flows.
    """
    inventory = resolve_backend_inventory(config) if backend_inventory is None else backend_inventory
    backend_name = None if config.totp_config is None else config.totp_config.totp_backend_name
    _, backend = inventory.resolve_totp(backend_name=backend_name)
    return backend


def totp_path(auth_path: str) -> str:
    """Return the mounted TOTP controller path."""
    base_path = auth_path.rstrip("/") or "/"
    return f"{base_path}/2fa"
