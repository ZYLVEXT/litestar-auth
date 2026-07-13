"""Factory helpers for plugin-managed TOTP controllers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Unpack

from litestar_auth._plugin.config import resolve_backend_inventory
from litestar_auth._plugin.controller_factory import ControllerFactoryKit
from litestar_auth._plugin.totp_controller._settings import (
    PluginTotpControllerOptions,
    _build_plugin_totp_startup_context,
    _PluginTotpControllerSettings,
)
from litestar_auth._plugin.totp_route_handlers import define_plugin_totp_controller_class
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar import Controller, Request

    from litestar_auth._plugin.config import LitestarAuthConfig, StartupBackendInventory, StartupBackendTemplate
    from litestar_auth.ratelimit import TotpRateLimitOrchestrator


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
    return ControllerFactoryKit.finalize_controller(
        totp_controller_cls,
        module=totp_controller_cls.__module__,
        name="TotpController",
        path=settings.path,
        mark_litestar_auth=False,
    )


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
        backend=options["backend"],
        enable_refresh=options.get("enable_refresh", False),
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
        totp_stepup_ttl_seconds=options.get("totp_stepup_ttl_seconds", 300),
        totp_stepup_allow_recovery=options.get("totp_stepup_allow_recovery", False),
        totp_stepup_policy=dict(options.get("totp_stepup_policy", {})),
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
