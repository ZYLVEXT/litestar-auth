"""Plugin-managed TOTP controller assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY, resolve_backend_inventory
from litestar_auth._plugin.totp_controller._factory import create_totp_controller, totp_backend, totp_path
from litestar_auth._plugin.totp_controller._settings import PluginTotpControllerOptions
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.openapi.spec import SecurityRequirement
    from litestar.types import ControllerRouterHandler

    from litestar_auth._plugin.config import LitestarAuthConfig, StartupBackendInventory
    from litestar_auth.authentication.backend import AuthenticationBackend

__all__ = (
    "PluginTotpControllerOptions",
    "build_totp_controller",
    "create_totp_controller",
    "totp_backend",
    "totp_path",
)


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
        enable_refresh=config.enable_refresh,
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
        totp_stepup_ttl_seconds=config.totp_stepup_ttl_seconds,
        totp_stepup_allow_recovery=config.totp_stepup_allow_recovery,
        totp_stepup_policy=config.totp_stepup_policy,
        totp_pending_require_client_binding=totp_config.totp_pending_require_client_binding,
        id_parser=config.id_parser,
        path=totp_path(config.auth_path),
        unsafe_testing=config.unsafe_testing,
        security=security,
    )
