"""Internal auth extension for plugin-owned OAuth controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth.oauth_encryption import _build_oauth_token_encryption, require_oauth_token_encryption

if TYPE_CHECKING:
    from litestar.types import ControllerRouterHandler

    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext


@dataclass(frozen=True, slots=True)
class _OAuthExtension:
    """Internal extension that contributes plugin-owned OAuth routes."""

    name: str = "oauth"
    enabled: bool = True

    def validate(self, context: AuthExtensionValidationContext) -> None:  # noqa: PLR6301
        """Validate OAuth extension prerequisites before app startup wiring mutates state."""
        contract = _build_oauth_route_registration_contract(
            auth_path=context.config.auth_path,
            oauth_config=context.config.oauth_config,
        )
        if not contract.has_configured_providers:
            return

        context.require_cryptography_fernet(install_hint="Install litestar-auth[oauth] to use OAuth providers.")
        require_oauth_token_encryption(
            _build_oauth_token_encryption(context.config),
            context="OAuth providers are configured",
        )

    def register(self, context: AuthExtensionRegistrationContext) -> None:  # noqa: PLR6301
        """Contribute plugin-owned OAuth controllers and production redirect validation."""
        from litestar_auth._plugin._oauth_controllers import (  # noqa: PLC0415
            _append_oauth_associate_controllers,
            _append_oauth_login_controllers,
        )
        from litestar_auth._plugin.startup import require_secure_oauth_redirect_in_production  # noqa: PLC0415

        require_secure_oauth_redirect_in_production(config=context.config, app_config=context.app_config)

        controllers: list[ControllerRouterHandler] = []
        _append_oauth_login_controllers(
            controllers=controllers,
            config=context.config,
            backend_inventory=context.startup_backend_inventory,
        )
        _append_oauth_associate_controllers(
            controllers=controllers,
            config=context.config,
            security=context.security_requirements or None,
        )
        for controller in controllers:
            context.add_controller(controller)


__all__ = ("_OAuthExtension",)
