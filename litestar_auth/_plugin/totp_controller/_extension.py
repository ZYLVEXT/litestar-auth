"""Internal auth extension for plugin-owned TOTP controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext


@dataclass(frozen=True, slots=True)
class _TotpExtension:
    """Internal extension that contributes plugin-owned TOTP routes."""

    name: str = "totp"
    enabled: bool = True

    def validate(self, context: AuthExtensionValidationContext) -> None:  # noqa: ARG002, PLR6301
        """Preserve existing TOTP factory-time validation."""
        return

    def register(self, context: AuthExtensionRegistrationContext) -> None:  # noqa: PLR6301
        """Contribute the plugin-owned TOTP controller."""
        from litestar_auth._plugin.totp_controller import build_totp_controller  # noqa: PLC0415

        context.add_controller(
            build_totp_controller(
                context.config,
                backend_inventory=context.startup_backend_inventory,
                security=context.security_requirements or None,
            ),
        )


__all__ = ("_TotpExtension",)
