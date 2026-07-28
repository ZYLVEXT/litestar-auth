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

    def validate(self, context: AuthExtensionValidationContext) -> None:  # ruff: ignore[unused-method-argument, no-self-use]
        """Preserve existing TOTP factory-time validation."""
        return

    def register(self, context: AuthExtensionRegistrationContext) -> None:  # ruff: ignore[no-self-use]
        """Contribute the plugin-owned TOTP controller."""
        from litestar_auth._plugin.totp_controller import (  # ruff: ignore[import-outside-top-level]
            build_totp_controller,
        )

        context.add_controller(
            build_totp_controller(
                context.config,
                backend_inventory=context.startup_backend_inventory,
                security=context.security_requirements or None,
            ),
        )


__all__ = ("_TotpExtension",)
