"""Internal auth extension for plugin-owned API-key management controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext


@dataclass(frozen=True, slots=True)
class _ApiKeyExtension:
    """Internal extension that contributes plugin-owned API-key management routes."""

    name: str = "api_keys"
    enabled: bool = True

    def validate(self, context: AuthExtensionValidationContext) -> None:  # noqa: ARG002, PLR6301
        """Preserve existing API-key config and factory validation."""
        return

    def register(self, context: AuthExtensionRegistrationContext) -> None:  # noqa: PLR6301
        """Contribute plugin-owned API-key management controllers."""
        from litestar_auth.controllers.api_keys import create_api_keys_controllers  # noqa: PLC0415

        for controller in create_api_keys_controllers(
            id_parser=context.config.id_parser,
            rate_limit_config=context.config.rate_limit_config,
            security=context.security_requirements or None,
            users_path=context.config.users_path,
            require_step_up_on_create=context.config.api_keys.require_step_up_on_create,
            signing_enabled=context.config.api_keys.signing_enabled,
            totp_stepup_policy=context.config.totp_stepup_policy,
        ):
            context.add_controller(controller)


__all__ = ("_ApiKeyExtension",)
