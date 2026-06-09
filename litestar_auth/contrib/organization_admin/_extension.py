"""First-party extension for mounting contrib organization-admin controllers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.types import Guard

    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext


@dataclass(frozen=True, slots=True)
class OrganizationAdminExtension:
    """Auth extension that contributes supported organization-admin HTTP controllers."""

    name: str = "organization_admin"
    enabled: bool = True
    route_prefix: str = "organizations"
    guards: Sequence[Guard] | None = None
    include_invitations: bool = False
    invitation_path: str = "/auth"
    _include_admin_controller: bool = True
    _mark_auth_owned: bool = True
    _use_plugin_openapi_security: bool = False

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Validate organization-admin prerequisites before app startup wiring mutates state.

        Raises:
            ConfigurationError: If organization-admin prerequisites are not configured.
        """
        if not context.organization_enabled:
            msg = "OrganizationAdminExtension requires organization_config.enabled=True."
            raise ConfigurationError(msg)
        if context.config.organization_config.store_factory is None:
            msg = "OrganizationAdminExtension requires organization_config.store_factory."
            raise ConfigurationError(msg)
        if self._include_admin_controller and context.config.id_parser is None:
            msg = "OrganizationAdminExtension requires id_parser directly or on user_manager_security."
            raise ConfigurationError(msg)
        if not self.include_invitations:
            return
        if context.config.user_manager_security is None:
            msg = "OrganizationAdminExtension invitation routes require user_manager_security."
            raise ConfigurationError(msg)
        if context.config.user_manager_security.organization_invitation_token_secret is None:
            msg = "OrganizationAdminExtension invitation routes require organization_invitation_token_secret."
            raise ConfigurationError(msg)

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute generated organization-admin controllers through the extension context."""
        from litestar_auth.contrib.organization_admin import (  # noqa: PLC0415
            OrganizationAdminControllerConfig,
            OrganizationInvitationControllerConfig,
            create_organization_admin_controller,
            create_organization_invitation_controller,
        )

        if self._include_admin_controller:
            controller = create_organization_admin_controller(
                controller_config=OrganizationAdminControllerConfig(
                    config=context.config,
                    route_prefix=self.route_prefix,
                    guards=self.guards,
                ),
            )
            context.add_controller(self._prepare_controller(context, controller))

        if not self.include_invitations:
            return
        security = (
            context.config.resolve_openapi_security_requirements() or None
            if self._use_plugin_openapi_security and context.config.include_openapi_security
            else context.security_requirements
        )

        invitation_controller = create_organization_invitation_controller(
            OrganizationInvitationControllerConfig(
                config=context.config,
                path=self.invitation_path,
                security=security,
            ),
        )
        context.add_controller(self._prepare_controller(context, invitation_controller))

    def _prepare_controller[ControllerT](
        self,
        context: AuthExtensionRegistrationContext,
        controller: ControllerT,
    ) -> ControllerT:
        """Apply extension route ownership when this extension owns exception formatting.

        Returns:
            The original controller, marked as auth-owned when configured.
        """
        if not self._mark_auth_owned:
            return controller
        return context.mark_auth_route_handler(controller)


__all__ = ("OrganizationAdminExtension",)
