"""First-party extension for mounting the contrib role-admin controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.types import Guard

    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext


@dataclass(frozen=True, slots=True)
class RoleAdminExtension:
    """Auth extension that contributes the supported role-admin HTTP controller."""

    name: str = "role_admin"
    enabled: bool = True
    route_prefix: str = "roles"
    guards: Sequence[Guard] | None = None

    @staticmethod
    def validate(context: AuthExtensionValidationContext) -> None:
        """Validate role-admin prerequisites before app startup wiring mutates state."""
        from litestar_auth._plugin.role_admin import resolve_role_model_family  # noqa: PLC0415
        from litestar_auth._superuser_role import normalize_superuser_role_name  # noqa: PLC0415

        normalize_superuser_role_name(context.config.superuser_role_name)
        resolve_role_model_family(context.user_model)

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute the generated role-admin controller through the extension context."""
        from litestar_auth.contrib.role_admin import (  # noqa: PLC0415
            RoleAdminControllerConfig,
            create_role_admin_controller,
        )

        controller = create_role_admin_controller(
            controller_config=RoleAdminControllerConfig(
                config=context.config,
                route_prefix=self.route_prefix,
                guards=self.guards,
            ),
        )
        context.add_controller(context.mark_auth_route_handler(controller))


__all__ = ("RoleAdminExtension",)
