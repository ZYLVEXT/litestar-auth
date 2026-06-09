"""Public extension authoring facade for litestar-auth."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from litestar_auth._manager.hooks import ExtensionManagerHookEvent, ExtensionManagerHookSubscriber
from litestar_auth._plugin.extensions._contracts import (
    EXTENSION_API_VERSION,
    EXTENSION_ENTRY_POINT_GROUP,
    AuthCliExtension,
    AuthEventSubscriberExtension,
    AuthExtension,
    AuthExtensionRegistrationContext,
    AuthExtensionValidationContext,
)

if TYPE_CHECKING:
    from litestar_auth.contrib.organization_admin import (
        OrganizationAdminControllerConfig,
        OrganizationInvitationControllerConfig,
        create_organization_admin_controller,
        create_organization_invitation_controller,
    )
    from litestar_auth.contrib.role_admin import RoleAdminControllerConfig, create_role_admin_controller
    from litestar_auth.controllers import (
        ApiKeysControllerConfig,
        AuthControllerConfig,
        OAuthAssociateControllerConfig,
        OAuthControllerConfig,
        OrganizationControllerConfig,
        RegisterControllerConfig,
        SessionDevicesControllerConfig,
        TotpControllerOptions,
        TotpUserManagerProtocol,
        UsersControllerConfig,
        backend_supports_organization_tokens,
        create_api_keys_controllers,
        create_auth_controller,
        create_oauth_associate_controller,
        create_oauth_controller,
        create_organization_controller,
        create_register_controller,
        create_reset_password_controller,
        create_session_devices_controller,
        create_totp_controller,
        create_users_controller,
        create_verify_controller,
    )
    from litestar_auth.oauth import ProviderOAuthControllerConfig, create_provider_oauth_controller

__all__ = (
    "EXTENSION_API_VERSION",
    "EXTENSION_ENTRY_POINT_GROUP",
    "ApiKeysControllerConfig",
    "AuthCliExtension",
    "AuthControllerConfig",
    "AuthEventSubscriberExtension",
    "AuthExtension",
    "AuthExtensionRegistrationContext",
    "AuthExtensionValidationContext",
    "ExtensionManagerHookEvent",
    "ExtensionManagerHookSubscriber",
    "OAuthAssociateControllerConfig",
    "OAuthControllerConfig",
    "OrganizationAdminControllerConfig",
    "OrganizationControllerConfig",
    "OrganizationInvitationControllerConfig",
    "ProviderOAuthControllerConfig",
    "RegisterControllerConfig",
    "RoleAdminControllerConfig",
    "SessionDevicesControllerConfig",
    "TotpControllerOptions",
    "TotpUserManagerProtocol",
    "UsersControllerConfig",
    "backend_supports_organization_tokens",
    "create_api_keys_controllers",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_organization_admin_controller",
    "create_organization_controller",
    "create_organization_invitation_controller",
    "create_provider_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_role_admin_controller",
    "create_session_devices_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
)

_PUBLIC_EXPORTS = {
    "ApiKeysControllerConfig": "litestar_auth.controllers",
    "AuthControllerConfig": "litestar_auth.controllers",
    "OAuthAssociateControllerConfig": "litestar_auth.controllers",
    "OAuthControllerConfig": "litestar_auth.controllers",
    "OrganizationAdminControllerConfig": "litestar_auth.contrib.organization_admin",
    "OrganizationControllerConfig": "litestar_auth.controllers",
    "OrganizationInvitationControllerConfig": "litestar_auth.contrib.organization_admin",
    "ProviderOAuthControllerConfig": "litestar_auth.oauth",
    "RegisterControllerConfig": "litestar_auth.controllers",
    "RoleAdminControllerConfig": "litestar_auth.contrib.role_admin",
    "SessionDevicesControllerConfig": "litestar_auth.controllers",
    "TotpControllerOptions": "litestar_auth.controllers",
    "TotpUserManagerProtocol": "litestar_auth.controllers",
    "UsersControllerConfig": "litestar_auth.controllers",
    "backend_supports_organization_tokens": "litestar_auth.controllers",
    "create_api_keys_controllers": "litestar_auth.controllers",
    "create_auth_controller": "litestar_auth.controllers",
    "create_oauth_associate_controller": "litestar_auth.controllers",
    "create_oauth_controller": "litestar_auth.controllers",
    "create_organization_admin_controller": "litestar_auth.contrib.organization_admin",
    "create_organization_controller": "litestar_auth.controllers",
    "create_organization_invitation_controller": "litestar_auth.contrib.organization_admin",
    "create_provider_oauth_controller": "litestar_auth.oauth",
    "create_register_controller": "litestar_auth.controllers",
    "create_reset_password_controller": "litestar_auth.controllers",
    "create_role_admin_controller": "litestar_auth.contrib.role_admin",
    "create_session_devices_controller": "litestar_auth.controllers",
    "create_totp_controller": "litestar_auth.controllers",
    "create_users_controller": "litestar_auth.controllers",
    "create_verify_controller": "litestar_auth.controllers",
}


def __getattr__(name: str) -> object:
    """Lazily resolve public helpers used by extension authors.

    Returns:
        Requested public extension-author helper.

    Raises:
        AttributeError: If ``name`` is not part of the public extension facade.
    """
    module_name = _PUBLIC_EXPORTS.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return the public extension facade inventory."""
    return sorted(__all__)
