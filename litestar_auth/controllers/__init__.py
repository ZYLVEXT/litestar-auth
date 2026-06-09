"""Public controller factory exports.

Use ``litestar_auth.payloads`` for built-in request and response payload types.
"""

# ruff: noqa: RUF067

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_auth.controllers.api_keys import ApiKeysControllerConfig, create_api_keys_controllers
    from litestar_auth.controllers.auth import AuthControllerConfig, create_auth_controller
    from litestar_auth.controllers.oauth import (
        OAuthAssociateControllerConfig,
        OAuthControllerConfig,
        create_oauth_associate_controller,
        create_oauth_controller,
    )
    from litestar_auth.controllers.organization import (
        OrganizationControllerConfig,
        backend_supports_organization_tokens,
        create_organization_controller,
    )
    from litestar_auth.controllers.register import RegisterControllerConfig, create_register_controller
    from litestar_auth.controllers.reset import create_reset_password_controller
    from litestar_auth.controllers.session_devices import (
        SessionDevicesControllerConfig,
        create_session_devices_controller,
    )
    from litestar_auth.controllers.totp import TotpControllerOptions, TotpUserManagerProtocol, create_totp_controller
    from litestar_auth.controllers.users import UsersControllerConfig, create_users_controller
    from litestar_auth.controllers.verify import create_verify_controller

__all__ = (
    "ApiKeysControllerConfig",
    "AuthControllerConfig",
    "OAuthAssociateControllerConfig",
    "OAuthControllerConfig",
    "OrganizationControllerConfig",
    "RegisterControllerConfig",
    "SessionDevicesControllerConfig",
    "TotpControllerOptions",
    "TotpUserManagerProtocol",
    "UsersControllerConfig",
    "backend_supports_organization_tokens",
    "create_api_keys_controllers",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_organization_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_session_devices_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
)

_EXPORT_MODULES = {
    "ApiKeysControllerConfig": "litestar_auth.controllers.api_keys",
    "AuthControllerConfig": "litestar_auth.controllers.auth",
    "OAuthAssociateControllerConfig": "litestar_auth.controllers.oauth",
    "OAuthControllerConfig": "litestar_auth.controllers.oauth",
    "OrganizationControllerConfig": "litestar_auth.controllers.organization",
    "RegisterControllerConfig": "litestar_auth.controllers.register",
    "SessionDevicesControllerConfig": "litestar_auth.controllers.session_devices",
    "TotpControllerOptions": "litestar_auth.controllers.totp",
    "TotpUserManagerProtocol": "litestar_auth.controllers.totp",
    "UsersControllerConfig": "litestar_auth.controllers.users",
    "backend_supports_organization_tokens": "litestar_auth.controllers.organization",
    "create_api_keys_controllers": "litestar_auth.controllers.api_keys",
    "create_auth_controller": "litestar_auth.controllers.auth",
    "create_oauth_associate_controller": "litestar_auth.controllers.oauth",
    "create_oauth_controller": "litestar_auth.controllers.oauth",
    "create_organization_controller": "litestar_auth.controllers.organization",
    "create_register_controller": "litestar_auth.controllers.register",
    "create_reset_password_controller": "litestar_auth.controllers.reset",
    "create_session_devices_controller": "litestar_auth.controllers.session_devices",
    "create_totp_controller": "litestar_auth.controllers.totp",
    "create_users_controller": "litestar_auth.controllers.users",
    "create_verify_controller": "litestar_auth.controllers.verify",
}


def __getattr__(name: str) -> object:
    """Lazily resolve public controller factory exports.

    Returns:
        Requested public controller export.

    Raises:
        AttributeError: If ``name`` is not a supported public export.
    """
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return the public controller export inventory."""
    return sorted(__all__)
