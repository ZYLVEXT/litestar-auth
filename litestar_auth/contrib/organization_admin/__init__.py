"""Opt-in public surface for HTTP organization-administration controllers."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.contrib.organization_admin._controller import (
        OrganizationAdminAuthorizationPolicy,
        OrganizationAdminControllerConfig,
        OrganizationAdminOperation,
        OrganizationGlobalAuthorityPolicy,
        OrganizationInvitationControllerConfig,
        OrganizationPathAuthorityPolicy,
        OrganizationRoleDelegationPolicy,
        create_organization_admin_controller,
        create_organization_invitation_controller,
    )
    from litestar_auth.contrib.organization_admin._extension import OrganizationAdminExtension

__all__ = (
    "OrganizationAdminAuthorizationPolicy",
    "OrganizationAdminControllerConfig",
    "OrganizationAdminExtension",
    "OrganizationAdminOperation",
    "OrganizationGlobalAuthorityPolicy",
    "OrganizationInvitationControllerConfig",
    "OrganizationPathAuthorityPolicy",
    "OrganizationRoleDelegationPolicy",
    "create_organization_admin_controller",
    "create_organization_invitation_controller",
)


def __getattr__(name: str) -> Callable[..., object]:
    """Lazily resolve the public organization-admin controller factory.

    Returns:
        The requested public organization-admin factory.

    Raises:
        AttributeError: If ``name`` is not part of the public package surface.
    """
    if name in {
        "OrganizationAdminAuthorizationPolicy",
        "OrganizationAdminControllerConfig",
        "OrganizationAdminOperation",
        "OrganizationGlobalAuthorityPolicy",
        "OrganizationPathAuthorityPolicy",
        "OrganizationRoleDelegationPolicy",
    }:
        controller_module = import_module("litestar_auth.contrib.organization_admin._controller")
        return getattr(controller_module, name)
    if name == "create_organization_admin_controller":
        controller_module = import_module("litestar_auth.contrib.organization_admin._controller")
        return controller_module.create_organization_admin_controller
    if name == "OrganizationAdminExtension":
        extension_module = import_module("litestar_auth.contrib.organization_admin._extension")
        return extension_module.OrganizationAdminExtension
    if name == "OrganizationInvitationControllerConfig":
        controller_module = import_module("litestar_auth.contrib.organization_admin._controller")
        return controller_module.OrganizationInvitationControllerConfig
    if name == "create_organization_invitation_controller":
        controller_module = import_module("litestar_auth.contrib.organization_admin._controller")
        return controller_module.create_organization_invitation_controller
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
