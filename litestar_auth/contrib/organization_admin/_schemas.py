"""Internal msgspec schemas for the opt-in contrib organization-admin HTTP surface."""

from __future__ import annotations

from typing import Annotated

import msgspec

import litestar_auth._schema_fields as schema_fields

_ORGANIZATION_NAME_MAX_LENGTH = 128
_ORGANIZATION_ROLE_MAX_LENGTH = 255
_ORGANIZATION_ROLE_LIST_MAX_LENGTH = 64

type OrganizationNameField = Annotated[str, msgspec.Meta(min_length=1, max_length=_ORGANIZATION_NAME_MAX_LENGTH)]
type OrganizationSlugField = schema_fields.OrganizationSlugField
type OrganizationRoleField = Annotated[str, msgspec.Meta(min_length=1, max_length=_ORGANIZATION_ROLE_MAX_LENGTH)]
type OrganizationRolesField = Annotated[
    list[OrganizationRoleField],
    msgspec.Meta(max_length=_ORGANIZATION_ROLE_LIST_MAX_LENGTH),
]


class OrganizationCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to create one normalized organization."""

    slug: OrganizationSlugField
    name: OrganizationNameField


class OrganizationUpdate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to replace mutable organization fields."""

    slug: OrganizationSlugField
    name: OrganizationNameField


class OrganizationRead(msgspec.Struct):
    """Public organization representation returned by contrib handlers."""

    id: str
    slug: str
    name: str


class MembershipCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to add one organization membership."""

    roles: OrganizationRolesField


class MembershipRolesUpdate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to replace one organization membership role set."""

    roles: OrganizationRolesField


class MembershipRead(msgspec.Struct):
    """Public organization membership representation returned by contrib handlers."""

    organization_id: str
    user_id: str
    roles: list[str]


class OrganizationInvitationCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to invite one email address into an organization."""

    invited_email: str
    roles: OrganizationRolesField


class OrganizationInvitationRead(msgspec.Struct):
    """Public invitation metadata returned by contrib admin handlers."""

    id: str
    organization_id: str
    invited_email: str
    roles: list[str]
    expires_at: str
    status: str


class OrganizationInvitationTokenRequest(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to accept or decline an organization invitation."""

    token: schema_fields.LongLivedTokenField


__all__ = (
    "MembershipCreate",
    "MembershipRead",
    "MembershipRolesUpdate",
    "OrganizationCreate",
    "OrganizationInvitationCreate",
    "OrganizationInvitationRead",
    "OrganizationInvitationTokenRequest",
    "OrganizationRead",
    "OrganizationUpdate",
)
