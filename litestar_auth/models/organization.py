"""Organization ORM models used by the bundled multi-tenant identity contract."""

from __future__ import annotations

from advanced_alchemy.base import DefaultBase

from litestar_auth.models.mixins import OrganizationInvitationMixin, OrganizationMembershipMixin, OrganizationMixin


class Organization(OrganizationMixin, DefaultBase):
    """Bundled organization catalog row."""

    __tablename__ = "organization"
    auth_organization_invitation_model = "OrganizationInvitation"


class OrganizationMembership(OrganizationMembershipMixin, DefaultBase):
    """Bundled join row linking one user to one organization."""

    __tablename__ = "organization_membership"


class OrganizationInvitation(OrganizationInvitationMixin, DefaultBase):
    """Bundled organization invitation row storing only a token digest."""

    __tablename__ = "organization_invitation"
