"""Reference :class:`User` ORM model built from the reusable auth model mixins."""

from __future__ import annotations

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.api_key import ApiKey as _BundledApiKey
from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserModelMixin, UserRoleRelationshipMixin
from litestar_auth.models.oauth import OAuthAccount as _BundledOAuthAccount
from litestar_auth.models.organization import OrganizationMembership as _BundledOrganizationMembership
from litestar_auth.models.role import Role as _BundledRole
from litestar_auth.models.role import UserRole as _BundledUserRole

# Ensure SQLAlchemy can resolve relationship targets against bundled mappers.
_ = _BundledApiKey
_ = _BundledOAuthAccount
_ = _BundledOrganizationMembership
_ = _BundledRole
_ = _BundledUserRole


class User(UserModelMixin, UserRoleRelationshipMixin, UserAuthRelationshipMixin, UUIDBase):
    """Base user model for authentication and authorization flows."""

    __tablename__ = "user"
    auth_api_key_model = "ApiKey"
    auth_organization_membership_model = "OrganizationMembership"
