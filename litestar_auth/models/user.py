"""Reference :class:`User` ORM model built from the reusable auth model mixins."""

from __future__ import annotations

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserModelMixin, UserRoleRelationshipMixin
from litestar_auth.models.oauth import OAuthAccount as _BundledOAuthAccount
from litestar_auth.models.role import Role as _BundledRole
from litestar_auth.models.role import UserRole as _BundledUserRole

# Ensure SQLAlchemy can resolve ``User.oauth_accounts`` against the bundled OAuth mapper.
_ = _BundledOAuthAccount
_ = _BundledRole
_ = _BundledUserRole


class User(UserModelMixin, UserRoleRelationshipMixin, UserAuthRelationshipMixin, UUIDBase):
    """Base user model for authentication and authorization flows."""

    __tablename__ = "user"
