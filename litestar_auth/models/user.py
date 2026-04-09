"""Reference :class:`User` ORM model built from the reusable auth model mixins."""

from __future__ import annotations

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserModelMixin
from litestar_auth.models.oauth import OAuthAccount as _BundledOAuthAccount

# Ensure SQLAlchemy can resolve ``User.oauth_accounts`` against the bundled OAuth mapper.
_ = _BundledOAuthAccount


class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):
    """Base user model for authentication and authorization flows."""

    __tablename__ = "user"
