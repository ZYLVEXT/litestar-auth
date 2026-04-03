"""Reference :class:`User` ORM model built from the reusable auth model mixins."""

from __future__ import annotations

import importlib

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserModelMixin

# Ensure the bundled OAuthAccount mapper is registered when the reference ``User`` is used.
importlib.import_module("litestar_auth.models.oauth")


class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):
    """Base user model for authentication and authorization flows."""

    __tablename__ = "user"
