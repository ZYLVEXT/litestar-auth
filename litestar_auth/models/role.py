"""Role ORM models used by the bundled relational role contract."""

from __future__ import annotations

from advanced_alchemy.base import DefaultBase
from sqlalchemy.orm import Mapped, mapped_column

from litestar_auth.models.mixins import RoleMixin, UserRoleAssociationMixin


class Role(RoleMixin, DefaultBase):
    """Bundled global role catalog row."""

    __tablename__ = "role"

    description: Mapped[str | None] = mapped_column(nullable=True, default=None)
    """Optional description or documentation for the role."""


class UserRole(UserRoleAssociationMixin, DefaultBase):
    """Bundled association row linking one user to one role."""

    __tablename__ = "user_role"
