"""Compatibility re-exports for the shared user-side relationship mixins."""

from __future__ import annotations

from litestar_auth.models.mixins import UserAuthRelationshipMixin, UserRoleRelationshipMixin

__all__ = ("UserAuthRelationshipMixin", "UserRoleRelationshipMixin")
