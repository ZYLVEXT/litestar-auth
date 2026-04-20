"""Internal msgspec schemas for the opt-in contrib role-admin HTTP surface."""

from __future__ import annotations

import msgspec


class RoleCreate(msgspec.Struct):
    """Payload used to create one normalized role-catalog entry."""

    name: str
    description: str | None = None


class RoleUpdate(msgspec.Struct, omit_defaults=True):
    """Partial role update payload with immutable role names."""

    description: str | None = None


class RoleRead(msgspec.Struct):
    """Public role-catalog representation returned by contrib handlers."""

    name: str
    description: str | None = None


class UserBrief(msgspec.Struct):
    """Public non-sensitive user summary for role-assignment listings."""

    id: str
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


__all__ = ("RoleCreate", "RoleRead", "RoleUpdate", "UserBrief")
