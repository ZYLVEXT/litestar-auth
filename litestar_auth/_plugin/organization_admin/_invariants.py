"""Invariant guards for organization administration."""

from __future__ import annotations

from typing import Any

from litestar_auth._roles import normalize_roles


class _OrganizationAdminInvariantMixin[ORG, MEMBERSHIP, ID]:
    """Fail-closed organization membership invariants."""

    def _has_privileged_role(self: Any, roles: object) -> bool:
        """Return whether ``roles`` includes an organization-admin role."""
        return bool(set(normalize_roles(roles)) & self.privileged_role_names)

    async def caller_has_organization_authority(self: Any, *, organization_id: ID, user_id: ID) -> bool:
        """Return whether ``user_id`` holds a privileged membership in ``organization_id``.

        Used as a defense-in-depth authority check on path-scoped administration routes so
        authority is always verified against the organization actually being addressed.

        Returns:
            ``True`` when the user is a privileged (admin/owner) member of the organization.
        """
        membership = await self.store.get_membership(organization_id=organization_id, user_id=user_id)
        return membership is not None and self._has_privileged_role(membership.roles)
