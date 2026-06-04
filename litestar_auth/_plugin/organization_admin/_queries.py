"""Query helpers for organization administration."""

from __future__ import annotations

from typing import Any

from litestar_auth._roles import normalize_role_name
from litestar_auth.exceptions import OrganizationMembershipNotFoundError, OrganizationNotFoundError


class _OrganizationAdminQueryMixin[ORG, MEMBERSHIP, ID]:
    """Store-backed organization and membership read helpers."""

    async def get_organization(self: Any, organization_id: ID) -> ORG:
        """Return one organization or raise a non-enumerating lookup error."""
        return await self._require_organization(organization_id)

    async def get_organization_by_slug(self: Any, slug: str) -> ORG:
        """Return one organization by normalized slug or raise a lookup error.

        Raises:
            OrganizationNotFoundError: If the slug is unknown.
        """
        organization = await self.store.get_organization_by_slug(normalize_role_name(slug))
        if organization is None:
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg)
        return organization

    async def list_organizations_for_user(
        self: Any,
        user_id: ID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[ORG], int]:
        """Return paginated organizations for ``user_id`` and the total available count."""
        return await self.store.list_organizations_for_user(user_id, offset=offset, limit=limit)

    async def list_members(
        self: Any,
        organization_id: ID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[MEMBERSHIP], int]:
        """Return paginated memberships for a known organization and the total available count."""
        await self._require_organization(organization_id)
        return await self.store.list_memberships(organization_id, offset=offset, limit=limit)

    async def get_membership(self: Any, *, organization_id: ID, user_id: ID) -> MEMBERSHIP:
        """Return one organization membership or raise a non-enumerating lookup error."""
        return await self._require_membership(organization_id=organization_id, user_id=user_id)

    async def _require_organization(self: Any, organization_id: ID) -> ORG:
        """Return the organization row or raise when it is unknown.

        Raises:
            OrganizationNotFoundError: If the organization is unknown.
        """
        organization = await self.store.get_organization(organization_id)
        if organization is None:
            msg = "Organization not found."
            raise OrganizationNotFoundError(message=msg)
        return organization

    async def _require_membership(self: Any, *, organization_id: ID, user_id: ID) -> MEMBERSHIP:
        """Return the membership row or raise when it is unknown.

        Raises:
            OrganizationMembershipNotFoundError: If the membership is unknown.
        """
        await self._require_organization(organization_id)
        membership = await self.store.get_membership(organization_id=organization_id, user_id=user_id)
        if membership is None:
            msg = "Organization membership not found."
            raise OrganizationMembershipNotFoundError(message=msg)
        return membership
