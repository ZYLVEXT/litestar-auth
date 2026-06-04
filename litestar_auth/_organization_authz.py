"""Organization-scoped authorization helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._current_organization import read_scope_current_organization_context
from litestar_auth._roles import normalize_roles

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

__all__ = ("resolve_current_organization_roles",)


def resolve_current_organization_roles(connection: ASGIConnection[Any, Any, Any, Any]) -> frozenset[str] | None:
    """Return normalized roles from the verified current-organization membership.

    ``None`` means the request has no verified current-organization context. An
    empty set means the request has a verified membership with no organization
    roles.
    """
    context = read_scope_current_organization_context(connection)
    if context is None:
        return None

    return frozenset(normalize_roles(context.membership.roles))
