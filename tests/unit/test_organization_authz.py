"""Tests for organization-scoped authorization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection

from litestar_auth._current_organization import CurrentOrganizationContext, set_scope_current_organization_context
from litestar_auth._organization_authz import resolve_current_organization_roles

pytestmark = pytest.mark.unit


@dataclass(frozen=True, slots=True)
class ExampleOrganization:
    """Organization row used by organization-authz helper tests."""

    id: UUID
    slug: str


@dataclass(frozen=True, slots=True)
class ExampleOrganizationMembership:
    """Membership row exposing organization-scoped roles."""

    organization_id: UUID
    user_id: UUID
    roles: object


class _GlobalRoleUser:
    """User whose global roles must not be read by org-scoped resolution."""

    @property
    def roles(self) -> list[str]:
        """Raise if the helper incorrectly falls back to global user roles.

        Raises:
            AssertionError: Always, because org-scoped resolution must ignore global roles.
        """
        msg = "global user roles must not be read"
        raise AssertionError(msg)


def _build_connection(
    *,
    state: object | None = None,
    user: object | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal HTTP connection for helper tests.

    Returns:
        Minimal Litestar ASGI connection.
    """
    scope: dict[str, object] = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
        "user": user,
        "auth": None,
    }
    if state is not None:
        scope["state"] = state
    return ASGIConnection(scope=cast("Any", scope))


def _set_context(connection: ASGIConnection[Any, Any, Any, Any], roles: object) -> None:
    """Store a verified organization context with the provided membership roles."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleOrganizationMembership(
        organization_id=organization.id,
        user_id=uuid4(),
        roles=roles,
    )
    set_scope_current_organization_context(
        connection.scope,
        CurrentOrganizationContext(organization=organization, membership=membership),
    )


def test_resolve_current_organization_roles_returns_normalized_membership_roles() -> None:
    """The helper resolves the organization membership role snapshot only."""
    connection = _build_connection(user=_GlobalRoleUser())
    _set_context(connection, [" Owner ", "billing", "OWNER", "Support"])

    assert resolve_current_organization_roles(connection) == frozenset({"billing", "owner", "support"})


def test_resolve_current_organization_roles_returns_none_without_context() -> None:
    """Missing verified organization context is distinct from an empty role set."""
    assert resolve_current_organization_roles(_build_connection()) is None


def test_resolve_current_organization_roles_preserves_empty_membership_roles() -> None:
    """A verified membership with no roles returns an empty set, not ``None``."""
    connection = _build_connection()
    _set_context(connection, [])

    assert resolve_current_organization_roles(connection) == frozenset()


def test_resolve_current_organization_roles_matches_shared_role_normalization() -> None:
    """Organization-scoped roles use the shared flat role normalization contract."""
    raw_roles = (" Admin ", "admin", "Billing", "billing")
    connection = _build_connection()
    _set_context(connection, raw_roles)

    assert resolve_current_organization_roles(connection) == frozenset({"admin", "billing"})
