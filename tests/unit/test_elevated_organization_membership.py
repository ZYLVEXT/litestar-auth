"""Tests for application-granted organization access without stored membership.

Multi-tenant applications need support and operations staff to work inside an organization they
are not a member of. Without a seam for it they override the store's ``get_membership`` to return
a row that does not exist, which reads as a lookup, hides the grant from audit, and risks
persisting a synthetic membership. The resolver is that seam, and every path here is a trust
boundary: it must stay closed by default, must never widen a member's own authority, and must be
distinguishable from real membership afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection

from litestar_auth._current_organization import (
    CurrentOrganizationContext,
    current_organization_is_elevated,
    read_scope_current_organization_context,
    set_scope_current_organization_context,
)
from litestar_auth.authentication.middleware import LitestarAuthMiddleware

pytestmark = pytest.mark.unit


@dataclass(frozen=True, slots=True)
class ExampleOrganization:
    """Organization row returned by the fake store."""

    id: UUID
    slug: str


@dataclass(frozen=True, slots=True)
class ExampleMembership:
    """Membership row carrying organization-scoped roles."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


@dataclass(frozen=True, slots=True)
class ExampleUser:
    """Authenticated principal reaching an organization-scoped route."""

    id: UUID


class _Store:
    """Organization store with a fixed organization and an optional stored membership."""

    def __init__(self, organization: ExampleOrganization | None, membership: ExampleMembership | None) -> None:
        self._organization = organization
        self._membership = membership
        self.membership_lookups = 0

    async def get_organization_by_slug(self, slug: str) -> ExampleOrganization | None:
        """Return the configured organization when the slug matches."""
        if self._organization is None or self._organization.slug != slug:
            return None
        return self._organization

    async def get_membership(self, *, organization_id: UUID, user_id: UUID) -> ExampleMembership | None:
        """Return the configured stored membership, if any."""
        self.membership_lookups += 1
        _ = organization_id, user_id
        return self._membership


def _build_connection() -> ASGIConnection[Any, Any, Any, Any]:
    """Build a minimal HTTP connection with mutable scope state.

    Returns:
        A connection whose scope state can carry an organization context.
    """
    scope = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
        "user": None,
        "auth": None,
        "state": {},
    }
    return ASGIConnection(scope=cast("Any", scope))


def _build_middleware(
    *,
    store: _Store | None,
    elevated_membership_resolver: object | None,
    tenant_resolver: object | None = None,
) -> LitestarAuthMiddleware[Any, Any]:
    """Build a middleware instance wired only with the organization seams under test.

    Returns:
        A middleware whose organization resolution can be driven directly.
    """
    middleware = cast("LitestarAuthMiddleware[Any, Any]", LitestarAuthMiddleware.__new__(LitestarAuthMiddleware))
    middleware.organization_store_factory = cast("Any", None if store is None else lambda _session: store)
    middleware.tenant_resolver = cast(
        "Any",
        (lambda _connection: "acme") if tenant_resolver is None else tenant_resolver,
    )
    middleware.elevated_membership_resolver = cast("Any", elevated_membership_resolver)
    return middleware


async def test_stored_membership_is_not_marked_elevated() -> None:
    """A member acting in their own organization must not be reported as elevated access."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    user = ExampleUser(id=uuid4())
    membership = ExampleMembership(organization_id=organization.id, user_id=user.id, roles=["owner"])
    middleware = _build_middleware(store=_Store(organization, membership), elevated_membership_resolver=None)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=user,
    )

    context = read_scope_current_organization_context(connection)
    assert context is not None
    assert context.membership is membership
    assert context.elevated is False
    assert current_organization_is_elevated(connection) is False


async def test_resolver_is_not_consulted_for_a_member() -> None:
    """Elevation may add access for a stranger; it must never rewrite a member's own authority."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    user = ExampleUser(id=uuid4())
    membership = ExampleMembership(organization_id=organization.id, user_id=user.id, roles=["viewer"])
    consulted = False

    async def resolver(  # ruff: ignore[unused-async] - the protocol returns an awaitable
        _connection: ASGIConnection[Any, Any, Any, Any], *, organization: ExampleOrganization, user: ExampleUser
    ) -> ExampleMembership:
        nonlocal consulted
        consulted = True
        return ExampleMembership(organization_id=organization.id, user_id=user.id, roles=["owner"])

    middleware = _build_middleware(store=_Store(organization, membership), elevated_membership_resolver=resolver)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=user,
    )

    context = read_scope_current_organization_context(connection)
    assert context is not None
    assert context.membership.roles == ["viewer"]
    assert consulted is False


async def test_resolver_grants_access_and_marks_it_elevated() -> None:
    """A non-member the application vouches for reaches the organization, visibly borrowed."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    user = ExampleUser(id=uuid4())
    seen: dict[str, Any] = {}

    async def resolver(  # ruff: ignore[unused-async] - the protocol returns an awaitable
        connection: ASGIConnection[Any, Any, Any, Any], *, organization: ExampleOrganization, user: ExampleUser
    ) -> ExampleMembership:
        seen.update(connection=connection, organization=organization, user=user)
        return ExampleMembership(organization_id=organization.id, user_id=user.id, roles=["support"])

    middleware = _build_middleware(store=_Store(organization, None), elevated_membership_resolver=resolver)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=user,
    )

    context = read_scope_current_organization_context(connection)
    assert context is not None
    assert context.membership.roles == ["support"]
    assert context.elevated is True
    assert current_organization_is_elevated(connection) is True
    # The resolver decides on the request, so it has to see who is asking and where.
    assert seen == {"connection": connection, "organization": organization, "user": user}


async def test_resolver_refusal_leaves_no_organization_context() -> None:
    """Returning ``None`` denies the request rather than granting an empty context."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")

    async def resolver(  # ruff: ignore[unused-async] - the protocol returns an awaitable
        _connection: ASGIConnection[Any, Any, Any, Any], *, organization: ExampleOrganization, user: ExampleUser
    ) -> None:
        _ = organization, user

    middleware = _build_middleware(store=_Store(organization, None), elevated_membership_resolver=resolver)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=ExampleUser(id=uuid4()),
    )

    assert read_scope_current_organization_context(connection) is None
    assert current_organization_is_elevated(connection) is False


async def test_unconfigured_resolver_keeps_a_non_member_out() -> None:
    """The default path is unchanged and closed: no resolver, no access for a stranger."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    middleware = _build_middleware(store=_Store(organization, None), elevated_membership_resolver=None)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=ExampleUser(id=uuid4()),
    )

    assert read_scope_current_organization_context(connection) is None


@pytest.mark.parametrize(
    ("store", "tenant_resolver"),
    [
        pytest.param(None, None, id="organizations-disabled"),
        pytest.param(_Store(ExampleOrganization(id=uuid4(), slug="acme"), None), lambda _c: None, id="no-slug"),
        pytest.param(_Store(None, None), None, id="unknown-organization"),
    ],
)
async def test_resolver_is_unreachable_without_a_resolved_organization(
    store: _Store | None,
    tenant_resolver: object | None,
) -> None:
    """Elevation cannot substitute for an organization the request never identified."""

    async def resolver(  # ruff: ignore[unused-async] - the protocol returns an awaitable
        _connection: ASGIConnection[Any, Any, Any, Any], *, organization: ExampleOrganization, user: ExampleUser
    ) -> ExampleMembership:
        _ = organization, user
        msg = "resolver must not be consulted without a resolved organization"
        raise AssertionError(msg)

    middleware = _build_middleware(
        store=store,
        elevated_membership_resolver=resolver,
        tenant_resolver=tenant_resolver,
    )
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=ExampleUser(id=uuid4()),
    )

    assert read_scope_current_organization_context(connection) is None


async def test_missing_identifiers_never_reach_the_resolver() -> None:
    """An organization or user without an ``id`` is an incomplete request, not a grant."""

    async def resolver(  # ruff: ignore[unused-async] - the protocol returns an awaitable
        _connection: ASGIConnection[Any, Any, Any, Any], *, organization: ExampleOrganization, user: ExampleUser
    ) -> ExampleMembership:
        _ = organization, user
        msg = "resolver must not be consulted without both identifiers"
        raise AssertionError(msg)

    organization = ExampleOrganization(id=uuid4(), slug="acme")
    middleware = _build_middleware(store=_Store(organization, None), elevated_membership_resolver=resolver)
    connection = _build_connection()

    await middleware._publish_current_organization_context_if_applicable(
        connection,
        session=cast("Any", object()),
        user=object(),
    )

    assert read_scope_current_organization_context(connection) is None


def test_elevation_is_false_for_a_request_with_no_organization() -> None:
    """Absence of context is not elevated access, so audit does not report a grant."""
    assert current_organization_is_elevated(_build_connection()) is False


def test_context_defaults_to_stored_membership() -> None:
    """Existing constructions keep their meaning: elevation is opt-in, never inferred."""
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleMembership(organization_id=organization.id, user_id=uuid4(), roles=[])
    connection = _build_connection()

    set_scope_current_organization_context(
        connection.scope,
        CurrentOrganizationContext(organization=organization, membership=membership),
    )

    assert current_organization_is_elevated(connection) is False
