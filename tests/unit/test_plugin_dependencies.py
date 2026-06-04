"""Unit tests for auth plugin dependency and exception-handler wiring helpers."""

from __future__ import annotations

import asyncio
import importlib
import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast, get_type_hints
from uuid import UUID, uuid4

import pytest
from litestar import Controller, Litestar, Request, get
from litestar.config.app import AppConfig
from litestar.datastructures.state import State
from litestar.di import NamedDependency, Provide
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response
from litestar.testing import AsyncTestClient

import litestar_auth._plugin.dependencies as dependencies_module
from litestar_auth._current_organization import (
    CurrentOrganizationContext,
    read_scope_current_organization_context,
    set_scope_current_organization_context,
)
from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
    DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config import LitestarAuthConfig, OAuthConfig, OrganizationConfig
from litestar_auth._plugin.scoped_session import SESSION_SCOPE_KEY, SessionFactory
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.exceptions import AuthorizationError, ErrorCode, InsufficientRolesError
from litestar_auth.guards import has_permission
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

DependencyProviders = dependencies_module.DependencyProviders
_make_backends_dependency_provider = dependencies_module._make_backends_dependency_provider
_make_db_session_provide = dependencies_module._make_db_session_provide
_make_user_manager_dependency_provider = dependencies_module._make_user_manager_dependency_provider
authorization_error_handler = dependencies_module.authorization_error_handler
client_exception_handler = dependencies_module.client_exception_handler
register_dependencies = dependencies_module.register_dependencies
register_exception_handlers = dependencies_module.register_exception_handlers

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.db import MembershipData, OrganizationData, OrganizationInvitationData

pytestmark = pytest.mark.unit
OAUTH_FLOW_COOKIE_SECRET = "oauth-flow-cookie-secret-1234567890"
_ResolvedPermissions = NamedDependency[frozenset[str]]


def _oauth_provider(*, name: str, client: object) -> OAuthProviderConfig:
    """Build an OAuthProviderConfig using the current runtime class.

    Returns:
        The current-runtime OAuthProviderConfig instance.
    """
    config_module = importlib.import_module("litestar_auth.config")
    oauth_provider_config_type = cast("type[Any]", config_module.OAuthProviderConfig)
    return oauth_provider_config_type(name=name, client=client)


HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_IM_A_TEAPOT = 418
HTTP_OK = 200


@dataclass(frozen=True, slots=True)
class ExampleOrganization:
    """Organization row used by current-organization dependency tests."""

    id: UUID
    slug: str


@dataclass(frozen=True, slots=True)
class ExampleOrganizationMembership:
    """Organization membership row used by current-organization dependency tests."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


class RecordingOrganizationStore:
    """Organization store fixture that records tenant and membership lookups."""

    def __init__(
        self,
        *,
        organization: ExampleOrganization | None,
        membership: ExampleOrganizationMembership | None,
    ) -> None:
        """Configure lookup results for one dependency test app."""
        self.organization = organization
        self.membership = membership
        self.slug_calls: list[str] = []
        self.membership_calls: list[tuple[UUID, UUID]] = []

    async def get_organization_by_slug(self, slug: str) -> ExampleOrganization | None:
        """Return the configured organization and record the slug lookup."""
        self.slug_calls.append(slug)
        await asyncio.sleep(0)
        return self.organization

    async def create_organization(self, data: OrganizationData) -> ExampleOrganization:
        """Persist a test organization in memory.

        Returns:
            The stored organization row.
        """
        self.organization = ExampleOrganization(id=uuid4(), slug=data.slug)
        return self.organization

    async def get_organization(self, organization_id: UUID) -> ExampleOrganization | None:
        """Return the configured organization when its id matches."""
        if self.organization is not None and self.organization.id == organization_id:
            return self.organization
        return None

    async def update_organization(self, organization_id: UUID, data: OrganizationData) -> ExampleOrganization | None:
        """Update the configured organization when its id matches.

        Returns:
            Updated organization when present, otherwise ``None``.
        """
        if self.organization is None or self.organization.id != organization_id:
            return None
        self.organization = ExampleOrganization(id=organization_id, slug=data.slug)
        return self.organization

    async def delete_organization(self, organization_id: UUID) -> bool:
        """Delete the configured organization when its id matches.

        Returns:
            Whether the configured organization was removed.
        """
        if self.organization is None or self.organization.id != organization_id:
            return False
        self.organization = None
        self.membership = None
        return True

    async def add_membership(self, data: MembershipData[UUID]) -> ExampleOrganizationMembership:
        """Persist a test membership in memory.

        Returns:
            The stored membership row.
        """
        self.membership = ExampleOrganizationMembership(
            organization_id=data.organization_id,
            user_id=data.user_id,
            roles=data.roles,
        )
        return self.membership

    async def get_membership(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> ExampleOrganizationMembership | None:
        """Return the configured membership and record the lookup."""
        self.membership_calls.append((organization_id, user_id))
        await asyncio.sleep(0)
        return self.membership

    async def list_memberships(
        self,
        organization_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[ExampleOrganizationMembership], int]:
        """Return the configured membership when it belongs to the organization."""
        if self.membership is not None and self.membership.organization_id == organization_id:
            memberships = [self.membership]
            return memberships[offset : offset + limit], len(memberships)
        return [], 0

    async def remove_membership(self, *, organization_id: UUID, user_id: UUID) -> bool:
        """Remove the configured membership when both identifiers match.

        Returns:
            Whether the configured membership was removed.
        """
        if (
            self.membership is not None
            and self.membership.organization_id == organization_id
            and self.membership.user_id == user_id
        ):
            self.membership = None
            return True
        return False

    async def remove_membership_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        privileged_roles: frozenset[str],
    ) -> bool:
        """Remove the configured membership for protocol conformance.

        Returns:
            Whether the configured membership was removed.
        """
        return await self.remove_membership(organization_id=organization_id, user_id=user_id)

    async def set_membership_roles(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
    ) -> ExampleOrganizationMembership | None:
        """Replace the configured membership roles when both identifiers match.

        Returns:
            Updated membership when present, otherwise ``None``.
        """
        if (
            self.membership is None
            or self.membership.organization_id != organization_id
            or self.membership.user_id != user_id
        ):
            return None
        self.membership = ExampleOrganizationMembership(organization_id=organization_id, user_id=user_id, roles=roles)
        return self.membership

    async def set_membership_roles_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> ExampleOrganizationMembership | None:
        """Replace membership roles for protocol conformance.

        Returns:
            Updated membership when present, otherwise ``None``.
        """
        return await self.set_membership_roles(organization_id=organization_id, user_id=user_id, roles=roles)

    async def list_organizations_for_user(
        self,
        user_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[ExampleOrganization], int]:
        """Return the configured organization when the user has the configured membership."""
        if (
            self.organization is not None
            and self.membership is not None
            and self.membership.organization_id == self.organization.id
            and self.membership.user_id == user_id
        ):
            organizations = [self.organization]
            return organizations[offset : offset + limit], len(organizations)
        return [], 0

    async def create_invitation(self, data: OrganizationInvitationData[UUID]) -> object:
        """Return an inert invitation row for protocol conformance."""
        return data

    async def get_invitation_by_token_hash(self, token_hash: bytes) -> object | None:
        """Current-organization dependency tests never resolve invitations.

        Returns:
            ``None`` because this fixture has no invitations.
        """
        return None

    async def get_invitation(self, invitation_id: UUID) -> object | None:
        """Current-organization dependency tests never resolve invitations.

        Returns:
            ``None`` because this fixture has no invitations.
        """
        return None

    async def list_pending_invitations(
        self,
        organization_id: UUID,
        *,
        now: datetime,
        offset: int,
        limit: int,
    ) -> tuple[list[object], int]:
        """Current-organization dependency tests never list invitations.

        Returns:
            Empty invitation list.
        """
        return [], 0

    async def revoke_invitation(self, invitation_id: UUID) -> object | None:
        """Current-organization dependency tests never revoke invitations.

        Returns:
            ``None`` because this fixture has no invitations.
        """
        return None

    async def consume_invitation(self, invitation_id: UUID, *, consumed_at: datetime) -> object | None:
        """Current-organization dependency tests never consume invitations.

        Returns:
            ``None`` because this fixture has no invitations.
        """
        return None


_CurrentOrganization = NamedDependency[object | None]


def _minimal_config() -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for dependency-registration tests.

    Returns:
        Plugin config suitable for isolated dependency-wiring assertions.
    """
    user_db = InMemoryUserDatabase([])
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-dependencies")),
            ),
        ],
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        include_users=False,
    )


def _providers() -> DependencyProviders:
    """Create provider callables matching plugin registration behavior.

    Returns:
        Dependency provider bundle matching the plugin's expected shapes.
    """

    def provide_config() -> object:
        return object()

    async def provide_user_manager(db_session: object) -> object:
        await asyncio.sleep(0)
        yield ("manager", db_session)

    def provide_backends() -> tuple[str, ...]:
        return ("primary",)

    def provide_user_model() -> type[ExampleUser]:
        return ExampleUser

    async def provide_oauth_associate_user_manager(db_session: object) -> object:
        await asyncio.sleep(0)
        yield ("oauth-associate", db_session)

    return DependencyProviders(
        config=provide_config,
        user_manager=provide_user_manager,
        backends=provide_backends,
        user_model=provide_user_model,
        oauth_associate_user_manager=provide_oauth_associate_user_manager,
    )


@get("/permissions", guards=[has_permission("posts:read")], sync_to_thread=False)
def _permissions_probe(litestar_auth_permissions: _ResolvedPermissions) -> dict[str, list[str]]:
    """Expose injected resolved permissions for integration coverage.

    Returns:
        Sorted effective permissions from plugin DI.
    """
    return {"permissions": sorted(litestar_auth_permissions)}


@get("/anonymous-permissions", sync_to_thread=False)
def _anonymous_permissions_probe(litestar_auth_permissions: _ResolvedPermissions) -> dict[str, list[str]]:
    """Expose injected resolved permissions without authentication.

    Returns:
        Sorted effective permissions from plugin DI.
    """
    return {"permissions": sorted(litestar_auth_permissions)}


def _permissions_app() -> tuple[Litestar, InMemoryTokenStrategy, ExampleUser]:
    """Build a plugin app with role-permission DI enabled.

    Returns:
        The app, backing token strategy, and authenticated test user.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="permissions@example.com",
        hashed_password=password_helper.hash("permissions-password"),
        is_verified=True,
        roles=["editor"],
    )
    user_db = InMemoryUserDatabase([user])
    strategy = InMemoryTokenStrategy(token_prefix="permissions")
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", strategy),
            ),
        ],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        role_permissions={
            "editor": ("posts:read", "posts:write"),
        },
        include_users=False,
    )
    return (
        Litestar(
            route_handlers=[_permissions_probe, _anonymous_permissions_probe],
            plugins=[LitestarAuth(config)],
        ),
        strategy,
        user,
    )


@get("/current-organization", guards=[has_permission("posts:read")], sync_to_thread=False)
def _current_organization_probe(
    request: Request[ExampleUser, Any, Any],
    litestar_auth_current_organization: _CurrentOrganization,
) -> dict[str, object]:
    """Expose injected current-organization context for integration coverage.

    Returns:
        Serialized current-organization context metadata.
    """
    context = cast(
        "CurrentOrganizationContext[ExampleOrganization, ExampleOrganizationMembership] | None",
        litestar_auth_current_organization,
    )
    scope_context = read_scope_current_organization_context(request)
    if context is None:
        return {"context": None, "same_as_scope": scope_context is None}
    return {
        "context": {
            "organization_id": str(context.organization.id),
            "organization_slug": context.organization.slug,
            "membership_user_id": str(context.membership.user_id),
            "membership_roles": context.membership.roles,
        },
        "same_as_scope": context is scope_context,
    }


@get("/anonymous-current-organization", sync_to_thread=False)
def _anonymous_current_organization_probe(
    litestar_auth_current_organization: _CurrentOrganization,
) -> dict[str, object]:
    """Expose current-organization DI for unauthenticated requests.

    Returns:
        Serialized absence of a verified current-organization context.
    """
    return {"context": litestar_auth_current_organization}


def _current_organization_app(
    *,
    membership: ExampleOrganizationMembership | None,
) -> tuple[Litestar, InMemoryTokenStrategy, ExampleUser, ExampleOrganization, RecordingOrganizationStore]:
    """Build a plugin app with current-organization DI enabled.

    Returns:
        App, token strategy, authenticated user, organization row, and recording store.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="tenant-member@example.com",
        hashed_password=password_helper.hash("tenant-password"),
        is_verified=True,
        roles=["editor"],
    )
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    store = RecordingOrganizationStore(organization=organization, membership=membership)
    user_db = InMemoryUserDatabase([user])
    strategy = InMemoryTokenStrategy(token_prefix="current-organization")

    def resolve_tenant(connection: object) -> str:
        """Return the tenant slug for dependency integration requests."""
        return "acme"

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", strategy),
            ),
        ],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=lambda _session: store,
            tenant_resolver=resolve_tenant,
        ),
        role_permissions={
            "editor": ("posts:read",),
            "owner": ("posts:read",),
        },
        include_users=False,
    )
    return (
        Litestar(
            route_handlers=[_current_organization_probe, _anonymous_current_organization_probe],
            plugins=[LitestarAuth(config)],
        ),
        strategy,
        user,
        organization,
        store,
    )


def test_client_exception_handler_formats_json_response() -> None:
    """ClientException values are surfaced in the auth JSON error contract."""
    exc = ClientException(
        detail="bad credentials",
        extra={"code": "AUTH_FAILED"},
        status_code=418,
        headers={"X-Auth": "1"},
    )

    response = client_exception_handler(cast("Any", None), exc)

    assert response.content == {"detail": "bad credentials", "code": "AUTH_FAILED"}
    assert response.status_code == HTTP_IM_A_TEAPOT
    assert response.media_type == MediaType.JSON
    assert response.headers == {"X-Auth": "1"}


def test_client_exception_handler_uses_error_code_unknown_when_extra_omits_code() -> None:
    """Auth JSON responses fall back to ErrorCode.UNKNOWN when no string code is in ClientException.extra."""
    exc = ClientException(detail="unspecified failure", extra={}, status_code=HTTP_BAD_REQUEST)

    response = client_exception_handler(cast("Any", None), exc)

    assert response.content == {"detail": "unspecified failure", "code": ErrorCode.UNKNOWN}
    assert response.status_code == HTTP_BAD_REQUEST


def test_authorization_error_handler_formats_base_authorization_error() -> None:
    """AuthorizationError values are surfaced as 403 auth JSON responses."""
    exc = AuthorizationError("denied")

    response = authorization_error_handler(cast("Any", None), exc)

    assert response.content == {"detail": "denied", "code": ErrorCode.AUTHORIZATION_DENIED}
    assert response.status_code == HTTP_FORBIDDEN
    assert response.media_type == MediaType.JSON


def test_authorization_error_handler_omits_structured_role_context() -> None:
    """Default insufficient-role responses keep role metadata off the wire."""
    exc = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"support"}),
        require_all=True,
    )

    response = authorization_error_handler(cast("Any", None), exc)

    assert response.content == {
        "detail": str(exc),
        "code": ErrorCode.INSUFFICIENT_ROLES,
    }
    assert response.status_code == HTTP_FORBIDDEN


def test_register_exception_handlers_preserves_existing_handlers() -> None:
    """Registering auth handlers keeps existing controller handlers while adding ClientException."""

    def existing_handler(_request: object, _exc: Exception) -> Response[dict[str, str]]:
        """Placeholder handler used to confirm existing handlers are preserved.

        Returns:
            Static JSON response used only for handler identity checks.
        """
        return Response({"detail": "runtime", "code": "RUNTIME"}, media_type=MediaType.JSON)

    @_mark_litestar_auth_route_handler
    class ExistingController(Controller):
        path = "/auth"

    ExistingController.exception_handlers = {RuntimeError: existing_handler}

    register_exception_handlers([ExistingController])
    handlers = cast("dict[type[Exception], object]", ExistingController.exception_handlers)

    assert handlers[RuntimeError] is existing_handler
    assert handlers[ClientException] is dependencies_module.client_exception_handler
    assert handlers[AuthorizationError] is dependencies_module.authorization_error_handler


def test_register_exception_handlers_preserves_existing_client_exception_handler() -> None:
    """Registering auth handlers does not override controller-local ClientException handlers."""

    def existing_handler(_request: object, _exc: Exception) -> Response[dict[str, str]]:
        """Return a sentinel response for identity assertions.

        Returns:
            Static JSON response used only for handler identity checks.
        """
        return Response({"detail": "existing", "code": "EXISTING"}, media_type=MediaType.JSON)

    @_mark_litestar_auth_route_handler
    class ExistingController(Controller):
        path = "/auth"

    ExistingController.exception_handlers = {ClientException: existing_handler}

    register_exception_handlers([ExistingController])
    handlers = cast("dict[type[Exception], object]", ExistingController.exception_handlers)

    assert handlers[ClientException] is existing_handler


def test_register_exception_handlers_only_mutates_handlers_it_receives() -> None:
    """Scope is controlled by the exact handler list supplied by the caller."""

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth"

    class NonAuthController(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/auth-state"

    register_exception_handlers([PluginOwnedController])

    assert PluginOwnedController.exception_handlers is not None
    assert PluginOwnedController.exception_handlers[ClientException] is dependencies_module.client_exception_handler
    assert NonAuthController.exception_handlers is None


def test_register_exception_handlers_adds_authorization_handler_to_non_auth_routes() -> None:
    """AuthorizationError mapping is attached to app routes so library guards work outside generated controllers."""

    class ApplicationRoute(Controller):
        exception_handlers: dict[type[Exception], object] | None = None
        path = "/app"

    register_exception_handlers([ApplicationRoute])

    handlers = cast("dict[type[Exception], object]", ApplicationRoute.exception_handlers)

    assert handlers[AuthorizationError] is dependencies_module.authorization_error_handler
    assert ClientException not in handlers


def test_make_db_session_provide_reuses_scoped_session_within_scope() -> None:
    """The generated sync provider reuses sessions for structurally compatible factories."""
    session_maker = assert_structural_session_factory(DummySessionMaker())
    provider = _make_db_session_provide(
        cast("async_sessionmaker[AsyncSession]", session_maker),
        session_scope_key=SESSION_SCOPE_KEY,
    )
    state = State()
    scope: dict[str, object] = {}

    first_session = provider(state, cast("Any", scope))
    second_session = provider(state, cast("Any", scope))
    other_scope_session = provider(state, cast("Any", {}))

    assert first_session is second_session
    assert other_scope_session is not first_session


def test_make_db_session_provide_annotations_are_runtime_resolvable() -> None:
    """Runtime type-hint resolution for the DB-session provider keeps SessionFactory available."""
    hints = get_type_hints(_make_db_session_provide)

    assert hints["session_maker"] is SessionFactory


def test_make_backends_dependency_provider_exposes_configured_di_parameter_name() -> None:
    """Backends providers expose the configured dependency key and accept Litestar-style injection."""
    marker = object()
    seen_sessions: list[object] = []

    def build_backends(session: AsyncSession) -> tuple[AuthenticationBackend[ExampleUser, UUID], ...]:
        seen_sessions.append(session)
        return ()

    provider = _make_backends_dependency_provider(build_backends, "custom_db_session")
    parameter_names = tuple(inspect.signature(provider).parameters)

    assert provider(custom_db_session=marker) == ()
    assert seen_sessions == [marker]
    assert parameter_names == ("custom_db_session",)


def test_make_backends_dependency_provider_rejects_multiple_positional_sessions() -> None:
    """Backends providers fail closed when callers supply more than one positional session."""

    def build_backends(_session: AsyncSession) -> tuple[AuthenticationBackend[ExampleUser, UUID], ...]:
        pytest.fail("build_backends should not run when too many positional dependency inputs are provided")

    provider = _make_backends_dependency_provider(build_backends, "db_session")
    with pytest.raises(TypeError, match="takes 1 positional argument but 2 were given"):
        provider(object(), object())


async def test_make_user_manager_dependency_provider_exposes_configured_di_parameter_name() -> None:
    """User-manager providers expose the configured dependency key and yield the injected manager."""
    marker = object()

    def build_user_manager(session: object) -> object:
        return ("manager", session)

    provider = _make_user_manager_dependency_provider(build_user_manager, "custom_db_session")
    generator = cast("Any", provider(custom_db_session=marker))
    try:
        manager = await anext(generator)
    finally:
        await generator.aclose()

    parameter_names = tuple(inspect.signature(provider).parameters)
    assert manager == ("manager", marker)
    assert parameter_names == ("custom_db_session",)


def test_make_user_manager_dependency_provider_rejects_positional_and_keyword_session() -> None:
    """Providing both the positional session and keyword DI value fails closed."""
    marker = object()

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run when duplicate dependency inputs are provided")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="db_session"):
        provider(marker, db_session=marker)


async def test_make_user_manager_dependency_provider_positional_path_stops_after_single_yield() -> None:
    """The direct positional-call path yields once and then stops cleanly."""
    marker = object()

    def build_user_manager(session: object) -> object:
        return ("manager", session)

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    generator = provider(marker)

    assert await anext(generator) == ("manager", marker)
    with pytest.raises(StopAsyncIteration):
        await anext(generator)


def test_make_user_manager_dependency_provider_requires_session_dependency() -> None:
    """Calling the provider without the configured dependency key raises TypeError."""

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run when the dependency is missing")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="db_session"):
        provider()


def test_make_user_manager_dependency_provider_rejects_unexpected_keyword_dependencies() -> None:
    """Unexpected keyword dependencies are rejected before building a user manager."""
    marker = object()

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run for unexpected keyword dependencies")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="other_session"):
        provider(other_session=marker)


def test_register_dependencies_raises_for_dependency_key_collisions() -> None:
    """Pre-existing app dependency keys fail closed before auth wiring mutates the app."""
    app_config = AppConfig()
    app_config.dependencies[DEFAULT_CONFIG_DEPENDENCY_KEY] = Provide(lambda: None, sync_to_thread=False)
    config = _minimal_config()

    with pytest.raises(ValueError, match=DEFAULT_CONFIG_DEPENDENCY_KEY):
        register_dependencies(app_config, config, providers=_providers())


def test_provide_resolved_permissions_returns_empty_set_for_anonymous_request() -> None:
    """The resolved-permissions provider is predictable before authentication."""
    request = Request(
        scope=cast(
            "Any",
            {
                "type": "http",
                "path": "/anonymous-permissions",
                "headers": [],
                "state": {},
                "user": None,
            },
        ),
    )

    assert dependencies_module.provide_resolved_permissions(request) == frozenset()


def test_provide_current_organization_returns_scope_context_or_none() -> None:
    """The current-organization provider exposes only verified scope context."""
    scope = cast(
        "Any",
        {
            "type": "http",
            "path": "/current-organization",
            "headers": [],
            "state": {},
            "user": None,
        },
    )
    request = Request(scope=scope)
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleOrganizationMembership(organization_id=organization.id, user_id=uuid4(), roles=["owner"])
    context = CurrentOrganizationContext(organization=organization, membership=membership)

    assert dependencies_module.provide_current_organization(request) is None

    set_scope_current_organization_context(scope, context)

    assert dependencies_module.provide_current_organization(request) is context


async def test_register_dependencies_registers_core_providers_and_autocommit_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core dependency keys, request-scoped DB DI, and autocommit wiring are all registered."""
    app_config = AppConfig()
    config = _minimal_config()
    autocommit_handler = object()
    monkeypatch.setattr(
        "litestar_auth._plugin.dependencies.async_autocommit_handler_maker",
        lambda **_: autocommit_handler,
    )

    register_dependencies(app_config, config, providers=_providers())

    assert set(app_config.dependencies) >= {
        DEFAULT_CONFIG_DEPENDENCY_KEY,
        DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        DEFAULT_BACKENDS_DEPENDENCY_KEY,
        DEFAULT_USER_MODEL_DEPENDENCY_KEY,
        DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY,
        DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY,
        config.db_session_dependency_key,
    }
    assert app_config.before_send == [autocommit_handler]

    db_session_provider = app_config.dependencies[config.db_session_dependency_key]
    assert isinstance(db_session_provider, Provide)
    assert db_session_provider.use_cache is False
    assert db_session_provider.sync_to_thread is False
    scoped_scope: dict[str, object] = {}
    first_session = db_session_provider.dependency(State(), cast("Any", scoped_scope))
    second_session = db_session_provider.dependency(State(), cast("Any", scoped_scope))
    assert first_session is second_session

    user_manager_provider = app_config.dependencies[DEFAULT_USER_MANAGER_DEPENDENCY_KEY]
    assert isinstance(user_manager_provider, Provide)
    assert user_manager_provider.use_cache is False
    generator = user_manager_provider.dependency(db_session=first_session)
    try:
        user_manager = await anext(generator)
    finally:
        await generator.aclose()
    assert user_manager == ("manager", first_session)

    backends_provider = app_config.dependencies[DEFAULT_BACKENDS_DEPENDENCY_KEY]
    assert isinstance(backends_provider, Provide)
    assert backends_provider.use_cache is False
    assert backends_provider.sync_to_thread is False
    assert backends_provider.dependency() == ("primary",)

    permissions_provider = app_config.dependencies[DEFAULT_RESOLVED_PERMISSIONS_DEPENDENCY_KEY]
    assert isinstance(permissions_provider, Provide)
    assert permissions_provider.use_cache is True
    assert permissions_provider.sync_to_thread is False

    current_organization_provider = app_config.dependencies[DEFAULT_CURRENT_ORGANIZATION_DEPENDENCY_KEY]
    assert isinstance(current_organization_provider, Provide)
    assert current_organization_provider.use_cache is True
    assert current_organization_provider.sync_to_thread is False


def test_register_dependencies_adds_oauth_associate_provider_only_when_configured() -> None:
    """OAuth associate DI is registered only when the matching config surface is enabled."""
    absent_app_config = AppConfig()
    absent_config = _minimal_config()

    register_dependencies(absent_app_config, absent_config, providers=_providers())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY not in absent_app_config.dependencies

    present_app_config = AppConfig()
    present_config = _minimal_config()
    present_config.oauth_config = OAuthConfig(
        oauth_providers=[_oauth_provider(name="example", client=object())],
        include_oauth_associate=True,
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )

    register_dependencies(present_app_config, present_config, providers=_providers())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY in present_app_config.dependencies


def test_unknown_dependency_provider_wiring_fails_loudly() -> None:
    """Invalid FeatureWiring dependency names are rejected during dependency resolution."""
    with pytest.raises(RuntimeError, match="unknown_provider"):
        dependencies_module._resolve_dependency_registration(
            "unknown_provider",
            config=_minimal_config(),
            providers=_providers(),
        )


def test_register_dependencies_skips_db_session_provider_and_autocommit_when_external() -> None:
    """External AsyncSession DI disables plugin-owned session and autocommit registration."""
    app_config = AppConfig()
    config = _minimal_config()
    config.db_session_dependency_provided_externally = True

    register_dependencies(app_config, config, providers=_providers())

    assert config.db_session_dependency_key not in app_config.dependencies
    assert app_config.before_send == []


def test_register_dependencies_wraps_sync_providers_without_sync_to_thread() -> None:
    """Non-generator sync providers are registered as explicit non-threaded Provide instances."""
    app_config = AppConfig()
    config = _minimal_config()

    def provide_config() -> str:
        return "config"

    register_dependencies(
        app_config,
        config,
        providers=DependencyProviders(
            config=provide_config,
            user_manager=_providers().user_manager,
            backends=_providers().backends,
            user_model=_providers().user_model,
            oauth_associate_user_manager=_providers().oauth_associate_user_manager,
        ),
    )

    config_provider = app_config.dependencies[DEFAULT_CONFIG_DEPENDENCY_KEY]
    assert isinstance(config_provider, Provide)
    assert config_provider.use_cache is True
    assert config_provider.sync_to_thread is False
    assert config_provider.dependency() == "config"


async def test_resolved_permissions_dependency_injects_authenticated_effective_permissions() -> None:
    """Handlers can inject the authenticated caller's resolved permissions."""
    app, strategy, user = _permissions_app()
    token = await strategy.write_token(user)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/permissions", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == HTTP_OK
    assert response.json() == {"permissions": ["posts:read", "posts:write"]}


async def test_resolved_permissions_dependency_returns_empty_set_for_unauthenticated_request() -> None:
    """Anonymous callers receive an empty resolved-permissions set through DI."""
    app, _strategy, _user = _permissions_app()

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/anonymous-permissions")

    assert response.status_code == HTTP_OK
    assert response.json() == {"permissions": []}


async def test_current_organization_dependency_injects_verified_member_context() -> None:
    """Handlers can inject the authenticated member's verified organization context."""
    user_id = uuid4()
    membership = ExampleOrganizationMembership(organization_id=uuid4(), user_id=user_id, roles=["owner"])
    app, strategy, user, organization, store = _current_organization_app(membership=membership)
    matching_membership = ExampleOrganizationMembership(
        organization_id=organization.id,
        user_id=user.id,
        roles=membership.roles,
    )
    store.membership = matching_membership
    token = await strategy.write_token(user)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/current-organization", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "context": {
            "organization_id": str(organization.id),
            "organization_slug": "acme",
            "membership_user_id": str(user.id),
            "membership_roles": ["owner"],
        },
        "same_as_scope": True,
    }
    assert store.slug_calls == ["acme"]
    assert store.membership_calls == [(organization.id, user.id)]


async def test_current_organization_dependency_returns_none_for_authenticated_non_member() -> None:
    """Authenticated non-members receive no current-organization context through DI."""
    app, strategy, user, organization, store = _current_organization_app(membership=None)
    token = await strategy.write_token(user)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/current-organization", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == HTTP_OK
    assert response.json() == {"context": None, "same_as_scope": True}
    assert store.slug_calls == ["acme"]
    assert store.membership_calls == [(organization.id, user.id)]


async def test_current_organization_dependency_returns_none_for_anonymous_request() -> None:
    """Anonymous callers receive no current-organization context through DI."""
    membership = ExampleOrganizationMembership(organization_id=uuid4(), user_id=uuid4(), roles=["owner"])
    app, _strategy, _user, _organization, store = _current_organization_app(membership=membership)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/anonymous-current-organization")

    assert response.status_code == HTTP_OK
    assert response.json() == {"context": None}
    assert store.slug_calls == []
    assert store.membership_calls == []
