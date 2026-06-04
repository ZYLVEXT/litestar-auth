"""Tests for the Litestar authentication middleware."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Self, cast
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.datastructures.state import State
from litestar.exceptions import ClientException, PermissionDeniedException

from litestar_auth._current_organization import (
    CURRENT_ORGANIZATION_CONTEXT_SENTINEL,
    CurrentOrganizationContext,
    clear_scope_current_organization_context,
    read_scope_current_organization_context,
    set_scope_current_organization_context,
)
from litestar_auth._permissions import (
    PERMISSION_RESOLVER_SENTINEL,
    StaticRolePermissionResolver,
    read_scope_permission_resolver,
)
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session
from litestar_auth._superuser_role import SUPERUSER_ROLE_NAME_SENTINEL
from litestar_auth._tenant_resolution import ClaimTenantResolver
from litestar_auth.authentication.middleware import (
    _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES,
    LitestarAuthMiddleware,
    LitestarAuthMiddlewareConfig,
    _cookie_header_contains_any_cookie_name,
    _request_supplied_auth_credentials,
    _resolve_api_key_failure_reason,
)
from litestar_auth.authentication.middleware import logger as middleware_logger
from litestar_auth.authentication.strategy._api_key_format import digest_api_key_secret
from litestar_auth.authentication.strategy.api_key import (
    ApiKeyContext,
    ApiKeyFailureReason,
    ApiKeyStrategy,
    api_key_failure_reason_to_error_code,
)
from litestar_auth.authentication.strategy.jwt import JWTContext
from litestar_auth.authentication.transport._api_key_signing import (
    API_KEY_SIGNED_BODY_SCOPE_KEY,
    build_canonical_request,
)
from litestar_auth.db import ApiKeyData
from litestar_auth.exceptions import ErrorCode
from tests._helpers import ExampleUser
from tests.integration.test_controller_api_keys import API_KEY_HASH_SECRET, InMemoryApiKeyStore

if TYPE_CHECKING:
    from types import TracebackType

    from litestar.types import HTTPReceiveMessage, HTTPScope, HTTPSendMessage, Receive, Scope, Send

    from litestar_auth.db import MembershipData, OrganizationData

pytestmark = pytest.mark.unit
HTTP_REQUEST_ENTITY_TOO_LARGE = 413


class DummySession:
    """Minimal session object used by middleware tests (mirrors ``AsyncSession`` surface)."""

    async def __aenter__(self) -> Self:
        """Enter async context.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit async context (no-op)."""

    async def close(self) -> None:
        """No-op for lifecycle parity."""

    async def commit(self) -> None:
        """No-op commit for lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for lifecycle parity."""


class DummySessionMaker:
    """Callable session factory returning a dummy session (mirrors ``async_sessionmaker()``)."""

    def __init__(self, session: DummySession) -> None:
        """Store the dummy session and track calls."""
        self.session = session
        self.call_count = 0

    def __call__(self) -> DummySession:
        """Return the dummy session (one logical session per factory call for this test double).

        Returns:
            The shared dummy session.
        """
        self.call_count += 1
        return self.session


class MissingUserManager:
    """User manager fixture that never resolves a user."""

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return no user."""
        return None


class ResolvingUserManager:
    """User manager fixture that resolves one configured user."""

    def __init__(self, user: ExampleUser) -> None:
        """Store the user to return for matching ids."""
        self.user = user

    async def get(self, user_id: UUID) -> ExampleUser | None:
        """Return the configured user when ids match."""
        if user_id == self.user.id:
            return self.user
        return None


@dataclass(frozen=True, slots=True)
class ExampleOrganization:
    """Organization row used by current-organization middleware tests."""

    id: UUID
    slug: str


@dataclass(frozen=True, slots=True)
class ExampleOrganizationMembership:
    """Organization-membership row used by current-organization middleware tests."""

    organization_id: UUID
    user_id: UUID
    roles: list[str]


class RecordingOrganizationStore:
    """Minimal organization store that records middleware lookup calls."""

    def __init__(
        self,
        *,
        organization: object | None,
        membership: ExampleOrganizationMembership | None,
    ) -> None:
        """Store lookup results for one request."""
        self.organization = organization
        self.membership = membership
        self.slug_calls: list[str] = []
        self.membership_calls: list[tuple[UUID, UUID]] = []

    async def get_organization_by_slug(self, slug: str) -> object | None:
        """Return the configured organization and record the slug lookup."""
        self.slug_calls.append(slug)
        await asyncio.sleep(0)
        return self.organization

    async def create_organization(self, data: OrganizationData) -> object:
        """Persist a test organization object.

        Returns:
            The stored organization object.
        """
        self.organization = data
        return self.organization

    async def get_organization(self, organization_id: UUID) -> object | None:
        """Return no organization by id for middleware-only tests."""
        await asyncio.sleep(0)
        return None

    async def update_organization(self, organization_id: UUID, data: OrganizationData) -> object | None:
        """Return no updated organization for middleware-only tests."""
        await asyncio.sleep(0)
        return None

    async def delete_organization(self, organization_id: UUID) -> bool:
        """Return no deleted organization for middleware-only tests.

        Returns:
            ``False`` because these tests never mutate organization state.
        """
        await asyncio.sleep(0)
        return False

    async def add_membership(self, data: MembershipData[UUID]) -> ExampleOrganizationMembership:
        """Persist a test membership.

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
        """Return the configured membership and record the exact lookup."""
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
        """Remove the configured membership for protocol coverage in middleware tests.

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
        """Replace membership roles for protocol coverage in middleware tests.

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
    ) -> tuple[list[object], int]:
        """Return no organizations for middleware-only tests."""
        await asyncio.sleep(0)
        return [], 0


class DummyRouteHandler:
    """Minimal route handler exposing the opt mapping Litestar expects."""

    def __init__(self) -> None:
        """Initialize route options."""
        self.opt: dict[str, object] = {}


def _build_scope() -> HTTPScope:
    """Create a minimal HTTP scope for middleware tests.

    Returns:
        Minimal HTTP scope.
    """
    litestar_app = MagicMock()
    litestar_app.state = State()
    return cast(
        "HTTPScope",
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/protected",
            "raw_path": b"/protected",
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "path_params": {},
            "route_handler": DummyRouteHandler(),
            "litestar_app": litestar_app,
        },
    )


def _build_connection(scope: HTTPScope) -> ASGIConnection[Any, Any, Any, Any]:
    """Create an ASGI connection for the provided scope.

    Args:
        scope: HTTP scope backing the connection.

    Returns:
        Litestar ASGI connection.
    """
    return ASGIConnection(scope)


async def _receive() -> HTTPReceiveMessage:
    """Return an empty ASGI message.

    Returns:
        Empty ASGI message.
    """
    await asyncio.sleep(0)
    return {"type": "http.request", "body": b"", "more_body": False}


class BodyReceive:
    """ASGI receive callable that returns one body message and tracks reads."""

    def __init__(self, body: bytes) -> None:
        """Store the body bytes to return."""
        self.body = body
        self.call_count = 0

    async def __call__(self) -> HTTPReceiveMessage:
        """Return the configured body once, then an empty body."""
        await asyncio.sleep(0)
        self.call_count += 1
        if self.call_count == 1:
            return {"type": "http.request", "body": self.body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}


class EmptyFrameReceive:
    """ASGI receive callable that emits a configured number of empty request frames."""

    def __init__(self, frame_count: int) -> None:
        """Store the number of frames to emit."""
        self.frame_count = frame_count
        self.call_count = 0

    async def __call__(self) -> HTTPReceiveMessage:
        """Return empty request frames until the configured frame count is reached."""
        await asyncio.sleep(0)
        self.call_count += 1
        return {
            "type": "http.request",
            "body": b"",
            "more_body": self.call_count < self.frame_count,
        }


async def _send(_: HTTPSendMessage) -> None:
    """Consume ASGI messages emitted by the wrapped app."""
    await asyncio.sleep(0)


async def _app(scope: Scope, receive: Receive, send: Send) -> None:
    """No-op ASGI app used by the middleware under test."""
    await asyncio.sleep(0)


async def _raising_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Raise from the downstream app after authentication middleware has run.

    Raises:
        RuntimeError: Always raised to exercise middleware cleanup.
    """
    await asyncio.sleep(0)
    msg = "downstream boom"
    raise RuntimeError(msg)


def test_middleware_rejects_config_combined_with_keyword_options() -> None:
    """LitestarAuthMiddleware accepts either a config object or keyword options."""
    session_maker = DummySessionMaker(DummySession())
    authenticator_factory = Mock()

    with pytest.raises(ValueError, match="LitestarAuthMiddlewareConfig or keyword options"):
        LitestarAuthMiddleware[ExampleUser, UUID](
            app=_app,
            config=LitestarAuthMiddlewareConfig[ExampleUser, UUID](
                get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
                authenticator_factory=authenticator_factory,
            ),
            get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
            authenticator_factory=authenticator_factory,
        )


def test_middleware_config_defaults_to_no_api_key_backend() -> None:
    """Direct middleware construction fails closed for signed body buffering by default."""
    config = LitestarAuthMiddlewareConfig[ExampleUser, UUID](
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(),
    )

    assert config.api_key_backend_present is False


async def test_middleware_sets_authenticated_user_in_scope() -> None:
    """Middleware authenticates through the request-local authenticator."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    authenticator_factory = Mock(return_value=authenticator)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] == user
    assert scope["auth"] == "bearer-jwt"
    assert scope["state"][SUPERUSER_ROLE_NAME_SENTINEL] == "superuser"
    assert read_scope_permission_resolver(_build_connection(scope)).resolve(user) == frozenset()
    assert session_maker.call_count == 1
    authenticator_factory.assert_called_once_with(session)
    authenticator.authenticate.assert_awaited_once()
    await_args = authenticator.authenticate.await_args
    assert await_args is not None
    connection = cast("ASGIConnection[Any, Any, Any, Any]", await_args.args[0])
    assert connection.scope is scope


async def test_authenticate_request_reuses_scoped_session_and_returns_resolved_user() -> None:
    """authenticate_request reuses an existing scoped session and returns the resolved user."""
    scope = _build_scope()
    bound_session = DummySession()
    cast("dict[str, Any]", scope)["_aa_connection_state"] = {"_sqlalchemy_db_session": bound_session}
    session_maker = DummySessionMaker(DummySession())
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    authenticator_factory = Mock(return_value=authenticator)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    result = await middleware.authenticate_request(_build_connection(scope))

    assert result.user == user
    assert result.auth == "bearer-jwt"
    assert scope["state"][SUPERUSER_ROLE_NAME_SENTINEL] == "superuser"
    assert read_scope_permission_resolver(_build_connection(scope)).resolve(user) == frozenset()
    assert session_maker.call_count == 0
    authenticator_factory.assert_called_once_with(bound_session)
    authenticator.authenticate.assert_awaited_once()


async def test_authenticate_request_publishes_verified_current_organization_context() -> None:
    """Authenticated members receive a verified current-organization request context."""
    scope = _build_scope()
    session = DummySession()
    user = ExampleUser(id=uuid4())
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleOrganizationMembership(organization_id=organization.id, user_id=user.id, roles=["owner"])
    store = RecordingOrganizationStore(organization=organization, membership=membership)
    tenant_resolver = Mock(return_value="acme")
    store_factory = Mock(return_value=store)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(session)),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )

    result = await middleware.authenticate_request(_build_connection(scope))

    context = read_scope_current_organization_context(_build_connection(scope))
    assert result.user == user
    assert context is not None
    assert context.organization is organization
    assert context.membership is membership
    assert store.slug_calls == ["acme"]
    assert store.membership_calls == [(organization.id, user.id)]
    store_factory.assert_called_once_with(session)
    tenant_resolver.assert_called_once()


async def test_authenticate_request_publishes_claim_resolved_current_organization_context() -> None:
    """Claim-based tenant resolution can read the freshly authenticated JWT context."""
    scope = _build_scope()
    session = DummySession()
    user = ExampleUser(id=uuid4())
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleOrganizationMembership(organization_id=organization.id, user_id=user.id, roles=["owner"])
    store = RecordingOrganizationStore(organization=organization, membership=membership)
    store_factory = Mock(return_value=store)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, JWTContext(organization=" Acme ")))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(session)),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=store_factory,
        tenant_resolver=ClaimTenantResolver(),
    )

    result = await middleware.authenticate_request(_build_connection(scope))

    context = read_scope_current_organization_context(_build_connection(scope))
    assert result.user == user
    assert result.auth == JWTContext(organization=" Acme ")
    assert scope["auth"] == JWTContext(organization=" Acme ")
    assert context is not None
    assert context.organization is organization
    assert context.membership is membership
    assert store.slug_calls == ["acme"]
    assert store.membership_calls == [(organization.id, user.id)]
    store_factory.assert_called_once_with(session)


@pytest.mark.parametrize(
    ("resolved_slug", "organization", "membership"),
    [
        pytest.param(None, None, None, id="no-slug"),
        pytest.param("missing", None, None, id="unknown-organization"),
        pytest.param("acme", ExampleOrganization(id=uuid4(), slug="acme"), None, id="non-member"),
    ],
)
async def test_authenticate_request_publishes_no_current_organization_context_for_unverified_tenants(
    resolved_slug: str | None,
    organization: ExampleOrganization | None,
    membership: ExampleOrganizationMembership | None,
) -> None:
    """Unknown tenants and non-members fail closed without request organization context."""
    scope = _build_scope()
    user = ExampleUser(id=uuid4())
    store = RecordingOrganizationStore(organization=organization, membership=membership)
    tenant_resolver = Mock(return_value=resolved_slug)
    store_factory = Mock(return_value=store)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )

    await middleware.authenticate_request(_build_connection(scope))

    assert read_scope_current_organization_context(_build_connection(scope)) is None
    tenant_resolver.assert_called_once()
    if resolved_slug is None:
        store_factory.assert_not_called()
        assert store.slug_calls == []
    else:
        store_factory.assert_called_once()
        assert store.slug_calls == [resolved_slug]
    if organization is None:
        assert store.membership_calls == []
    else:
        assert store.membership_calls == [(organization.id, user.id)]


async def test_authenticate_request_publishes_no_current_organization_context_without_row_ids() -> None:
    """Organization rows without an id cannot become verified request context."""
    scope = _build_scope()
    user = ExampleUser(id=uuid4())
    store = RecordingOrganizationStore(organization=object(), membership=None)
    tenant_resolver = Mock(return_value="acme")
    store_factory = Mock(return_value=store)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )

    await middleware.authenticate_request(_build_connection(scope))

    assert read_scope_current_organization_context(_build_connection(scope)) is None
    assert store.slug_calls == ["acme"]
    assert store.membership_calls == []


async def test_authenticate_request_skips_current_organization_for_anonymous_requests() -> None:
    """Anonymous requests never receive a current-organization context."""
    scope = _build_scope()
    store = RecordingOrganizationStore(organization=None, membership=None)
    tenant_resolver = Mock(return_value="acme")
    store_factory = Mock(return_value=store)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=store_factory,
        tenant_resolver=tenant_resolver,
    )

    await middleware.authenticate_request(_build_connection(scope))

    assert read_scope_current_organization_context(_build_connection(scope)) is None
    tenant_resolver.assert_not_called()
    store_factory.assert_not_called()


async def test_authenticate_request_skips_current_organization_when_feature_disabled() -> None:
    """Middleware performs no organization work when tenant resolution is not configured."""
    scope = _build_scope()
    user = ExampleUser(id=uuid4())
    tenant_resolver = Mock(return_value="acme")
    store_factory = Mock()
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        organization_store_factory=None,
        tenant_resolver=tenant_resolver,
    )

    await middleware.authenticate_request(_build_connection(scope))

    assert read_scope_current_organization_context(_build_connection(scope)) is None
    tenant_resolver.assert_not_called()
    store_factory.assert_not_called()


async def test_successful_api_key_auth_without_usage_recorder_returns_context() -> None:
    """API-key auth succeeds even when a custom manager has no usage recorder hook."""
    scope = _build_scope()
    bound_session = DummySession()
    cast("dict[str, Any]", scope)["_aa_connection_state"] = {"_sqlalchemy_db_session": bound_session}
    user = ExampleUser(id=uuid4())
    auth_context = ApiKeyContext(key_id="key-id", scopes=("read",), prefix_env="prod")
    authenticator = Mock()
    authenticator.user_manager = object()
    authenticator.authenticate = AsyncMock(return_value=(user, auth_context))
    authenticator_factory = Mock(return_value=authenticator)
    api_key_use_rate_limit = Mock()
    api_key_use_rate_limit.before_request = AsyncMock()
    api_key_use_rate_limit.increment = AsyncMock()
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=authenticator_factory,
        api_key_use_rate_limit=api_key_use_rate_limit,
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] == user
    assert scope["auth"] == auth_context
    api_key_use_rate_limit.before_request.assert_not_called()
    api_key_use_rate_limit.increment.assert_not_called()


async def test_successful_jwt_auth_returns_context() -> None:
    """JWT auth contexts are stored on the request scope like other contextual strategies."""
    scope = _build_scope()
    user = ExampleUser(id=uuid4())
    auth_context = JWTContext(organization="acme")
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, auth_context))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] == user
    assert scope["auth"] == auth_context


async def test_middleware_leaves_unauthenticated_requests_as_none() -> None:
    """Middleware returns ``None`` user/auth instead of raising 401."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        superuser_role_name=" Admin ",
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] is None
    assert scope["auth"] is None
    assert scope["state"][SUPERUSER_ROLE_NAME_SENTINEL] == "admin"
    assert session_maker.call_count == 1
    authenticator.authenticate.assert_awaited_once()


async def test_middleware_sets_configured_permission_resolver_in_scope() -> None:
    """Middleware publishes the configured permission resolver on request scope state."""
    scope = _build_scope()
    user = ExampleUser(id=uuid4(), roles=["admin"])
    resolver = StaticRolePermissionResolver({"admin": ("posts:read",)})
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(return_value=authenticator),
        permission_resolver=resolver,
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["state"][PERMISSION_RESOLVER_SENTINEL] is resolver
    assert read_scope_permission_resolver(_build_connection(scope)).resolve(user) == frozenset({"posts:read"})


def test_read_scope_permission_resolver_falls_back_to_safe_default() -> None:
    """Guard-side resolver reads fail closed outside plugin-managed requests."""
    user = ExampleUser(id=uuid4(), roles=["admin"])
    connection = cast(
        "ASGIConnection[Any, Any, Any, Any]",
        MagicMock(scope={"state": object()}),
    )

    assert read_scope_permission_resolver(_build_connection(_build_scope())).resolve(user) == frozenset()
    assert read_scope_permission_resolver(connection).resolve(user) == frozenset()


def test_read_scope_permission_resolver_rejects_invalid_scope_value() -> None:
    """Malformed plugin-owned resolver state fails closed."""
    scope = _build_scope()
    scope["state"] = {PERMISSION_RESOLVER_SENTINEL: object()}

    with pytest.raises(PermissionDeniedException, match="permission resolver is invalid"):
        read_scope_permission_resolver(_build_connection(scope))


def test_current_organization_scope_helpers_read_verified_context_or_none() -> None:
    """Current-organization helper reads only verified request-scope context objects."""
    scope = _build_scope()
    organization = ExampleOrganization(id=uuid4(), slug="acme")
    membership = ExampleOrganizationMembership(organization_id=organization.id, user_id=uuid4(), roles=["owner"])
    context = CurrentOrganizationContext(organization=organization, membership=membership)

    assert read_scope_current_organization_context(_build_connection(scope)) is None

    set_scope_current_organization_context(scope, context)
    assert read_scope_current_organization_context(_build_connection(scope)) is context

    scope["state"][CURRENT_ORGANIZATION_CONTEXT_SENTINEL] = object()
    assert read_scope_current_organization_context(_build_connection(scope)) is None

    clear_scope_current_organization_context(scope)
    assert read_scope_current_organization_context(_build_connection(scope)) is None


def test_current_organization_scope_helpers_ignore_non_mapping_state() -> None:
    """Malformed scope state is treated as absent organization context."""
    scope = _build_scope()
    scope["state"] = cast("Any", object())
    connection = cast("ASGIConnection[Any, Any, Any, Any]", MagicMock(scope=scope))

    clear_scope_current_organization_context(scope)

    assert read_scope_current_organization_context(connection) is None


async def test_middleware_buffers_body_for_api_key_backend_when_any_authorization_header_is_signed() -> None:
    """Duplicate Authorization headers trigger API-key buffering when any value is a signed request."""
    scope = _build_scope()
    body = b'{"signed": true}'
    receive = BodyReceive(body)
    scope["headers"] = [
        (b"authorization", b"LSA1-HMAC-SHA256 keyid=test,signedheaders=host,signature=abc"),
        (b"authorization", b"Bearer token"),
        (b"host", b"example.test"),
    ]
    session_maker = DummySessionMaker(DummySession())
    authenticator = Mock()

    async def authenticate(connection: ASGIConnection[Any, Any, Any, Any]) -> tuple[None, None]:
        await asyncio.sleep(0)
        canonical_request = build_canonical_request(connection, signed_headers=("host",))
        assert canonical_request.endswith(hashlib.sha256(body).hexdigest())
        return None, None

    authenticator.authenticate = AsyncMock(side_effect=authenticate)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        api_key_backend_present=True,
    )

    await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == 1
    assert API_KEY_SIGNED_BODY_SCOPE_KEY not in scope


async def test_middleware_clears_signed_body_when_downstream_raises() -> None:
    """Signed-body scope storage is bounded by the middleware frame on downstream errors."""
    scope = _build_scope()
    receive = BodyReceive(b'{"signed": true}')
    scope["headers"] = [(b"authorization", b"LSA1-HMAC-SHA256 keyid=test,signedheaders=host,signature=abc")]
    session_maker = DummySessionMaker(DummySession())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_raising_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        api_key_backend_present=True,
    )

    with pytest.raises(RuntimeError, match="downstream boom"):
        await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == 1
    assert API_KEY_SIGNED_BODY_SCOPE_KEY not in scope


async def test_middleware_does_not_buffer_signed_body_without_api_key_backend() -> None:
    """Signed Authorization headers are ignored when no API-key backend is configured."""
    scope = _build_scope()
    receive = BodyReceive(b"unread")
    scope["headers"] = [(b"authorization", b"LSA1-HMAC-SHA256 keyid=test,signedheaders=host,signature=abc")]
    session_maker = DummySessionMaker(DummySession())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        api_key_backend_present=False,
    )

    await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == 0
    assert API_KEY_SIGNED_BODY_SCOPE_KEY not in scope


async def test_middleware_allows_signed_body_at_configured_message_limit() -> None:
    """Signed-body buffering accepts empty frame streams at the configured message limit."""
    scope = _build_scope()
    max_messages = _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
    receive = EmptyFrameReceive(max_messages)
    scope["headers"] = [(b"authorization", b"LSA1-HMAC-SHA256 keyid=test,signedheaders=host,signature=abc")]
    session_maker = DummySessionMaker(DummySession())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        api_key_backend_present=True,
        api_key_signed_body_max_messages=max_messages,
    )

    await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == max_messages
    assert API_KEY_SIGNED_BODY_SCOPE_KEY not in scope


async def test_middleware_rejects_signed_body_over_configured_message_limit() -> None:
    """Signed-body buffering fails closed before unbounded pre-auth frame accumulation."""
    scope = _build_scope()
    max_messages = _DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
    receive = EmptyFrameReceive(max_messages + 1)
    scope["headers"] = [(b"authorization", b"LSA1-HMAC-SHA256 keyid=test,signedheaders=host,signature=abc")]
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(
            get_or_create_scoped_session,
            session_maker=cast("Any", DummySessionMaker(DummySession())),
        ),
        authenticator_factory=Mock(),
        api_key_backend_present=True,
        api_key_signed_body_max_messages=max_messages,
    )

    with pytest.raises(ClientException) as exc_info:
        await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == max_messages + 1
    assert exc_info.value.status_code == HTTP_REQUEST_ENTITY_TOO_LARGE
    assert exc_info.value.extra == {"code": ErrorCode.REQUEST_BODY_INVALID}


async def test_middleware_does_not_buffer_body_for_single_non_signed_authorization_header() -> None:
    """Non-signed Authorization headers keep the request body untouched."""
    scope = _build_scope()
    receive = BodyReceive(b"unread")
    scope["headers"] = [(b"authorization", b"Bearer token")]
    session_maker = DummySessionMaker(DummySession())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        api_key_backend_present=True,
    )

    await middleware(scope, cast("Receive", receive), cast("Send", _send))

    assert receive.call_count == 0
    assert API_KEY_SIGNED_BODY_SCOPE_KEY not in scope


async def test_authenticate_request_propagates_authenticator_factory_errors() -> None:
    """authenticate_request propagates factory failures without swallowing them."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    expected = RuntimeError("factory boom")
    authenticator_factory = Mock(side_effect=expected)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    with pytest.raises(RuntimeError, match="factory boom"):
        await middleware.authenticate_request(_build_connection(scope))

    assert session_maker.call_count == 1
    authenticator_factory.assert_called_once_with(session)


async def test_middleware_logs_failed_token_validation_when_credentials_present(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requests carrying credentials but resolving no user are logged as token failures."""
    scope = _build_scope()
    leaked_credential_marker = "leaked-bearer-credential-marker"
    scope["headers"] = [(b"authorization", f"Bearer {leaked_credential_marker}".encode())]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["token_validation_failed"]
    aggregated = "".join(record.getMessage() for record in caplog.records)
    assert leaked_credential_marker not in aggregated


async def test_authenticate_request_does_not_log_failed_token_validation_when_user_resolves(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Resolved users suppress token failure logging even when credentials are present."""
    scope = _build_scope()
    scope["headers"] = [(b"authorization", b"Bearer valid-token")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        result = await middleware.authenticate_request(_build_connection(scope))

    assert result.user == user
    assert result.auth == "bearer-jwt"
    assert not caplog.records


async def test_middleware_does_not_log_failed_token_validation_for_unrelated_cookies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Cookies unrelated to auth do not trigger token validation failure logging."""
    scope = _build_scope()
    scope["headers"] = [(b"cookie", b"sessionid=abc123")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == []


async def test_middleware_logs_failed_token_validation_for_configured_auth_cookies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requests carrying configured auth cookies but resolving no user are logged as token failures."""
    scope = _build_scope()
    leaked_cookie_marker = b"leaked-cookie-credential-marker"
    scope["headers"] = [(b"cookie", b"litestar_auth=" + leaked_cookie_marker)]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["token_validation_failed"]
    leaked_cookie_text = leaked_cookie_marker.decode()
    aggregated = "".join(record.getMessage() for record in caplog.records)
    assert leaked_cookie_text not in aggregated


async def test_api_key_failure_reason_helper_handles_active_valid_secret_branch() -> None:
    """The API-key failure helper keeps active valid rows mapped to the generic invalid code."""
    store = InMemoryApiKeyStore()
    key_id = "valid-branch"
    secret = "secret"
    await store.create(
        ApiKeyData(
            key_id=key_id,
            user_id=uuid4(),
            hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
            encrypted_secret=None,
            name="Valid",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            expires_at=None,
            created_via="test",
        ),
    )
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=store,
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        unsafe_testing=True,
    )

    reason = await _resolve_api_key_failure_reason(
        f"ak_prod_{key_id}.{secret}",
        strategy,
        user_manager=MissingUserManager(),
    )

    assert reason == ApiKeyFailureReason.INVALID
    assert api_key_failure_reason_to_error_code(reason) == ErrorCode.API_KEY_INVALID


async def test_api_key_failure_reason_helper_falls_back_when_attempt_succeeds() -> None:
    """The middleware helper still returns a failure reason if invoked for a valid token."""
    store = InMemoryApiKeyStore()
    user = ExampleUser(id=uuid4())
    key_id = "valid-user-branch"
    secret = "secret"
    await store.create(
        ApiKeyData(
            key_id=key_id,
            user_id=user.id,
            hashed_secret=digest_api_key_secret(api_key_hash_secret=API_KEY_HASH_SECRET.encode(), secret=secret),
            encrypted_secret=None,
            name="Valid",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            expires_at=None,
            created_via="test",
        ),
    )
    strategy = ApiKeyStrategy[ExampleUser, UUID](
        api_key_store=store,
        api_key_hash_secret=API_KEY_HASH_SECRET,
        prefix_env="prod",
        unsafe_testing=True,
    )

    reason = await _resolve_api_key_failure_reason(
        f"ak_prod_{key_id}.{secret}",
        strategy,
        user_manager=ResolvingUserManager(user),
    )

    assert reason == ApiKeyFailureReason.INVALID


def test_request_supplied_auth_credentials_detects_bearer_header() -> None:
    """Authorization headers count as supplied auth credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"authorization", b"Bearer token")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth"}),
    )

    assert has_credentials is True


def test_request_supplied_auth_credentials_detects_api_key_header() -> None:
    """The API-key header counts as supplied auth credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"x-api-key", b"ak_prod_key.secret")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth"}),
    )

    assert has_credentials is True


def test_request_supplied_auth_credentials_detects_configured_auth_cookie() -> None:
    """Configured auth cookies count as supplied auth credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"cookie", b"other=value; litestar_auth=token; another=1")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    assert has_credentials is True


def test_request_supplied_auth_credentials_returns_false_without_matching_headers() -> None:
    """Missing auth headers and unrelated cookies do not count as supplied credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"x-test", b"value"), (b"cookie", b"sessionid=abc123")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth"}),
    )

    assert has_credentials is False


def test_cookie_header_contains_any_cookie_name_strips_whitespace() -> None:
    """Cookie-name matching tolerates header whitespace and multiple cookie pairs."""
    assert _cookie_header_contains_any_cookie_name(
        b"sessionid=abc123; litestar_auth_refresh=token; theme=dark",
        frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )
    assert not _cookie_header_contains_any_cookie_name(
        b"sessionid=abc123; theme=dark",
        frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )
