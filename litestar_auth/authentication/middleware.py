"""Litestar adapter for the principal-neutral authentication pipeline."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NotRequired, Required, TypedDict, Unpack, overload, override

import anyio
from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationCoordinator,
    AuthenticationRuntime,
    Invalid,
    InvariantFailure,
    NotApplicable,
    RequestAuthenticationProvider,
    RequestView,
    RouteProviderPolicy,
    TlsPeerEvidence,
    Unavailable,
)
from litestar.datastructures.state import State
from litestar.exceptions import ClientException, InternalServerException, NotAuthorizedException
from litestar.middleware.authentication import AbstractAuthenticationMiddleware, AuthenticationResult
from litestar.types import ASGIApp, Method, Scope, Scopes

from litestar_auth._current_organization import (
    CurrentOrganizationContext,
    clear_scope_current_organization_context,
    set_scope_current_organization_context,
)
from litestar_auth._permissions import DEFAULT_PERMISSION_RESOLVER, set_scope_permission_resolver
from litestar_auth._superuser_role import (
    DEFAULT_SUPERUSER_ROLE_NAME,
    normalize_superuser_role_name,
    set_scope_superuser_role_name,
)
from litestar_auth.types import PermissionResolver, UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._tenant_resolution import TenantResolver
    from litestar_auth.db import BaseOrganizationStore
else:  # pragma: no cover - optional dependency - import-time fallback
    AsyncSession = Any

AUTHENTICATION_PROVIDERS_KEY = "authentication_providers"
type PrincipalLoader = Callable[[AuthenticationContext], object | Awaitable[object]]
type TlsPeerEvidenceFactory = Callable[[Scope], TlsPeerEvidence | None]
type CorrelationIdFactory = Callable[[Scope], str | None]
type RequestSessionProvider = Callable[[State, Scope], AsyncSession]
type OrganizationStoreFactory = Callable[[AsyncSession], BaseOrganizationStore[Any, Any, Any, Any]]


@dataclass(frozen=True, slots=True)
class LitestarProviderBinding:
    """Bind a neutral provider to its Litestar request-user projection."""

    provider: RequestAuthenticationProvider
    load_principal: PrincipalLoader


type ProviderBindingsFactory = Callable[[AsyncSession], Sequence[LitestarProviderBinding]]


@dataclass(frozen=True, slots=True)
class LitestarAuthMiddlewareConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :class:`LitestarAuthMiddleware`."""

    get_request_session: RequestSessionProvider
    provider_bindings_factory: ProviderBindingsFactory
    default_policy: RouteProviderPolicy
    authentication_deadline_seconds: float | None = None
    tls_peer_evidence_factory: TlsPeerEvidenceFactory | None = None
    correlation_id_factory: CorrelationIdFactory | None = None
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME
    permission_resolver: PermissionResolver = DEFAULT_PERMISSION_RESOLVER
    organization_store_factory: OrganizationStoreFactory | None = None
    tenant_resolver: TenantResolver | None = None
    exclude: str | list[str] | None = None
    exclude_from_auth_key: str = "exclude_from_auth"
    exclude_http_methods: Sequence[Method] | None = None
    scopes: Scopes | None = None

    def __post_init__(self) -> None:
        """Validate middleware execution limits.

        Raises:
            ValueError: If the authentication deadline is not positive.
        """
        if self.authentication_deadline_seconds is not None and self.authentication_deadline_seconds <= 0:
            msg = "authentication_deadline_seconds must be positive"
            raise ValueError(msg)


class LitestarAuthMiddlewareOptions[UP: UserProtocol[Any], ID](TypedDict):
    """Keyword options accepted by :class:`LitestarAuthMiddleware`."""

    get_request_session: Required[RequestSessionProvider]
    provider_bindings_factory: Required[ProviderBindingsFactory]
    default_policy: Required[RouteProviderPolicy]
    authentication_deadline_seconds: NotRequired[float | None]
    tls_peer_evidence_factory: NotRequired[TlsPeerEvidenceFactory | None]
    correlation_id_factory: NotRequired[CorrelationIdFactory | None]
    superuser_role_name: NotRequired[str]
    permission_resolver: NotRequired[PermissionResolver]
    organization_store_factory: NotRequired[OrganizationStoreFactory | None]
    tenant_resolver: NotRequired[TenantResolver | None]
    exclude: NotRequired[str | list[str] | None]
    exclude_from_auth_key: NotRequired[str]
    exclude_http_methods: NotRequired[Sequence[Method] | None]
    scopes: NotRequired[Scopes | None]


class LitestarAuthMiddleware[UP: UserProtocol[Any], ID](AbstractAuthenticationMiddleware):
    """Run one principal-neutral authentication pipeline for every route."""

    @overload
    def __init__(self, app: ASGIApp, *, config: LitestarAuthMiddlewareConfig[UP, ID]) -> None: ...

    @overload
    def __init__(
        self,
        app: ASGIApp,
        **options: Unpack[LitestarAuthMiddlewareOptions[UP, ID]],
    ) -> None: ...

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: LitestarAuthMiddlewareConfig[UP, ID] | None = None,
        **options: Unpack[LitestarAuthMiddlewareOptions[UP, ID]],
    ) -> None:
        """Initialize the middleware.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
        """
        if config is not None and options:
            msg = "Pass either LitestarAuthMiddlewareConfig or keyword options, not both."
            raise ValueError(msg)
        settings = LitestarAuthMiddlewareConfig(**options) if config is None else config
        super().__init__(
            app=app,
            exclude=settings.exclude,
            exclude_from_auth_key=settings.exclude_from_auth_key,
            exclude_http_methods=settings.exclude_http_methods,
            scopes=settings.scopes,
        )
        self.get_request_session = settings.get_request_session
        self.provider_bindings_factory = settings.provider_bindings_factory
        self.default_policy = settings.default_policy
        self.authentication_deadline_seconds = settings.authentication_deadline_seconds
        self.tls_peer_evidence_factory = settings.tls_peer_evidence_factory
        self.correlation_id_factory = settings.correlation_id_factory
        self.superuser_role_name = normalize_superuser_role_name(settings.superuser_role_name)
        self.permission_resolver = settings.permission_resolver
        self.organization_store_factory = settings.organization_store_factory
        self.tenant_resolver = settings.tenant_resolver

    @override
    async def authenticate_request(
        self,
        connection: ASGIConnection[Any, Any, Any, Any],
    ) -> AuthenticationResult:
        """Authenticate the request and project the verified principal into Litestar.

        Returns:
            Litestar authentication result for an anonymous or authenticated request.

        Raises:
            NotAuthorizedException: If an owned credential is invalid.
            ClientException: If credential verification is temporarily unavailable.
            InternalServerException: If provider configuration violates an invariant.
        """
        set_scope_superuser_role_name(connection.scope, self)
        set_scope_permission_resolver(connection.scope, self.permission_resolver)
        session = self.get_request_session(connection.app.state, connection.scope)
        bindings = tuple(self.provider_bindings_factory(session))
        coordinator = AuthenticationCoordinator(binding.provider for binding in bindings)
        policy = _resolve_route_policy(connection, default=self.default_policy)
        runtime = AuthenticationRuntime(
            deadline=(
                None
                if self.authentication_deadline_seconds is None
                else _current_async_time() + self.authentication_deadline_seconds
            ),
        )
        tls_peer = None if self.tls_peer_evidence_factory is None else self.tls_peer_evidence_factory(connection.scope)
        correlation_id = None if self.correlation_id_factory is None else self.correlation_id_factory(connection.scope)
        decision = await coordinator.authenticate(
            _request_view(connection.scope, tls_peer=tls_peer, correlation_id=correlation_id),
            runtime,
            policy,
        )

        if isinstance(decision, NotApplicable):
            clear_scope_current_organization_context(connection.scope)
            return AuthenticationResult(user=None, auth=None)
        if isinstance(decision, Invalid):
            raise NotAuthorizedException(
                detail="Authentication credentials are invalid.",
                extra={"code": decision.code.value},
            )
        if isinstance(decision, Unavailable):
            raise ClientException(
                status_code=503,
                detail="Authentication service is unavailable.",
                extra={"code": decision.code.value},
            )
        if isinstance(decision, InvariantFailure):
            raise InternalServerException(
                detail="Authentication configuration is invalid.",
                extra={"code": decision.code.value},
            )
        if not isinstance(decision, Authenticated):
            raise InternalServerException(detail="Authentication provider returned an invalid decision.")

        binding = _binding_for_authenticated_provider(bindings, decision.context)
        principal = binding.load_principal(decision.context)
        if inspect.isawaitable(principal):
            principal = await principal
        if principal is None:
            raise InternalServerException(detail="Authentication principal projection failed.")

        if decision.context.subject.kind == "human":
            await _publish_current_organization_context_if_applicable(
                connection,
                session=session,
                user=principal,
                organization_store_factory=self.organization_store_factory,
                tenant_resolver=self.tenant_resolver,
            )
        else:
            clear_scope_current_organization_context(connection.scope)
        return AuthenticationResult(user=principal, auth=decision.context)


def route_provider_policy(*providers: str) -> dict[str, RouteProviderPolicy]:
    """Build Litestar ``opt`` metadata for a route or application segment.

    Returns:
        Metadata mapping accepted by Litestar route handlers, controllers, routers, and apps.
    """
    return {AUTHENTICATION_PROVIDERS_KEY: RouteProviderPolicy(providers)}


def _resolve_route_policy(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    default: RouteProviderPolicy,
) -> RouteProviderPolicy:
    value = connection.route_handler.opt.get(AUTHENTICATION_PROVIDERS_KEY, default)
    if isinstance(value, RouteProviderPolicy):
        return value
    raise InternalServerException(detail="Route authentication policy is invalid.")


def _request_view(
    scope: Scope,
    *,
    tls_peer: TlsPeerEvidence | None = None,
    correlation_id: str | None = None,
) -> RequestView:
    method = scope.get("method")
    return RequestView(
        method=method if isinstance(method, str) else "GET",
        headers=tuple(scope.get("headers", ())),
        scheme=scope.get("scheme"),
        tls_peer=tls_peer,
        correlation_id=correlation_id,
    )


def _current_async_time() -> float:
    return anyio.current_time()


def _binding_for_authenticated_provider(
    bindings: Sequence[LitestarProviderBinding],
    context: AuthenticationContext,
) -> LitestarProviderBinding:
    matches = tuple(binding for binding in bindings if binding.provider.name == context.evidence.provider)
    if len(matches) != 1:
        raise InternalServerException(detail="Authenticated provider binding is missing or ambiguous.")
    return matches[0]


async def _publish_current_organization_context_if_applicable(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    session: AsyncSession,
    user: object,
    organization_store_factory: OrganizationStoreFactory | None,
    tenant_resolver: TenantResolver | None,
) -> None:
    """Publish verified organization membership for one authenticated human request."""
    clear_scope_current_organization_context(connection.scope)
    if organization_store_factory is None or tenant_resolver is None:
        return

    slug = tenant_resolver(connection)
    if slug is None:
        return

    store = organization_store_factory(session)
    organization = await store.get_organization_by_slug(slug)
    if organization is None:
        return

    organization_id = getattr(organization, "id", None)
    user_id = getattr(user, "id", None)
    if organization_id is None or user_id is None:
        return

    membership = await store.get_membership(organization_id=organization_id, user_id=user_id)
    if membership is None:
        return

    set_scope_current_organization_context(
        connection.scope,
        CurrentOrganizationContext(organization=organization, membership=membership),
    )
