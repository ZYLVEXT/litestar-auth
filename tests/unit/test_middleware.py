"""Tests for the Litestar principal-neutral authentication adapter."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import anyio.lowlevel
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationEvidence,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    NotApplicable,
    PrincipalRef,
    RequestView,
    RouteProviderPolicy,
    Unavailable,
)
from litestar.connection import ASGIConnection
from litestar.datastructures.state import State
from litestar.exceptions import ClientException, InternalServerException, NotAuthorizedException

from litestar_auth.authentication.middleware import (
    AUTHENTICATION_PROVIDERS_KEY,
    LitestarAuthMiddleware,
    LitestarAuthMiddlewareConfig,
    LitestarProviderBinding,
    _binding_for_authenticated_provider,
    route_provider_policy,
)
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from collections.abc import Mapping

pytestmark = pytest.mark.unit
SERVICE_UNAVAILABLE = 503


class _Provider:
    """Return one configured neutral decision."""

    name = "test_provider"
    profile = "test_profile"

    def __init__(self, decision: object, *, match: CredentialMatch = CredentialMatch.OWNED) -> None:
        """Store the decision and matcher result."""
        self.decision = decision
        self.match_result = match
        self.request: RequestView | None = None
        self.runtime: AuthenticationRuntime | None = None

    def match(self, request: RequestView) -> CredentialMatch:
        """Return configured credential ownership.

        Returns:
            Configured matcher result.
        """
        self.request = request
        return self.match_result

    async def authenticate(self, request: RequestView, runtime: AuthenticationRuntime) -> object:
        """Return configured decision.

        Returns:
            Configured authentication decision.
        """
        self.request = request
        self.runtime = runtime
        return self.decision


class _Store:
    """Organization store double."""

    def __init__(self, organization: object | None, membership: object | None) -> None:
        """Store lookup results."""
        self.organization = organization
        self.membership = membership
        self.membership_args: tuple[object, object] | None = None

    async def get_organization_by_slug(self, slug: str) -> object | None:
        """Return configured organization.

        Returns:
            Configured organization.
        """
        assert slug == "tenant"
        return self.organization

    async def get_membership(self, *, organization_id: object, user_id: object) -> object | None:
        """Return configured membership.

        Returns:
            Configured membership.
        """
        self.membership_args = (organization_id, user_id)
        return self.membership


def _context(*, kind: str = "human", provider: str = "test_provider") -> AuthenticationContext:
    """Build a valid neutral context.

    Returns:
        Authentication context for tests.
    """
    principal = PrincipalRef(issuer="https://issuer.example", subject="subject", kind=kind)
    return AuthenticationContext(
        subject=principal,
        actor=principal,
        evidence=AuthenticationEvidence(
            provider=provider,
            profile="test_profile",
            method="test_method",
            issuer=principal.issuer,
        ),
    )


def _connection(
    *,
    opt: Mapping[str, object] | None = None,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    """Build a routed Litestar connection.

    Returns:
        Minimal ASGI connection accepted by the middleware.
    """
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/resource",
        "path_params": {},
        "query_string": b"",
        "scheme": "https",
        "headers": headers or [],
        "litestar_app": SimpleNamespace(state=State()),
        "route_handler": SimpleNamespace(opt=opt or {}),
    }
    return ASGIConnection(scope=cast("Any", scope))


async def _app(scope: object, receive: object, send: object) -> None:
    """No-op ASGI application."""


def _middleware(  # ruff: ignore[too-many-arguments]
    provider: _Provider,
    *,
    loader: object,
    organization_store_factory: object | None = None,
    tenant_resolver: object | None = None,
    deadline: float | None = None,
    correlation_id_factory: object | None = None,
) -> LitestarAuthMiddleware[ExampleUser, object]:
    """Build middleware with one request-scoped provider.

    Returns:
        Middleware under test.
    """
    binding = LitestarProviderBinding(
        provider=cast("Any", provider),
        load_principal=cast("Any", loader),
    )
    return LitestarAuthMiddleware[ExampleUser, object](
        cast("Any", _app),
        get_request_session=cast("Any", lambda _state, _scope: object()),
        provider_bindings_factory=lambda _session: (binding,),
        default_policy=RouteProviderPolicy((provider.name,)),
        authentication_deadline_seconds=deadline,
        correlation_id_factory=cast("Any", correlation_id_factory),
        organization_store_factory=cast("Any", organization_store_factory),
        tenant_resolver=cast("Any", tenant_resolver),
    )


@pytest.mark.parametrize("deadline", [0, -1.0])
def test_config_rejects_nonpositive_deadline(deadline: float) -> None:
    """Provider deadline must be positive when configured."""
    with pytest.raises(ValueError, match="positive"):
        LitestarAuthMiddlewareConfig(
            get_request_session=cast("Any", lambda _state, _scope: object()),
            provider_bindings_factory=lambda _session: (),
            default_policy=RouteProviderPolicy(),
            authentication_deadline_seconds=deadline,
        )


def test_middleware_rejects_config_mixed_with_options() -> None:
    """Construction accepts either a config object or keyword options."""
    config = LitestarAuthMiddlewareConfig(
        get_request_session=cast("Any", lambda _state, _scope: object()),
        provider_bindings_factory=lambda _session: (),
        default_policy=RouteProviderPolicy(),
    )
    with pytest.raises(ValueError, match="either"):
        LitestarAuthMiddleware(
            cast("Any", _app),
            config=config,
            get_request_session=cast("Any", lambda _state, _scope: object()),
            provider_bindings_factory=lambda _session: (),
            default_policy=RouteProviderPolicy(),
        )


def test_route_provider_policy_builds_layerable_litestar_metadata() -> None:
    """Public helper emits the documented route opt value."""
    assert route_provider_policy("one") == {
        AUTHENTICATION_PROVIDERS_KEY: RouteProviderPolicy(("one",)),
    }
    with pytest.raises(ValueError, match="at most one"):
        route_provider_policy("one", "two")


async def test_not_applicable_request_remains_anonymous_and_preserves_raw_headers() -> None:
    """Absent credentials remain anonymous after duplicate-preserving projection."""
    provider = _Provider(NotApplicable(), match=CredentialMatch.NOT_APPLICABLE)
    middleware = _middleware(provider, loader=lambda _context: object())
    connection = _connection(headers=[(b"x-test", b"one"), (b"x-test", b"two")])

    result = await middleware.authenticate_request(connection)

    assert result.user is None
    assert result.auth is None
    assert provider.request is not None
    assert provider.request.correlation_id is None
    assert provider.request.method == "POST"
    assert provider.request.scheme == "https"
    assert provider.request.header_values(b"x-test") == (b"one", b"two")


async def test_middleware_projects_application_correlation_id() -> None:
    """Only the configured trusted scope projection supplies correlation metadata."""
    provider = _Provider(NotApplicable(), match=CredentialMatch.NOT_APPLICABLE)
    middleware = _middleware(
        provider,
        loader=lambda _context: object(),
        correlation_id_factory=lambda _scope: "trace-123",
    )

    await middleware.authenticate_request(_connection())

    assert provider.request is not None
    assert provider.request.correlation_id == "trace-123"


async def test_route_policy_overrides_application_default() -> None:
    """Nearest Litestar route opt policy controls allowed providers."""
    provider = _Provider(NotApplicable(), match=CredentialMatch.NOT_APPLICABLE)
    middleware = _middleware(provider, loader=lambda _context: object())
    connection = _connection(opt=route_provider_policy())

    result = await middleware.authenticate_request(connection)

    assert result.user is None
    assert provider.request is None


async def test_invalid_route_policy_fails_closed() -> None:
    """Malformed route metadata is a server configuration failure."""
    middleware = _middleware(_Provider(NotApplicable()), loader=lambda _context: object())

    with pytest.raises(InternalServerException, match="policy"):
        await middleware.authenticate_request(
            _connection(opt={AUTHENTICATION_PROVIDERS_KEY: ("test_provider",)}),
        )


async def test_invalid_credential_maps_to_safe_401() -> None:
    """Owned invalid credentials map to a generic 401 with stable code."""
    middleware = _middleware(
        _Provider(Invalid(FailureCode.REVOKED)),
        loader=lambda _context: object(),
    )

    with pytest.raises(NotAuthorizedException) as exc_info:
        await middleware.authenticate_request(_connection())

    assert exc_info.value.detail == "Authentication credentials are invalid."
    assert exc_info.value.extra == {"code": "revoked"}


async def test_unavailable_provider_maps_to_safe_503() -> None:
    """Unavailable verification is terminal and maps to 503."""
    middleware = _middleware(_Provider(Unavailable()), loader=lambda _context: object())

    with pytest.raises(ClientException) as exc_info:
        await middleware.authenticate_request(_connection())

    assert exc_info.value.status_code == SERVICE_UNAVAILABLE
    assert exc_info.value.extra == {"code": "provider_unavailable"}


async def test_provider_returning_unknown_decision_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider decisions outside the typed contract are configuration failures."""
    middleware = _middleware(_Provider(object()), loader=lambda _context: object())

    async def return_invalid_decision(*_args: object, **_kwargs: object) -> object:
        await anyio.lowlevel.checkpoint()
        return object()

    monkeypatch.setattr(
        "litestar_auth.authentication.middleware.AuthenticationCoordinator.authenticate",
        return_invalid_decision,
    )

    with pytest.raises(InternalServerException, match="invalid decision"):
        await middleware.authenticate_request(_connection())


async def test_unknown_provider_in_policy_maps_to_invariant_failure() -> None:
    """Unknown route provider cannot silently become anonymous."""
    middleware = _middleware(_Provider(NotApplicable()), loader=lambda _context: object())

    with pytest.raises(InternalServerException, match="configuration"):
        await middleware.authenticate_request(
            _connection(opt=route_provider_policy("missing_provider")),
        )


async def test_human_authentication_projects_user_and_context() -> None:
    """Human authentication keeps the bounded user model in request.user."""
    user = ExampleUser(id=uuid4())
    context = _context()
    provider = _Provider(Authenticated(context))
    middleware = _middleware(provider, loader=lambda _loaded_context: user, deadline=1.0)

    result = await middleware.authenticate_request(_connection())

    assert result.user is user
    assert result.auth is context
    assert provider.runtime is not None
    assert provider.runtime.deadline is not None


async def test_async_machine_projection_skips_human_postprocessing() -> None:
    """Machine providers may project a framework object asynchronously."""
    principal = object()
    context = _context(kind="service")

    async def load_principal(loaded_context: AuthenticationContext) -> object:
        await anyio.lowlevel.checkpoint()
        assert loaded_context is context
        return principal

    middleware = _middleware(_Provider(Authenticated(context)), loader=load_principal)

    result = await middleware.authenticate_request(_connection())

    assert result.user is principal
    assert result.auth is context


async def test_missing_principal_projection_fails_closed() -> None:
    """A successful provider must project exactly one framework principal."""
    middleware = _middleware(
        _Provider(Authenticated(_context())),
        loader=lambda _context: None,
    )

    with pytest.raises(InternalServerException, match="projection"):
        await middleware.authenticate_request(_connection())


def test_binding_lookup_rejects_missing_or_duplicate_provider() -> None:
    """Post-processing cannot guess an authenticated provider binding."""
    context = _context()
    provider = _Provider(Authenticated(context))
    binding = LitestarProviderBinding(provider=cast("Any", provider), load_principal=lambda _loaded: object())

    with pytest.raises(InternalServerException, match="missing or ambiguous"):
        _binding_for_authenticated_provider((), context)
    with pytest.raises(InternalServerException, match="missing or ambiguous"):
        _binding_for_authenticated_provider((binding, binding), context)


@pytest.mark.parametrize(
    ("organization", "membership", "user_has_id"),
    [
        (None, object(), True),
        (SimpleNamespace(id=None), object(), True),
        (SimpleNamespace(id="org"), object(), False),
        (SimpleNamespace(id="org"), None, True),
    ],
)
async def test_human_organization_postprocessing_stops_on_unverified_state(
    organization: object | None,
    membership: object | None,
    *,
    user_has_id: bool,
) -> None:
    """Only a verified organization membership reaches request context."""
    store = _Store(organization, membership)
    user = ExampleUser(id=uuid4()) if user_has_id else object()
    middleware = _middleware(
        _Provider(Authenticated(_context())),
        loader=lambda _context: user,
        organization_store_factory=lambda _session: store,
        tenant_resolver=lambda _connection: "tenant",
    )
    connection = _connection()

    result = await middleware.authenticate_request(connection)

    assert result.user is user


async def test_human_organization_postprocessing_publishes_verified_membership() -> None:
    """Verified tenant membership is published for downstream human guards."""
    organization = SimpleNamespace(id="org")
    membership = object()
    store = _Store(organization, membership)
    user = ExampleUser(id=uuid4())
    middleware = _middleware(
        _Provider(Authenticated(_context())),
        loader=lambda _context: user,
        organization_store_factory=lambda _session: store,
        tenant_resolver=lambda _connection: "tenant",
    )
    connection = _connection()

    await middleware.authenticate_request(connection)

    assert store.membership_args == ("org", user.id)
