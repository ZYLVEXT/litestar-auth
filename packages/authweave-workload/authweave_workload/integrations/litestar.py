"""Litestar extension for sender-constrained workload authentication."""

from __future__ import annotations

import base64
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from typing import TYPE_CHECKING, Any, ClassVar, Never, cast

from authweave_core import AuthenticationContext, ReplayStore, SpiffePeerEvidence, TlsPeerEvidence
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.openapi.spec import SecurityScheme

from authweave_workload.events import SecurityEvent
from authweave_workload.jwt import MTLSBoundJWTProvider, TrustedIssuer
from authweave_workload.provider import DirectMTLSPolicy, DirectMTLSProvider
from litestar_auth.authentication import LitestarProviderBinding
from litestar_auth.extensions import (
    EXTENSION_API_VERSION,
    AuthExtensionRegistrationContext,
    AuthExtensionValidationContext,
)

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Scope

    from authweave_workload.dpop import DPoPPolicy
    from authweave_workload.introspection import (
        BoundedIntrospectionClient,
        IntrospectionIssuerProfile,
    )
    from authweave_workload.jwt import DelegationPolicy
    from authweave_workload.spiffe import SpiffePolicy, SpiffePrincipalResolver

type SecurityEventCallback = Callable[[SecurityEvent], Awaitable[None] | None]
type TlsPeerEvidenceFactory = Callable[[Scope], TlsPeerEvidence | None]
type SpiffePeerEvidenceFactory = Callable[[Scope], SpiffePeerEvidence | None]
type MachineGuard = Callable[[ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], None]
type _CertificateTimeParser = Callable[[bytes], datetime]
UNIX_SOCKET_PROXY = "unix"
_SHA256_HEX_LENGTH = 64

_CLOUDFLARE_CERTIFICATE_TIME_PATTERN = re.compile(
    rb"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    rb"(?P<day> [1-9]|[12][0-9]|3[01]) "
    rb"(?P<hour>[0-2][0-9]):(?P<minute>[0-5][0-9]):(?P<second>[0-5][0-9]) "
    rb"(?P<year>[0-9]{4}) GMT"
)
_CLOUDFLARE_MONTHS = {
    b"Jan": 1,
    b"Feb": 2,
    b"Mar": 3,
    b"Apr": 4,
    b"May": 5,
    b"Jun": 6,
    b"Jul": 7,
    b"Aug": 8,
    b"Sep": 9,
    b"Oct": 10,
    b"Nov": 11,
    b"Dec": 12,
}

_TLS_HEADER_NAMES = (
    b"x-auth-tls-verified",
    b"x-auth-tls-version",
    b"x-auth-client-cert-sha256",
    b"x-auth-client-cert-not-before",
    b"x-auth-client-cert-not-after",
    b"x-auth-client-cert-trust-anchor",
)

_SPIFFE_HEADER_NAMES = (
    b"x-auth-spiffe-id",
    b"x-auth-spiffe-not-before",
    b"x-auth-spiffe-not-after",
)


@dataclass(frozen=True, slots=True)
class DirectMTLSProviderConfig:
    """One direct mTLS provider contribution."""

    name: str
    policy: DirectMTLSPolicy
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class MTLSBoundJWTProviderConfig:
    """One external mTLS-bound access-token provider contribution."""

    name: str
    issuer: TrustedIssuer
    tls_policy: DirectMTLSPolicy
    delegation_policy: DelegationPolicy | None = None
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class DPoPBoundJWTProviderConfig:
    """One external DPoP-bound access-token provider contribution."""

    name: str
    issuer: TrustedIssuer
    dpop: DPoPPolicy
    replay_store: ReplayStore
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class SPIFFEProviderConfig:
    """One SPIFFE X.509-SVID provider contribution (mesh or headless projection)."""

    name: str
    policy: SpiffePolicy
    resolver: SpiffePrincipalResolver
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class MTLSBoundIntrospectionProviderConfig:
    """One mTLS-bound opaque-token introspection provider contribution."""

    name: str
    client: BoundedIntrospectionClient
    profile: IntrospectionIssuerProfile
    tls_policy: DirectMTLSPolicy
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class DPoPBoundIntrospectionProviderConfig:
    """One DPoP-bound opaque-token introspection provider contribution."""

    name: str
    client: BoundedIntrospectionClient
    profile: IntrospectionIssuerProfile
    dpop: DPoPPolicy
    replay_store: ReplayStore
    event_callback: SecurityEventCallback | None = None


@dataclass(frozen=True, slots=True)
class WorkloadAuthExtension:
    """Contribute workload providers to litestar-auth's single middleware."""

    tls_peer_evidence_factory: TlsPeerEvidenceFactory
    direct_mtls: tuple[DirectMTLSProviderConfig, ...] = ()
    mtls_bound_jwt: tuple[MTLSBoundJWTProviderConfig, ...] = ()
    dpop_bound_jwt: tuple[DPoPBoundJWTProviderConfig, ...] = ()
    spiffe: tuple[SPIFFEProviderConfig, ...] = ()
    mtls_bound_introspection: tuple[MTLSBoundIntrospectionProviderConfig, ...] = ()
    dpop_bound_introspection: tuple[DPoPBoundIntrospectionProviderConfig, ...] = ()
    spiffe_peer_evidence_factory: SpiffePeerEvidenceFactory | None = None
    name: str = "authweave_workload"
    enabled: bool = True
    allow_unaudited: bool = False
    requires_api: tuple[int, int] = EXTENSION_API_VERSION

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Reject provider inventory conflicts before application wiring.

        Raises:
            ValueError: If the provider inventory is empty, duplicated, or conflicts.
        """
        providers = (
            *self.direct_mtls,
            *self.mtls_bound_jwt,
            *self.dpop_bound_jwt,
            *self.spiffe,
            *self.mtls_bound_introspection,
            *self.dpop_bound_introspection,
        )
        if not providers:
            msg = "authweave-workload extension requires at least one provider"
            raise ValueError(msg)
        inventories = (
            self.direct_mtls,
            self.mtls_bound_jwt,
            self.dpop_bound_jwt,
            self.spiffe,
            self.mtls_bound_introspection,
            self.dpop_bound_introspection,
        )
        if any(len(inventory) > 1 for inventory in inventories):
            msg = "authweave-workload permits at most one provider for each machine profile"
            raise ValueError(msg)
        if self.spiffe and self.spiffe_peer_evidence_factory is None:
            msg = "SPIFFE providers require spiffe_peer_evidence_factory"
            raise ValueError(msg)
        names = tuple(provider.name for provider in providers)
        if len(names) != len(set(names)):
            msg = "authweave-workload provider names must be unique"
            raise ValueError(msg)
        if set(names).intersection(context.backend_names):
            msg = "authweave-workload provider names conflict with human providers"
            raise ValueError(msg)
        if not self.allow_unaudited:
            unaudited = tuple(provider.name for provider in providers if provider.event_callback is None)
            if unaudited:
                joined = ", ".join(unaudited)
                msg = (
                    "authweave-workload production configuration requires a mandatory "
                    f"authentication event_callback for provider(s): {joined}. "
                    "Set allow_unaudited=True only for explicitly non-audited local fixtures (ADR 0001)."
                )
                raise ValueError(msg)

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Register typed providers, trusted TLS/SPIFFE projection, and OpenAPI metadata."""
        context.add_tls_peer_evidence_factory(
            self.name,
            lambda scope: self.tls_peer_evidence_factory(cast("Scope", scope)),
        )
        if self.spiffe_peer_evidence_factory is not None:
            spiffe_factory = self.spiffe_peer_evidence_factory
            context.add_spiffe_peer_evidence_factory(
                self.name,
                lambda scope, factory=spiffe_factory: factory(cast("Scope", scope)),
            )
        for settings in self.direct_mtls:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile=DirectMTLSProvider.profile,
                factory=lambda session, settings=settings: _direct_binding(session, settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="mutualTLS",
                    description="TLS 1.3 mutual-TLS client certificate authentication.",
                ),
            )
        for settings in self.mtls_bound_jwt:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile=MTLSBoundJWTProvider.profile,
                factory=lambda _session, settings=settings: _jwt_binding(settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="http",
                    scheme="Bearer",
                    bearer_format="JWT",
                    description="RFC 8705 certificate-bound access token; trusted mTLS evidence is mandatory.",
                ),
            )
        for settings in self.dpop_bound_jwt:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile="dpop_bound_access_token",
                factory=lambda _session, settings=settings: _dpop_binding(settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="http",
                    scheme="DPoP",
                    bearer_format="JWT",
                    description="RFC 9449 DPoP-bound access token; DPoP proof JWT is mandatory.",
                ),
            )
        for settings in self.spiffe:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile="spiffe_x509_svid",
                factory=lambda _session, settings=settings: _spiffe_binding(settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="mutualTLS",
                    description="SPIFFE X.509-SVID identity projected by a single trusted validation boundary.",
                ),
            )
        for settings in self.mtls_bound_introspection:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile="mtls_bound_introspection",
                factory=lambda _session, settings=settings: _introspection_binding(settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="http",
                    scheme="Bearer",
                    bearer_format="opaque",
                    description="RFC 7662 introspection; cnf.x5t#S256 must match trusted mTLS evidence.",
                ),
            )
        for settings in self.dpop_bound_introspection:
            context.add_authentication_provider(
                self.name,
                name=settings.name,
                profile="dpop_bound_introspection",
                factory=lambda _session, settings=settings: _dpop_introspection_binding(settings),
            )
            context.add_openapi_security_scheme(
                self.name,
                settings.name,
                SecurityScheme(
                    type="http",
                    scheme="DPoP",
                    bearer_format="opaque",
                    description="RFC 9449 DPoP proof bound to RFC 7662 or RFC 9701 introspection.",
                ),
            )


def _parse_time(value: bytes) -> datetime:
    parsed = datetime.fromisoformat(value.decode("ascii"))
    if parsed.utcoffset() is None:
        raise ValueError
    return parsed


def _parse_cloudflare_time(value: bytes) -> datetime:
    match = _CLOUDFLARE_CERTIFICATE_TIME_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError
    return datetime(
        int(match["year"]),
        _CLOUDFLARE_MONTHS[match["month"]],
        int(match["day"]),
        int(match["hour"]),
        int(match["minute"]),
        int(match["second"]),
        tzinfo=UTC,
    )


@dataclass(frozen=True, slots=True)
class _TLSHeaderEvidence:
    """Shared fail-closed projection for provider-specific TLS header contracts."""

    proxy_addresses: frozenset[str]
    trust_anchors: frozenset[str]
    revocation_checked_at: Callable[[], datetime]
    termination_boundary: str
    _provider_name: ClassVar[str]
    _certificate_time_parser: ClassVar[_CertificateTimeParser]

    def __post_init__(self) -> None:
        """Require an explicit proxy and trust-anchor allowlist.

        Raises:
            ValueError: If either allowlist is empty.
        """
        if not self.proxy_addresses or not self.trust_anchors or not callable(self.revocation_checked_at):
            msg = f"{self._provider_name} TLS evidence requires proxy addresses and trust anchors"
            raise ValueError(msg)

    def __call__(self, scope: Scope) -> TlsPeerEvidence | None:
        """Return strict TLS evidence or reject forged/incomplete presentations.

        Raises:
            NotAuthorizedException: If presented TLS evidence is untrusted or malformed.
        """
        values = _tls_headers(scope)
        if not values:
            return None
        client = scope.get("client")
        client_address = (
            client[0]
            if isinstance(client, tuple) and client and isinstance(client[0], str)
            else UNIX_SOCKET_PROXY
            if client is None
            else None
        )
        if client_address not in self.proxy_addresses:
            _reject_evidence("TLS client evidence is not trusted.")
        if set(values) != set(_TLS_HEADER_NAMES) or values[b"x-auth-tls-verified"] != b"SUCCESS":
            _reject_evidence("TLS client evidence is invalid.")
        try:
            trust_anchor = values[b"x-auth-client-cert-trust-anchor"].decode("ascii")
            _require_trust_anchor(trust_anchor, self.trust_anchors)
            return TlsPeerEvidence(
                tls_version=values[b"x-auth-tls-version"].decode("ascii"),
                certificate_thumbprint=_parse_sha256_thumbprint(values[b"x-auth-client-cert-sha256"]),
                certificate_not_before=self._certificate_time_parser(values[b"x-auth-client-cert-not-before"]),
                certificate_not_after=self._certificate_time_parser(values[b"x-auth-client-cert-not-after"]),
                revocation_checked_at=self.revocation_checked_at(),
                trust_anchor=trust_anchor,
                termination_boundary=self.termination_boundary,
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise NotAuthorizedException(detail="TLS client evidence is invalid.") from exc


@dataclass(frozen=True, slots=True)
class EnvoyTLSHeaderEvidence(_TLSHeaderEvidence):
    """Project sanitized Envoy headers only from allowlisted proxy connections."""

    termination_boundary: str = "envoy"
    _provider_name: ClassVar[str] = "Envoy"
    _certificate_time_parser: ClassVar[_CertificateTimeParser] = staticmethod(_parse_time)


@dataclass(frozen=True, slots=True)
class CloudflareTLSHeaderEvidence(_TLSHeaderEvidence):
    """Project sanitized Cloudflare mTLS headers from allowlisted origin connections.

    Cloudflare certificate validity fields use its documented OpenSSL-style
    ``Mon DD HH:MM:SS YYYY GMT`` representation. The edge must emit
    ``X-Auth-TLS-Verified: SUCCESS`` only when ``cert_verified`` is true and
    ``cert_revoked`` is false, overwrite every ``X-Auth-*`` evidence header,
    and prevent direct traffic from reaching the origin.
    """

    termination_boundary: str = "cloudflare"
    _provider_name: ClassVar[str] = "Cloudflare"
    _certificate_time_parser: ClassVar[_CertificateTimeParser] = staticmethod(_parse_cloudflare_time)


@dataclass(frozen=True, slots=True)
class MeshSPIFFEHeaderEvidence:
    """Project SPIFFE peer identity from allowlisted mesh identity headers.

    Only trust these headers when the connection arrives from an allowlisted
    local mesh proxy that already validated the X.509-SVID chain (ADR 0006).
    """

    proxy_addresses: frozenset[str]
    termination_boundary: str = "mesh-local"

    def __post_init__(self) -> None:
        """Require an explicit proxy allowlist and termination boundary.

        Raises:
            ValueError: If the proxy allowlist or boundary is empty.
        """
        if not self.proxy_addresses or not self.termination_boundary:
            msg = "Mesh SPIFFE evidence requires proxy addresses and a termination boundary"
            raise ValueError(msg)

    def __call__(self, scope: Scope) -> SpiffePeerEvidence | None:
        """Return SPIFFE peer evidence or reject forged/incomplete presentations.

        Raises:
            NotAuthorizedException: If presented SPIFFE evidence is untrusted or malformed.
        """
        values = _spiffe_headers(scope)
        if not values:
            return None
        client = scope.get("client")
        client_address = (
            client[0]
            if isinstance(client, tuple) and client and isinstance(client[0], str)
            else UNIX_SOCKET_PROXY
            if client is None
            else None
        )
        if client_address not in self.proxy_addresses:
            _reject_evidence("SPIFFE peer evidence is not trusted.")
        if set(values) != set(_SPIFFE_HEADER_NAMES):
            _reject_evidence("SPIFFE peer evidence is invalid.")
        try:
            spiffe_id = values[b"x-auth-spiffe-id"].decode("ascii")
            parsed = import_module("authweave_workload.spiffe").parse_spiffe_id(spiffe_id)
            return SpiffePeerEvidence(
                spiffe_id=str(parsed),
                trust_domain=parsed.trust_domain,
                not_before=_parse_time(values[b"x-auth-spiffe-not-before"]),
                not_after=_parse_time(values[b"x-auth-spiffe-not-after"]),
                termination_boundary=self.termination_boundary,
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise NotAuthorizedException(detail="SPIFFE peer evidence is invalid.") from exc


def _direct_binding(session: object, settings: DirectMTLSProviderConfig) -> LitestarProviderBinding:
    store_type = import_module("authweave_workload.sqlalchemy").SQLAlchemyWorkloadStore
    provider = DirectMTLSProvider(
        name=settings.name,
        store=store_type(cast("Any", session)),
        policy=settings.policy,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def _jwt_binding(settings: MTLSBoundJWTProviderConfig) -> LitestarProviderBinding:
    provider = MTLSBoundJWTProvider(
        name=settings.name,
        issuer=settings.issuer,
        tls_policy=settings.tls_policy,
        delegation_policy=settings.delegation_policy,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def _dpop_binding(settings: DPoPBoundJWTProviderConfig) -> LitestarProviderBinding:
    dpop_module = import_module("authweave_workload.dpop")
    provider = dpop_module.DPoPBoundJWTProvider(
        name=settings.name,
        issuer=settings.issuer,
        dpop=settings.dpop,
        replay_store=settings.replay_store,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def _spiffe_binding(settings: SPIFFEProviderConfig) -> LitestarProviderBinding:
    spiffe_module = import_module("authweave_workload.spiffe")
    provider = spiffe_module.SPIFFEProvider(
        name=settings.name,
        policy=settings.policy,
        resolver=settings.resolver,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def _introspection_binding(settings: MTLSBoundIntrospectionProviderConfig) -> LitestarProviderBinding:
    intro_module = import_module("authweave_workload.introspection")
    provider = intro_module.MTLSBoundIntrospectionProvider(
        name=settings.name,
        client=settings.client,
        profile=settings.profile,
        tls_policy=settings.tls_policy,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def _dpop_introspection_binding(settings: DPoPBoundIntrospectionProviderConfig) -> LitestarProviderBinding:
    intro_module = import_module("authweave_workload.introspection")
    provider = intro_module.DPoPBoundIntrospectionProvider(
        name=settings.name,
        client=settings.client,
        profile=settings.profile,
        dpop=settings.dpop,
        replay_store=settings.replay_store,
        event_callback=settings.event_callback,
    )
    return LitestarProviderBinding(provider=provider, load_principal=_load_principal)


def raise_dpop_nonce_challenge(nonce: str) -> Never:
    """Raise a secret-free DPoP nonce challenge as HTTP 401.

    Raises:
        NotAuthorizedException: Always, with RFC 9449 challenge headers.
    """
    challenge = import_module("authweave_workload.dpop").DPoPNonceChallenge(nonce)
    raise NotAuthorizedException(
        detail="Authentication credentials are invalid.",
        headers={
            "WWW-Authenticate": challenge.www_authenticate(),
            **challenge.response_headers(),
        },
    )


def _load_principal(context: AuthenticationContext) -> object:
    return context.subject


def _tls_headers(scope: Scope) -> dict[bytes, bytes]:
    relevant: dict[bytes, bytes] = {}
    for raw_name, value in scope.get("headers", ()):
        name = raw_name.lower()
        if name not in _TLS_HEADER_NAMES:
            continue
        if name in relevant:
            raise NotAuthorizedException(detail="TLS client evidence is ambiguous.")
        relevant[name] = value
    return relevant


def _spiffe_headers(scope: Scope) -> dict[bytes, bytes]:
    relevant: dict[bytes, bytes] = {}
    for raw_name, value in scope.get("headers", ()):
        name = raw_name.lower()
        if name not in _SPIFFE_HEADER_NAMES:
            continue
        if name in relevant:
            raise NotAuthorizedException(detail="SPIFFE peer evidence is ambiguous.")
        relevant[name] = value
    return relevant


def _parse_sha256_thumbprint(value: bytes) -> str:
    encoded = value.decode("ascii")
    if len(encoded) != _SHA256_HEX_LENGTH:
        raise ValueError
    digest = bytes.fromhex(encoded)
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _require_trust_anchor(value: str, allowed: frozenset[str]) -> None:
    if value not in allowed:
        raise ValueError


def _reject_evidence(detail: str) -> Never:
    raise NotAuthorizedException(detail=detail)


def require_machine_kind(*kinds: str) -> MachineGuard:
    """Build a guard requiring one explicit non-human principal kind.

    Returns:
        A Litestar guard.

    Raises:
        ValueError: If no non-human kind is supplied.
    """
    required = frozenset(kinds)
    if not required or "human" in required:
        msg = "machine kind guard requires at least one non-human kind"
        raise ValueError(msg)

    def guard(connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler) -> None:
        context = _machine_context(connection)
        if context.subject.kind not in required:
            raise PermissionDeniedException(detail="Machine principal kind is not permitted.")

    return guard


def require_machine_scope(scope: str) -> MachineGuard:
    """Build a guard requiring one verified credential scope.

    Returns:
        A Litestar guard.

    Raises:
        ValueError: If the scope is empty.
    """
    if not scope:
        raise ValueError

    def guard(connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler) -> None:
        if scope not in _machine_context(connection).evidence.scopes:
            raise PermissionDeniedException(detail="Machine credential scope is insufficient.")

    return guard


def require_machine_audience(audience: str) -> MachineGuard:
    """Build a guard requiring one verified audience.

    Returns:
        A Litestar guard.

    Raises:
        ValueError: If the audience is empty.
    """
    if not audience:
        raise ValueError

    def guard(connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler) -> None:
        if audience not in _machine_context(connection).evidence.audiences:
            raise PermissionDeniedException(detail="Machine credential audience is not permitted.")

    return guard


def require_machine_environment(environment: str) -> MachineGuard:
    """Build a guard requiring one verified environment.

    Returns:
        A Litestar guard.

    Raises:
        ValueError: If the environment is empty.
    """
    if not environment:
        raise ValueError

    def guard(connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler) -> None:
        if _machine_context(connection).evidence.environment != environment:
            raise PermissionDeniedException(detail="Machine credential environment is not permitted.")

    return guard


def require_maximum_delegation_depth(maximum_depth: int) -> MachineGuard:
    """Build a guard bounding the verified delegation chain.

    Returns:
        A Litestar guard.

    Raises:
        ValueError: If the maximum depth is negative.
    """
    if maximum_depth < 0:
        raise ValueError

    def guard(connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler) -> None:
        if len(_machine_context(connection).delegation_chain) > maximum_depth:
            raise PermissionDeniedException(detail="Machine delegation depth is not permitted.")

    return guard


def _machine_context(connection: ASGIConnection[Any, Any, Any, Any]) -> AuthenticationContext:
    context = connection.auth
    if not isinstance(context, AuthenticationContext) or context.subject.kind == "human":
        raise NotAuthorizedException(detail="Machine authentication is required.")
    return context


__all__ = (
    "UNIX_SOCKET_PROXY",
    "CloudflareTLSHeaderEvidence",
    "DPoPBoundIntrospectionProviderConfig",
    "DPoPBoundJWTProviderConfig",
    "DirectMTLSProviderConfig",
    "EnvoyTLSHeaderEvidence",
    "MTLSBoundIntrospectionProviderConfig",
    "MTLSBoundJWTProviderConfig",
    "MeshSPIFFEHeaderEvidence",
    "SPIFFEProviderConfig",
    "WorkloadAuthExtension",
    "raise_dpop_nonce_challenge",
    "require_machine_audience",
    "require_machine_environment",
    "require_machine_kind",
    "require_machine_scope",
    "require_maximum_delegation_depth",
)
