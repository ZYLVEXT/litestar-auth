"""Litestar extension for sender-constrained workload authentication."""

from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from importlib import import_module
from typing import TYPE_CHECKING, Any, Never, cast

from authweave_core import AuthenticationContext, TlsPeerEvidence
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

    from authweave_workload.jwt import DelegationPolicy

type SecurityEventCallback = Callable[[SecurityEvent], Awaitable[None] | None]
type TlsPeerEvidenceFactory = Callable[[Scope], TlsPeerEvidence | None]
type MachineGuard = Callable[[ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], None]
UNIX_SOCKET_PROXY = "unix"
_ENVOY_SHA256_HEX_LENGTH = 64

_TLS_HEADER_NAMES = (
    b"x-auth-tls-verified",
    b"x-auth-tls-version",
    b"x-auth-client-cert-sha256",
    b"x-auth-client-cert-not-before",
    b"x-auth-client-cert-not-after",
    b"x-auth-client-cert-trust-anchor",
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
class WorkloadAuthExtension:
    """Contribute workload providers to litestar-auth's single middleware."""

    tls_peer_evidence_factory: TlsPeerEvidenceFactory
    direct_mtls: tuple[DirectMTLSProviderConfig, ...] = ()
    mtls_bound_jwt: tuple[MTLSBoundJWTProviderConfig, ...] = ()
    name: str = "authweave_workload"
    enabled: bool = True
    requires_api: tuple[int, int] = EXTENSION_API_VERSION

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Reject provider inventory conflicts before application wiring.

        Raises:
            ValueError: If the provider inventory is empty, duplicated, or conflicts.
        """
        providers = (*self.direct_mtls, *self.mtls_bound_jwt)
        if not providers:
            msg = "authweave-workload extension requires at least one provider"
            raise ValueError(msg)
        if len(self.direct_mtls) > 1 or len(self.mtls_bound_jwt) > 1:
            msg = "authweave-workload permits at most one provider for each machine profile"
            raise ValueError(msg)
        names = tuple(provider.name for provider in providers)
        if len(names) != len(set(names)):
            msg = "authweave-workload provider names must be unique"
            raise ValueError(msg)
        if set(names).intersection(context.backend_names):
            msg = "authweave-workload provider names conflict with human providers"
            raise ValueError(msg)

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Register typed providers, trusted TLS projection, and OpenAPI metadata."""
        context.add_tls_peer_evidence_factory(
            self.name,
            lambda scope: self.tls_peer_evidence_factory(cast("Scope", scope)),
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


@dataclass(frozen=True, slots=True)
class EnvoyTLSHeaderEvidence:
    """Project sanitized Envoy headers only from allowlisted proxy connections."""

    proxy_addresses: frozenset[str]
    trust_anchors: frozenset[str]
    revocation_checked_at: Callable[[], datetime]
    termination_boundary: str = "envoy"

    def __post_init__(self) -> None:
        """Require an explicit proxy and trust-anchor allowlist.

        Raises:
            ValueError: If either allowlist is empty.
        """
        if not self.proxy_addresses or not self.trust_anchors or not callable(self.revocation_checked_at):
            msg = "Envoy TLS evidence requires proxy addresses and trust anchors"
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
                certificate_thumbprint=_parse_envoy_thumbprint(values[b"x-auth-client-cert-sha256"]),
                certificate_not_before=_parse_time(values[b"x-auth-client-cert-not-before"]),
                certificate_not_after=_parse_time(values[b"x-auth-client-cert-not-after"]),
                revocation_checked_at=self.revocation_checked_at(),
                trust_anchor=trust_anchor,
                termination_boundary=self.termination_boundary,
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise NotAuthorizedException(detail="TLS client evidence is invalid.") from exc


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


def _parse_time(value: bytes) -> datetime:
    parsed = datetime.fromisoformat(value.decode("ascii"))
    if parsed.utcoffset() is None:
        raise ValueError
    return parsed


def _parse_envoy_thumbprint(value: bytes) -> str:
    encoded = value.decode("ascii")
    if len(encoded) != _ENVOY_SHA256_HEX_LENGTH:
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
    "DirectMTLSProviderConfig",
    "EnvoyTLSHeaderEvidence",
    "MTLSBoundJWTProviderConfig",
    "WorkloadAuthExtension",
    "require_machine_audience",
    "require_machine_environment",
    "require_machine_kind",
    "require_machine_scope",
    "require_maximum_delegation_depth",
)
