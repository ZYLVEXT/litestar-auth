"""Tests for the optional Litestar workload extension."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest
from authweave_core import AuthenticationContext, AuthenticationEvidence, PrincipalRef
from authweave_workload.integrations.litestar import (
    UNIX_SOCKET_PROXY,
    CloudflareTLSHeaderEvidence,
    DirectMTLSProviderConfig,
    EnvoyTLSHeaderEvidence,
    MeshSPIFFEHeaderEvidence,
    MTLSBoundJWTProviderConfig,
    SPIFFEProviderConfig,
    WorkloadAuthExtension,
    require_machine_audience,
    require_machine_environment,
    require_machine_kind,
    require_machine_scope,
    require_maximum_delegation_depth,
)
from authweave_workload.provider import DirectMTLSPolicy
from authweave_workload.spiffe import SpiffePolicy, SpiffeResolvedPrincipal
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_auth._plugin.extensions._context import (
    ExtensionRegistrationContext,
    ExtensionRegistrationContributions,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from authweave_workload.jwt import TrustedIssuer
    from litestar.connection import ASGIConnection
    from litestar.handlers.base import BaseRouteHandler
    from litestar.types import Scope

    from litestar_auth.extensions import AuthExtensionRegistrationContext, AuthExtensionValidationContext

_SHA256_THUMBPRINT = "ab" * 32
_REVOCATION_CHECKED_AT = datetime(2026, 7, 30, tzinfo=UTC)


def _scope(*, client: str | None = "127.0.0.1", headers: list[tuple[bytes, bytes]] | None = None) -> Scope:
    return cast(
        "Scope",
        {
            "client": None if client is None else (client, 443),
            "headers": headers or [],
        },
    )


def _headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"x-auth-tls-verified", b"SUCCESS"),
        (b"x-auth-tls-version", b"TLSv1.3"),
        (b"x-auth-client-cert-sha256", _SHA256_THUMBPRINT.encode()),
        (b"x-auth-client-cert-not-before", b"2026-01-01T00:00:00+00:00"),
        (b"x-auth-client-cert-not-after", b"2027-01-01T00:00:00+00:00"),
        (b"x-auth-client-cert-trust-anchor", b"local-ca"),
    ]


def _evidence_factory(*, proxy_addresses: frozenset[str] = frozenset({"127.0.0.1"})) -> EnvoyTLSHeaderEvidence:
    return EnvoyTLSHeaderEvidence(
        proxy_addresses,
        frozenset({"local-ca"}),
        lambda: _REVOCATION_CHECKED_AT,
    )


def _cloudflare_headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"x-auth-tls-verified", b"SUCCESS"),
        (b"x-auth-tls-version", b"TLSv1.3"),
        (b"x-auth-client-cert-sha256", _SHA256_THUMBPRINT.encode()),
        (b"x-auth-client-cert-not-before", b"Mar 21 13:35:00 2026 GMT"),
        (b"x-auth-client-cert-not-after", b"Nov  7 08:05:00 2026 GMT"),
        (b"x-auth-client-cert-trust-anchor", b"local-ca"),
    ]


def _cloudflare_evidence_factory() -> CloudflareTLSHeaderEvidence:
    return CloudflareTLSHeaderEvidence(
        frozenset({"127.0.0.1"}),
        frozenset({"local-ca"}),
        lambda: _REVOCATION_CHECKED_AT,
    )


pytestmark = pytest.mark.integration


def test_envoy_evidence_is_absent_without_proxy_headers() -> None:
    factory = _evidence_factory()

    assert factory(_scope()) is None


def test_envoy_evidence_rejects_forged_untrusted_headers() -> None:
    factory = _evidence_factory()

    with pytest.raises(NotAuthorizedException, match="not trusted"):
        factory(_scope(client="203.0.113.5", headers=_headers()))


def test_envoy_evidence_rejects_duplicate_security_headers() -> None:
    factory = _evidence_factory()

    with pytest.raises(NotAuthorizedException, match="ambiguous"):
        factory(_scope(headers=[*_headers(), (b"x-auth-tls-version", b"TLSv1.2")]))


def test_envoy_evidence_builds_strict_neutral_projection() -> None:
    factory = _evidence_factory()

    evidence = factory(_scope(headers=[(b"x-unrelated", b"value"), *_headers()]))

    assert evidence is not None
    assert evidence.tls_version == "TLSv1.3"
    expected_thumbprint = base64.urlsafe_b64encode(bytes.fromhex(_SHA256_THUMBPRINT)).rstrip(b"=").decode()
    assert evidence.certificate_thumbprint == expected_thumbprint
    assert evidence.revocation_checked_at == _REVOCATION_CHECKED_AT
    assert evidence.trust_anchor == "local-ca"
    assert evidence.termination_boundary == "envoy"


@pytest.mark.parametrize(
    ("proxy_addresses", "trust_anchors"),
    [(frozenset(), frozenset({"ca"})), (frozenset({"127.0.0.1"}), frozenset())],
)
def test_envoy_evidence_requires_explicit_trust(
    proxy_addresses: frozenset[str],
    trust_anchors: frozenset[str],
) -> None:
    with pytest.raises(ValueError, match="requires"):
        EnvoyTLSHeaderEvidence(proxy_addresses, trust_anchors, lambda: _REVOCATION_CHECKED_AT)


def test_envoy_evidence_accepts_an_explicit_unix_socket_boundary() -> None:
    factory = _evidence_factory(proxy_addresses=frozenset({UNIX_SOCKET_PROXY}))

    assert factory(_scope(client=None, headers=_headers())) is not None


@pytest.mark.parametrize(
    "headers",
    [
        _headers()[:-1],
        [(name, b"FAILED" if name == b"x-auth-tls-verified" else value) for name, value in _headers()],
        [(name, b"other-ca" if name == b"x-auth-client-cert-trust-anchor" else value) for name, value in _headers()],
        [(name, b"not-a-time" if name == b"x-auth-client-cert-not-before" else value) for name, value in _headers()],
        [
            (name, b"2026-01-01T00:00:00" if name == b"x-auth-client-cert-not-before" else value)
            for name, value in _headers()
        ],
        [(name, b"not-a-fingerprint" if name == b"x-auth-client-cert-sha256" else value) for name, value in _headers()],
        [(name, b"\xff" if name == b"x-auth-client-cert-trust-anchor" else value) for name, value in _headers()],
    ],
)
def test_envoy_evidence_rejects_incomplete_or_malformed_headers(headers: list[tuple[bytes, bytes]]) -> None:
    factory = _evidence_factory()
    with pytest.raises(NotAuthorizedException, match="invalid"):
        factory(_scope(headers=headers))


def test_envoy_evidence_rejects_cloudflare_timestamp_contract() -> None:
    with pytest.raises(NotAuthorizedException, match="invalid"):
        _evidence_factory()(_scope(headers=_cloudflare_headers()))


def test_cloudflare_evidence_builds_strict_neutral_projection() -> None:
    evidence = _cloudflare_evidence_factory()(_scope(headers=_cloudflare_headers()))

    assert evidence is not None
    assert evidence.certificate_not_before == datetime(2026, 3, 21, 13, 35, tzinfo=UTC)
    assert evidence.certificate_not_after == datetime(2026, 11, 7, 8, 5, tzinfo=UTC)
    assert evidence.revocation_checked_at == _REVOCATION_CHECKED_AT
    assert evidence.termination_boundary == "cloudflare"


def test_cloudflare_evidence_is_absent_without_headers_and_requires_explicit_trust() -> None:
    assert _cloudflare_evidence_factory()(_scope()) is None
    with pytest.raises(ValueError, match="Cloudflare TLS evidence requires"):
        CloudflareTLSHeaderEvidence(frozenset(), frozenset({"local-ca"}), lambda: _REVOCATION_CHECKED_AT)


@pytest.mark.parametrize(
    ("scope", "message"),
    [
        (_scope(client="203.0.113.5", headers=_cloudflare_headers()), "not trusted"),
        (
            _scope(headers=[*_cloudflare_headers(), (b"x-auth-tls-version", b"TLSv1.2")]),
            "ambiguous",
        ),
        (_scope(headers=_cloudflare_headers()[:-1]), "invalid"),
    ],
)
def test_cloudflare_evidence_rejects_untrusted_ambiguous_or_incomplete_headers(
    scope: Scope,
    message: str,
) -> None:
    with pytest.raises(NotAuthorizedException, match=message):
        _cloudflare_evidence_factory()(scope)


def test_cloudflare_evidence_rejects_unverified_or_revoked_projection() -> None:
    headers = [(name, b"FAILED" if name == b"x-auth-tls-verified" else value) for name, value in _cloudflare_headers()]
    with pytest.raises(NotAuthorizedException, match="invalid"):
        _cloudflare_evidence_factory()(_scope(headers=headers))


@pytest.mark.parametrize(
    "value",
    [
        b"2026-11-07T08:05:00+00:00",
        b"Nov 07 08:05:00 2026 GMT",
        b"Nov  7 08:05:00 2026 UTC",
        b"Not  7 08:05:00 2026 GMT",
        b"Feb 30 08:05:00 2026 GMT",
        b"Nov  7 25:05:00 2026 GMT",
    ],
)
def test_cloudflare_evidence_rejects_non_cloudflare_or_invalid_timestamps(value: bytes) -> None:
    headers = [
        (name, value if name == b"x-auth-client-cert-not-before" else header_value)
        for name, header_value in _cloudflare_headers()
    ]
    with pytest.raises(NotAuthorizedException, match="invalid"):
        _cloudflare_evidence_factory()(_scope(headers=headers))


def _policy() -> DirectMTLSPolicy:
    return DirectMTLSPolicy(
        trust_anchors=frozenset({"ca"}),
        termination_boundaries=frozenset({"envoy"}),
    )


def _extension(
    *,
    direct: tuple[DirectMTLSProviderConfig, ...] = (),
    jwt: tuple[MTLSBoundJWTProviderConfig, ...] = (),
) -> WorkloadAuthExtension:
    return WorkloadAuthExtension(
        lambda _scope: None,
        direct_mtls=direct,
        mtls_bound_jwt=jwt,
        allow_unaudited=True,
    )


def _validation_context(*backend_names: str) -> AuthExtensionValidationContext:
    return cast("AuthExtensionValidationContext", SimpleNamespace(backend_names=backend_names))


def test_workload_extension_rejects_empty_duplicate_and_conflicting_inventory() -> None:
    direct = DirectMTLSProviderConfig("machine", _policy())
    jwt = MTLSBoundJWTProviderConfig("jwt", cast("TrustedIssuer", object()), _policy())
    with pytest.raises(ValueError, match="at least"):
        _extension().validate(_validation_context())
    with pytest.raises(ValueError, match="at most"):
        _extension(direct=(direct, direct)).validate(_validation_context())
    with pytest.raises(ValueError, match="unique"):
        _extension(direct=(direct,), jwt=(replace(jwt, name="machine"),)).validate(_validation_context())
    with pytest.raises(ValueError, match="human"):
        _extension(direct=(direct,)).validate(_validation_context("machine"))


def test_workload_extension_requires_mandatory_event_callback_in_production() -> None:
    """ADR 0001: production configuration must wire a mandatory event callback."""
    direct = DirectMTLSProviderConfig("machine", _policy())
    production = WorkloadAuthExtension(lambda _scope: None, direct_mtls=(direct,))
    with pytest.raises(ValueError, match="event_callback"):
        production.validate(_validation_context())

    delivered: list[object] = []

    def _deliver(event: object) -> None:
        delivered.append(event)

    audited = WorkloadAuthExtension(
        lambda _scope: None,
        direct_mtls=(replace(direct, event_callback=_deliver),),
    )
    audited.validate(_validation_context())

    fixture = WorkloadAuthExtension(
        lambda _scope: None,
        direct_mtls=(direct,),
        allow_unaudited=True,
    )
    fixture.validate(_validation_context())


class _RegistrationRecorder:
    """Minimal Extension SDK v2 recorder."""

    backend_names: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.tls_factories: list[tuple[str, object]] = []
        self.spiffe_factories: list[tuple[str, object]] = []
        self.providers: list[tuple[str, str, str, object]] = []
        self.schemes: list[tuple[str, str, object]] = []

    def add_tls_peer_evidence_factory(self, extension_name: str, factory: object) -> None:
        self.tls_factories.append((extension_name, factory))

    def add_spiffe_peer_evidence_factory(self, extension_name: str, factory: object) -> None:
        self.spiffe_factories.append((extension_name, factory))

    def add_authentication_provider(
        self,
        extension_name: str,
        *,
        name: str,
        profile: str,
        factory: object,
    ) -> None:
        self.providers.append((extension_name, name, profile, factory))

    def add_openapi_security_scheme(self, extension_name: str, name: str, scheme: object) -> None:
        self.schemes.append((extension_name, name, scheme))


def test_workload_extension_registers_both_profiles_through_sdk_v2() -> None:
    direct = DirectMTLSProviderConfig("direct", _policy())
    jwt = MTLSBoundJWTProviderConfig("external", cast("TrustedIssuer", object()), _policy())
    extension = _extension(direct=(direct,), jwt=(jwt,))
    recorder = _RegistrationRecorder()

    extension.validate(_validation_context())
    extension.register(cast("AuthExtensionRegistrationContext", recorder))

    assert [item[1] for item in recorder.providers] == ["direct", "external"]
    assert [item[1] for item in recorder.schemes] == ["direct", "external"]
    assert recorder.tls_factories[0][0] == "authweave_workload"
    tls_factory = cast("Callable[[object], object]", recorder.tls_factories[0][1])
    assert tls_factory(cast("object", _scope())) is None
    jwt_factory = cast("Callable[[object], object]", recorder.providers[1][3])
    assert jwt_factory(None) is not None
    direct_factory = cast("Callable[[object], Any]", recorder.providers[0][3])
    direct_binding = direct_factory(object())
    assert direct_binding.load_principal(_context()).subject == "subject"


def _context(*, kind: str = "workload") -> AuthenticationContext:
    subject = PrincipalRef("issuer", "subject", kind)
    evidence = AuthenticationEvidence(
        "provider",
        "direct_mtls",
        "mtls",
        "issuer",
        audiences=("api",),
        scopes=("write",),
        environment="sandbox",
        extensions={"authweave-workload:application_id": "application"},
    )
    return AuthenticationContext(subject, subject, evidence)


def _connection(auth: object) -> object:
    return SimpleNamespace(auth=auth)


@pytest.mark.parametrize(
    ("builder", "arguments", "message"),
    [
        (require_machine_kind, (), "non-human"),
        (require_machine_kind, ("human",), "non-human"),
        (require_machine_scope, ("",), "^$"),
        (require_machine_audience, ("",), "^$"),
        (require_machine_environment, ("",), "^$"),
        (require_maximum_delegation_depth, (-1,), "^$"),
    ],
)
def test_machine_guards_reject_invalid_configuration(
    builder: Callable[..., object],
    arguments: tuple[object, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        builder(*arguments)


def test_machine_guards_enforce_verified_context_dimensions() -> None:
    connection = cast("ASGIConnection", _connection(_context()))
    handler = cast("BaseRouteHandler", None)
    require_machine_kind("workload")(connection, handler)
    require_machine_scope("write")(connection, handler)
    require_machine_audience("api")(connection, handler)
    require_machine_environment("sandbox")(connection, handler)
    require_maximum_delegation_depth(0)(connection, handler)
    failing = (
        require_machine_kind("service"),
        require_machine_scope("read"),
        require_machine_audience("other"),
        require_machine_environment("live"),
    )
    for guard in failing:
        with pytest.raises(PermissionDeniedException):
            guard(connection, handler)
    with pytest.raises(NotAuthorizedException):
        require_machine_kind("workload")(cast("ASGIConnection", _connection(None)), handler)
    with pytest.raises(NotAuthorizedException):
        require_machine_kind("workload")(cast("ASGIConnection", _connection(_context(kind="human"))), handler)
    delegated = replace(
        _context(),
        delegation_chain=(PrincipalRef("issuer", "actor", "agent"),),
    )
    with pytest.raises(PermissionDeniedException):
        require_maximum_delegation_depth(0)(cast("ASGIConnection", _connection(delegated)), handler)


_SPIFFE_ID = "spiffe://example.org/payments/worker"
_SPIFFE_BOUNDARY = "mesh-local"


def _spiffe_headers() -> list[tuple[bytes, bytes]]:
    return [
        (b"x-auth-spiffe-id", _SPIFFE_ID.encode()),
        (b"x-auth-spiffe-not-before", b"2026-07-31T11:00:00+00:00"),
        (b"x-auth-spiffe-not-after", b"2026-07-31T13:00:00+00:00"),
    ]


def _spiffe_factory(*, proxy_addresses: frozenset[str] = frozenset({"127.0.0.1"})) -> MeshSPIFFEHeaderEvidence:
    return MeshSPIFFEHeaderEvidence(proxy_addresses, termination_boundary=_SPIFFE_BOUNDARY)


class _StaticSpiffeResolver:
    async def resolve(self, spiffe_id: object) -> SpiffeResolvedPrincipal:
        return SpiffeResolvedPrincipal(
            principal=PrincipalRef(
                f"spiffe://{getattr(spiffe_id, 'trust_domain', 'example.org')}", str(spiffe_id), "workload"
            ),
            application_id="payments",
            environment="sandbox",
        )


def test_mesh_spiffe_evidence_is_absent_without_headers() -> None:
    assert _spiffe_factory()(_scope()) is None


def test_mesh_spiffe_evidence_rejects_untrusted_proxy() -> None:
    with pytest.raises(NotAuthorizedException, match="not trusted"):
        _spiffe_factory()(_scope(client="203.0.113.5", headers=_spiffe_headers()))


def test_mesh_spiffe_evidence_rejects_duplicate_headers() -> None:
    with pytest.raises(NotAuthorizedException, match="ambiguous"):
        _spiffe_factory()(_scope(headers=[*_spiffe_headers(), (b"x-auth-spiffe-id", _SPIFFE_ID.encode())]))


def test_mesh_spiffe_evidence_builds_secret_free_projection() -> None:
    evidence = _spiffe_factory()(_scope(headers=[(b"x-irrelevant", b"ignored"), *_spiffe_headers()]))
    assert evidence is not None
    assert evidence.spiffe_id == _SPIFFE_ID
    assert evidence.trust_domain == "example.org"
    assert evidence.termination_boundary == _SPIFFE_BOUNDARY


@pytest.mark.parametrize(
    "headers",
    [
        _spiffe_headers()[:-1],
        [(b"x-auth-spiffe-id", b"\xff"), *_spiffe_headers()[1:]],
    ],
)
def test_mesh_spiffe_evidence_rejects_incomplete_or_malformed_projection(
    headers: list[tuple[bytes, bytes]],
) -> None:
    with pytest.raises(NotAuthorizedException, match="invalid"):
        _spiffe_factory()(_scope(headers=headers))


def test_mesh_spiffe_evidence_accepts_unix_socket_proxy() -> None:
    factory = _spiffe_factory(proxy_addresses=frozenset({UNIX_SOCKET_PROXY}))
    evidence = factory(_scope(client=None, headers=_spiffe_headers()))
    assert evidence is not None


def test_mesh_spiffe_evidence_requires_proxy_allowlist() -> None:
    with pytest.raises(ValueError, match="proxy addresses"):
        MeshSPIFFEHeaderEvidence(frozenset())


def test_spiffe_extension_requires_peer_factory_and_registers_profile() -> None:
    settings = SPIFFEProviderConfig(
        name="spiffe",
        policy=SpiffePolicy(
            allowed_trust_domains=frozenset({"example.org"}),
            termination_boundaries=frozenset({_SPIFFE_BOUNDARY}),
        ),
        resolver=_StaticSpiffeResolver(),
    )
    with pytest.raises(ValueError, match="spiffe_peer_evidence_factory"):
        WorkloadAuthExtension(lambda _scope: None, spiffe=(settings,)).validate(_validation_context())

    extension = WorkloadAuthExtension(
        lambda _scope: None,
        spiffe=(settings,),
        spiffe_peer_evidence_factory=_spiffe_factory(),
        allow_unaudited=True,
    )
    recorder = _RegistrationRecorder()
    extension.validate(_validation_context())
    extension.register(cast("AuthExtensionRegistrationContext", recorder))
    assert recorder.providers[0][2] == "spiffe_x509_svid"
    assert recorder.spiffe_factories[0][0] == "authweave_workload"
    factory = cast("Callable[[object], object]", recorder.spiffe_factories[0][1])
    projected = factory(cast("object", _scope(headers=_spiffe_headers())))
    assert projected is not None
    binding_factory = cast("Callable[[object], Any]", recorder.providers[0][3])
    assert binding_factory(None).provider.profile == "spiffe_x509_svid"

    with pytest.raises(ValueError, match="at most one"):
        WorkloadAuthExtension(
            lambda _scope: None,
            spiffe=(settings, settings),
            spiffe_peer_evidence_factory=_spiffe_factory(),
        ).validate(_validation_context())


def test_extension_spiffe_peer_factory_conflict_is_enforced() -> None:
    class _Holder:
        contributions = ExtensionRegistrationContributions()

    holder = _Holder()

    def factory(_scope: object) -> None:
        return None

    cast("Any", ExtensionRegistrationContext.add_spiffe_peer_evidence_factory)(holder, "alpha", factory)
    assert holder.contributions.spiffe_evidence is not None
    assert holder.contributions.spiffe_evidence.extension_name == "alpha"
    with pytest.raises(ValueError, match="conflicts with extension 'alpha'"):
        cast("Any", ExtensionRegistrationContext.add_spiffe_peer_evidence_factory)(holder, "beta", factory)
    with pytest.raises(TypeError, match="callable"):
        cast("Any", ExtensionRegistrationContext.add_spiffe_peer_evidence_factory)(
            holder, "gamma", cast("Any", object())
        )
