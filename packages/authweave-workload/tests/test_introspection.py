"""RFC 7662 plain introspection and mTLS-bound opaque-token provider tests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, cast
from unittest.mock import patch
from urllib.parse import parse_qs

import jwt
import jwt.algorithms
import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    InMemoryReplayStore,
    Invalid,
    ReplayOutcome,
    RequestView,
    TlsPeerEvidence,
    Unavailable,
)
from authweave_workload.authorization_details import (
    PAYMENT_AUTHORIZATION_TYPE,
    PaymentAuthorizationPolicy,
    payment_authorization_evidence,
)
from authweave_workload.dpop import DPoPPolicy
from authweave_workload.introspection import (
    BoundedIntrospectionClient,
    DPoPBoundIntrospectionProvider,
    IntrospectionCachePolicy,
    IntrospectionClaims,
    IntrospectionEndpoint,
    IntrospectionIssuerProfile,
    IntrospectionUnavailableError,
    IntrospectionValidationError,
    MTLSBoundIntrospectionProvider,
    PrivateKeyJWTClientAuth,
    SignedIntrospectionResponsePolicy,
    StaticBearerClientAuth,
    parse_plain_introspection,
    parse_signed_introspection,
    token_digest,
)
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.provider import DirectMTLSPolicy
from authweave_workload.redis_store import RedisIntrospectionCache
from cryptography.hazmat.primitives.asymmetric import ec

_NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
_THUMBPRINT = "A" * 43
_TOKEN = "opaque-access-token"
_ISSUER = "https://as.example/issuer"
_HTTP_OK = 200
_PAYMENT_LOCATION = "https://api.example/payments"


def _payment_policy() -> PaymentAuthorizationPolicy:
    return PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"})},
        allowed_locations=frozenset({_PAYMENT_LOCATION}),
        currency_limits={"EUR": "500.00"},
    )


def _payment_details(*, action: str = "initiate") -> list[dict[str, object]]:
    return [
        {
            "type": PAYMENT_AUTHORIZATION_TYPE,
            "actions": [action],
            "locations": [_PAYMENT_LOCATION],
            "instructedAmount": {"currency": "EUR", "amount": "125.50"},
        }
    ]


def _peer(*, thumbprint: str = _THUMBPRINT) -> TlsPeerEvidence:
    return TlsPeerEvidence(
        tls_version="TLSv1.3",
        certificate_thumbprint=thumbprint,
        certificate_not_before=_NOW - timedelta(hours=1),
        certificate_not_after=_NOW + timedelta(hours=1),
        revocation_checked_at=_NOW - timedelta(minutes=1),
        trust_anchor="local-ca",
        termination_boundary="envoy",
    )


def _policy() -> DirectMTLSPolicy:
    return DirectMTLSPolicy(
        trust_anchors=frozenset({"local-ca"}),
        termination_boundaries=frozenset({"envoy"}),
    )


def _active_body(*, thumbprint: str = _THUMBPRINT, **extra: object) -> bytes:
    payload: dict[str, object] = {
        "active": True,
        "sub": "merchant-1",
        "client_id": "client-1",
        "aud": "payments-api",
        "scope": "payments:write",
        "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
        "iat": int((_NOW - timedelta(minutes=1)).timestamp()),
        "cnf": {"x5t#S256": thumbprint},
    }
    payload.update(extra)
    return json.dumps(payload).encode()


def _request(*, token: str = _TOKEN, peer: TlsPeerEvidence | None = None) -> RequestView:
    return RequestView(
        method="POST",
        headers=((b"authorization", f"Bearer {token}".encode()),),
        tls_peer=_peer() if peer is None else peer,
        timestamp=_NOW,
    )


def _poster(
    body: bytes,
    *,
    status: int = _HTTP_OK,
    content_type: str = "application/json",
) -> Any:
    async def poster(
        _url: str,
        _headers: object,
        _request_body: bytes,
        _timeout: float,
        _maximum: int,
    ) -> tuple[int, bytes, str]:
        return status, body, content_type

    return poster


def _provider(
    body: bytes | None = None,
    *,
    profile: IntrospectionIssuerProfile | None = None,
    poster: Any = None,
) -> MTLSBoundIntrospectionProvider:
    return MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body() if body is None else body) if poster is None else poster,
        ),
        profile=profile or IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )


pytestmark = pytest.mark.unit


async def test_parse_and_provider_succeeds_with_matching_cnf() -> None:
    claims = parse_plain_introspection(_active_body())
    assert claims.active
    assert claims.confirmation_thumbprint == _THUMBPRINT

    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        client_auth=StaticBearerClientAuth("rs-client-token"),
        poster=_poster(_active_body()),
    )
    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=client,
        profile=IntrospectionIssuerProfile(
            issuer=_ISSUER,
            environment="sandbox",
            audiences=frozenset({"payments-api"}),
        ),
        tls_policy=_policy(),
    )
    assert provider.match(_request()) is CredentialMatch.OWNED
    decision = await provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.confirmation_thumbprint == _THUMBPRINT
    assert decision.context.evidence.method == "introspection"


async def test_plain_introspection_maps_typed_payment_authority_and_cache_transport() -> None:
    """Plain RFC 7662 details survive bounded cache encoding and issuer validation."""
    from authweave_workload import introspection as introspection_module

    body = _active_body(authorization_details=_payment_details())
    claims = parse_plain_introspection(body)
    assert claims.authorization_details is not None
    assert claims.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE
    cached = introspection_module._parse_cached_claims(introspection_module._encode_cached_claims(claims))
    assert cached.authorization_details == claims.authorization_details
    provider = _provider(
        body,
        profile=IntrospectionIssuerProfile(
            issuer=_ISSUER,
            environment="sandbox",
            audiences=frozenset({"payments-api"}),
            payment_authorization=_payment_policy(),
        ),
    )

    decision = await provider.authenticate(_request(), AuthenticationRuntime())

    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE
    widened = _provider(
        _active_body(authorization_details=_payment_details(action="refund")),
        profile=provider.issuer_profile,
    )
    assert await widened.authenticate(_request(), AuthenticationRuntime()) == Invalid(FailureCode.INVALID)


async def test_introspection_callback_failure_fails_closed() -> None:
    """ADR 0001: a raised event callback maps the outcome to Unavailable."""

    def _raise(_event: object) -> None:
        raise RuntimeError

    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body()),
        ),
        profile=IntrospectionIssuerProfile(
            issuer=_ISSUER,
            environment="sandbox",
            audiences=frozenset({"payments-api"}),
        ),
        tls_policy=_policy(),
        event_callback=_raise,
    )
    decision = await provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


async def test_provider_rejects_cnf_mismatch_and_inactive() -> None:
    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body(thumbprint="B" * 43)),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    decision = await provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.SENDER_CONSTRAINT_MISMATCH

    inactive_provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(b'{"active":false}'),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    inactive_decision = await inactive_provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(inactive_decision, Invalid)
    assert inactive_decision.code is FailureCode.INVALID


async def test_provider_unavailable_on_transport_failure() -> None:
    async def boom(*_args: object, **_kwargs: object) -> tuple[int, bytes, str]:
        raise IntrospectionUnavailableError("down")

    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=boom,
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    decision = await provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Unavailable)


def test_parse_rejects_inactive_metadata_and_bad_cnf() -> None:
    with pytest.raises(IntrospectionValidationError, match="inactive"):
        parse_plain_introspection(b'{"active":false,"sub":"x"}')
    with pytest.raises(IntrospectionValidationError, match="boolean"):
        parse_plain_introspection(b'{"active":"yes"}')
    assert parse_plain_introspection(_active_body(cnf={"jkt": "A" * 43})).confirmation_jkt == "A" * 43
    with pytest.raises(IntrospectionValidationError, match="confirmation"):
        parse_plain_introspection(_active_body(cnf={"x5t#S256": "short"}))
    with pytest.raises(IntrospectionValidationError, match="exactly one"):
        parse_plain_introspection(_active_body(cnf={"jkt": "A" * 43, "x5t#S256": "A" * 43}))


def test_endpoint_and_profile_validation() -> None:
    with pytest.raises(ValueError, match="https"):
        IntrospectionEndpoint(url="http://as.example/introspect")
    with pytest.raises(ValueError, match="positive"):
        IntrospectionEndpoint(url="https://as.example/introspect", timeout_seconds=0)
    with pytest.raises(ValueError, match="human"):
        IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox", principal_kind="human")
    with pytest.raises(ValueError, match="subject_claim"):
        IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox", subject_claim="email")
    with pytest.raises(ValueError, match="outbound"):
        StaticBearerClientAuth("")
    digest = token_digest(_TOKEN, issuer=_ISSUER)
    assert len(digest) == 43
    assert digest != _TOKEN


def test_static_bearer_client_auth_repr_redacts_token() -> None:
    secret_canary = "SECRET_CANARY_introspection_client"

    client_auth = StaticBearerClientAuth(secret_canary)

    assert secret_canary not in repr(client_auth)
    assert secret_canary not in str(client_auth)


async def test_match_ambiguity_and_missing_tls() -> None:
    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body()),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    assert provider.match(RequestView(method="POST", timestamp=_NOW)) is CredentialMatch.NOT_APPLICABLE
    ambiguous = RequestView(
        method="POST",
        headers=((b"authorization", b"Bearer a"), (b"authorization", b"Bearer b")),
        timestamp=_NOW,
    )
    assert provider.match(ambiguous) is CredentialMatch.AMBIGUOUS
    dpop_mixed = RequestView(
        method="POST",
        headers=((b"authorization", b"Bearer a"), (b"dpop", b"proof")),
        timestamp=_NOW,
    )
    assert provider.match(dpop_mixed) is CredentialMatch.AMBIGUOUS
    no_tls = RequestView(
        method="POST",
        headers=((b"authorization", f"Bearer {_TOKEN}".encode()),),
        timestamp=_NOW,
    )
    decision = await provider.authenticate(no_tls, AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.SENDER_CONSTRAINT_MISMATCH


async def test_audience_and_content_type_failures() -> None:
    provider = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body(aud="other-api")),
        ),
        profile=IntrospectionIssuerProfile(
            issuer=_ISSUER,
            environment="sandbox",
            audiences=frozenset({"payments-api"}),
        ),
        tls_policy=_policy(),
    )
    decision = await provider.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.AUDIENCE_MISMATCH

    typed = MTLSBoundIntrospectionProvider(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body(), content_type="text/plain"),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    typed_decision = await typed.authenticate(_request(), AuthenticationRuntime())
    assert isinstance(typed_decision, Invalid)
    assert typed_decision.code is FailureCode.MALFORMED


async def test_default_poster_requires_httpx_and_bounds_response(monkeypatch: pytest.MonkeyPatch) -> None:
    from authweave_workload import introspection as mod

    class _FakeResponse:
        status_code = _HTTP_OK
        headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

        async def aiter_bytes(self) -> Any:
            yield b'{"active":false}'

        async def aclose(self) -> None:
            return None

    class _Stream:
        async def __aenter__(self) -> _FakeResponse:
            return _FakeResponse()

        async def __aexit__(self, *_exc: object) -> None:
            return None

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            return None

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_exc: object) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> _Stream:
            return _Stream()

    class _Httpx:
        HTTPError = OSError
        AsyncClient = _Client

    monkeypatch.setitem(__import__("sys").modules, "httpx", cast("Any", _Httpx))
    status, body, ctype = await mod._post_introspection(
        "https://as.example/introspect",
        {"accept": "application/json"},
        b"token=x",
        1.0,
        1024,
    )
    assert status == _HTTP_OK
    assert body == b'{"active":false}'
    assert ctype == "application/json"

    class _Huge:
        status_code = _HTTP_OK
        headers: ClassVar[dict[str, str]] = {"content-type": "application/json"}

        async def aiter_bytes(self) -> Any:
            yield b"x" * 64

        async def aclose(self) -> None:
            return None

    class _HugeStream:
        async def __aenter__(self) -> _Huge:
            return _Huge()

        async def __aexit__(self, *_exc: object) -> None:
            return None

    class _HugeClient:
        def __init__(self, **_kwargs: object) -> None:
            return None

        async def __aenter__(self) -> _HugeClient:
            return self

        async def __aexit__(self, *_exc: object) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> _HugeStream:
            return _HugeStream()

    cast("Any", _Httpx).AsyncClient = _HugeClient
    with pytest.raises(IntrospectionValidationError, match="size limit"):
        await mod._post_introspection(
            "https://as.example/introspect",
            {"accept": "application/json"},
            b"token=x",
            1.0,
            8,
        )

    class _UnavailableClient(_Client):
        async def __aenter__(self) -> _UnavailableClient:
            raise TimeoutError

    cast("Any", _Httpx).AsyncClient = _UnavailableClient
    with pytest.raises(IntrospectionUnavailableError, match="request failed"):
        await mod._post_introspection(
            "https://as.example/introspect",
            {"accept": "application/json"},
            b"token=x",
            1.0,
            8,
        )


async def test_litestar_introspection_extension_wiring() -> None:
    from authweave_workload.integrations.litestar import (
        DPoPBoundIntrospectionProviderConfig,
        MTLSBoundIntrospectionProviderConfig,
        WorkloadAuthExtension,
        _dpop_introspection_binding,
    )

    settings = MTLSBoundIntrospectionProviderConfig(
        name="intro",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body()),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        tls_policy=_policy(),
    )
    extension = WorkloadAuthExtension(
        lambda _scope: None,
        mtls_bound_introspection=(settings,),
        dpop_bound_introspection=(
            DPoPBoundIntrospectionProviderConfig(
                name="dpop-intro",
                client=settings.client,
                profile=settings.profile,
                dpop=DPoPPolicy(resource_server_id="payments-api"),
                replay_store=InMemoryReplayStore(capacity=8, time_source=_NOW.timestamp),
            ),
        ),
        allow_unaudited=True,
    )
    registered: list[dict[str, object]] = []

    class _Ctx:
        backend_names: frozenset[str] = frozenset()

        def add_tls_peer_evidence_factory(self, *_args: object, **_kwargs: object) -> None:
            return None

        def add_spiffe_peer_evidence_factory(self, *_args: object, **_kwargs: object) -> None:
            return None

        def add_authentication_provider(self, *_args: object, **kwargs: object) -> None:
            registered.append(kwargs)

        def add_openapi_security_scheme(self, *_args: object, **kwargs: object) -> None:
            return None

    extension.validate(cast("Any", _Ctx()))
    extension.register(cast("Any", _Ctx()))
    profiles = {cast("Any", item["factory"])(object()).provider.profile for item in registered}
    assert profiles == {"mtls_bound_introspection", "dpop_bound_introspection"}

    dpop_binding = _dpop_introspection_binding(
        DPoPBoundIntrospectionProviderConfig(
            name="dpop-intro",
            client=settings.client,
            profile=settings.profile,
            dpop=DPoPPolicy(resource_server_id="payments-api"),
            replay_store=InMemoryReplayStore(capacity=8, time_source=_NOW.timestamp),
        )
    )
    assert dpop_binding.provider.profile == "dpop_bound_introspection"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"not-json", "valid JSON"),
        (b"[]", "object"),
        (_active_body(exp="tomorrow"), "time claims"),
        (_active_body(sub=1), "string claim"),
        (_active_body(scope=["payments:write"]), "scope"),
        (_active_body(scope="payments:write payments:write"), "scope list"),
        (_active_body(aud=["payments-api", "payments-api"]), "aud claim"),
        (_active_body(aud=[1]), "aud claim"),
        (_active_body(authorization_details="not-an-array"), "authorization_details transport"),
    ],
)
def test_plain_parser_rejects_malformed_claim_shapes(payload: bytes, message: str) -> None:
    with pytest.raises(IntrospectionValidationError, match=message):
        parse_plain_introspection(payload)


def test_plain_parser_accepts_bounded_optional_claim_shapes() -> None:
    claims = parse_plain_introspection(
        _active_body(
            sub=None,
            aud=["payments-api", "refunds-api"],
            scope="",
            exp=None,
            iat=None,
            nbf=None,
            token_type=None,
            cnf=None,
        ),
    )
    assert claims.subject is None
    assert claims.audiences == ("payments-api", "refunds-api")
    assert claims.scopes == ()
    assert claims.expires_at is None
    assert claims.confirmation_thumbprint is None
    absent_collections = parse_plain_introspection(_active_body(aud=None, scope=None))
    assert absent_collections.audiences == ()
    assert absent_collections.scopes == ()


@pytest.mark.parametrize(
    "url",
    [
        "https://as.example/introspect#fragment",
        "https://user:password@as.example/introspect",
        "https://user%40as.example@as.example/introspect",
        "https:///introspect",
    ],
)
def test_endpoint_rejects_ambiguous_authority(url: str) -> None:
    with pytest.raises(ValueError, match=r"userinfo|https"):
        IntrospectionEndpoint(url=url)


def test_profile_and_static_auth_validation_edges() -> None:
    with pytest.raises(ValueError, match="required"):
        IntrospectionIssuerProfile(issuer="", environment="sandbox")
    with pytest.raises(ValueError, match="required"):
        IntrospectionIssuerProfile(issuer=_ISSUER, environment="")
    with pytest.raises(ValueError, match="outbound"):
        StaticBearerClientAuth("x" * 16_385)


async def test_private_key_jwt_and_signed_response_are_verified_end_to_end() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    public_jwk.update(kid="as-signing", alg="ES256", use="sig")

    class Signer:
        async def sign(
            self,
            *,
            protected_headers: Any,
            claims: Any,
        ) -> str:
            return jwt.encode(claims, key, algorithm="ES256", headers=protected_headers)

    auth = PrivateKeyJWTClientAuth(
        client_id="resource-server",
        audience="https://as.example/introspect",
        key_id="rs-signing",
        algorithm="ES256",
        signer=Signer(),
        time_source=lambda: _NOW,
        jti_source=lambda: "assertion-1",
    )
    response = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": "payments-api",
            "iat": int(_NOW.timestamp()),
            "token_introspection": json.loads(_active_body()),
        },
        key,
        algorithm="ES256",
        headers={"typ": "token-introspection+jwt", "kid": "as-signing"},
    ).encode()
    captured: dict[str, object] = {}

    async def poster(
        _url: str,
        headers: object,
        body: bytes,
        _timeout: float,
        _maximum: int,
    ) -> tuple[int, bytes, str]:
        captured.update(headers=headers, body=body)
        return _HTTP_OK, response, "application/token-introspection+jwt"

    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        client_auth=auth,
        signed_response=SignedIntrospectionResponsePolicy(
            issuer=_ISSUER,
            audience="payments-api",
            jwks=BoundedJWKSClient(static_jwks={"keys": [public_jwk]}),
            time_source=lambda: _NOW,
        ),
        poster=poster,
    )
    claims = await client.introspect(_TOKEN)
    form = parse_qs(cast("bytes", captured["body"]).decode(), strict_parsing=True)
    assertion = jwt.decode(
        form["client_assertion"][0],
        key.public_key(),
        algorithms=["ES256"],
        audience="https://as.example/introspect",
        options={"verify_exp": False},
    )
    assert claims.confirmation_thumbprint == _THUMBPRINT
    assert assertion["iss"] == assertion["sub"] == "resource-server"
    assert assertion["jti"] == "assertion-1"
    assert cast("dict[str, str]", captured["headers"])["accept"] == "application/token-introspection+jwt"


async def test_dpop_bound_opaque_token_is_verified_and_replay_rejected() -> None:
    proof_key = ec.generate_private_key(ec.SECP256R1())
    proof_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(proof_key.public_key()))
    canonical = json.dumps(
        {name: proof_jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    jkt = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    ath = base64.urlsafe_b64encode(hashlib.sha256(_TOKEN.encode()).digest()).rstrip(b"=").decode()
    policy = DPoPPolicy(resource_server_id="payments-api")
    proof = jwt.encode(
        {
            "jti": "proof-1",
            "htm": "POST",
            "htu": "https://api.example/payments",
            "iat": int((_NOW + policy.clock_skew).timestamp()),
            "ath": ath,
        },
        proof_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": proof_jwk},
    )
    request = RequestView(
        method="POST",
        target_uri="https://api.example/payments?ignored=yes",
        headers=((b"authorization", f"DPoP {_TOKEN}".encode()), (b"dpop", proof.encode())),
        timestamp=_NOW,
    )
    replay_clock = [0.0]
    provider = DPoPBoundIntrospectionProvider(
        name="opaque-dpop",
        client=BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            poster=_poster(_active_body(cnf={"jkt": jkt}, token_type="DPoP")),
        ),
        profile=IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
        dpop=policy,
        replay_store=InMemoryReplayStore(capacity=8, time_source=lambda: replay_clock[0]),
    )
    assert provider.match(request) is CredentialMatch.OWNED
    assert isinstance(await provider.authenticate(request, AuthenticationRuntime()), Authenticated)
    elapsed = policy.iat_window + 2 * policy.clock_skew
    replay_clock[0] = elapsed.total_seconds()
    replay = await provider.authenticate(replace(request, timestamp=_NOW + elapsed), AuthenticationRuntime())
    assert isinstance(replay, Invalid)
    assert replay.code is FailureCode.INVALID


async def test_introspection_cache_uses_digest_and_expiry_ceiling() -> None:
    entries: dict[str, bytes] = {}
    writes: list[tuple[str, int]] = []

    class Cache:
        async def get(self, key: str) -> bytes | None:
            return entries.get(key)

        async def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
            entries[key] = value
            writes.append((key, ttl_seconds))

    calls = 0

    async def poster(*_args: object) -> tuple[int, bytes, str]:
        nonlocal calls
        calls += 1
        return _HTTP_OK, _active_body(), "application/json"

    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        cache=Cache(),
        cache_policy=IntrospectionCachePolicy(
            issuer=_ISSUER,
            active_ttl_seconds=60,
            revocation_risk_ceiling_seconds=20,
            time_source=lambda: _NOW,
        ),
        poster=poster,
    )
    assert (await client.introspect(_TOKEN)).active
    assert (await client.introspect(_TOKEN)).active
    assert calls == 1
    assert writes[0][1] == 20
    assert _TOKEN not in writes[0][0]

    jkt_client = BoundedIntrospectionClient(
        endpoint=client.endpoint,
        cache=Cache(),
        cache_policy=IntrospectionCachePolicy(issuer=_ISSUER, active_ttl_seconds=10),
        poster=_poster(_active_body(cnf={"jkt": "A" * 43}, exp=None)),
    )
    assert (await jkt_client.introspect("other-token")).confirmation_jkt == "A" * 43
    unbound_client = BoundedIntrospectionClient(
        endpoint=client.endpoint,
        cache=Cache(),
        cache_policy=IntrospectionCachePolicy(issuer=_ISSUER, active_ttl_seconds=10),
        poster=_poster(_active_body(cnf=None, exp=None)),
    )
    assert (await unbound_client.introspect("unbound-token")).active


async def test_introspection_cache_failures_fall_through_and_inactive_is_short_lived() -> None:
    class Cache:
        value: bytes | None = None
        fail_get = False
        fail_set = False
        writes = 0

        async def get(self, key: str) -> bytes | None:
            del key
            if self.fail_get:
                raise OSError
            return self.value

        async def set(self, key: str, value: bytes, *, ttl_seconds: int) -> None:
            del key
            if self.fail_set:
                raise OSError
            assert ttl_seconds == 5
            self.value = value
            self.writes += 1

    cache = Cache()
    calls = 0

    async def poster(*_args: object) -> tuple[int, bytes, str]:
        nonlocal calls
        calls += 1
        return _HTTP_OK, b'{"active":false}', "application/json"

    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        cache=cache,
        cache_policy=IntrospectionCachePolicy(issuer=_ISSUER),
        poster=poster,
    )
    assert not (await client.introspect(_TOKEN)).active
    assert not (await client.introspect(_TOKEN)).active
    assert calls == 1
    assert cache.writes == 1

    cache.value = b"x" * 65_537
    cache.fail_set = True
    assert not (await client.introspect(_TOKEN)).active
    cache.fail_get = True
    assert not (await client.introspect(_TOKEN)).active

    active_cache = Cache()
    active = BoundedIntrospectionClient(
        endpoint=client.endpoint,
        cache=active_cache,
        cache_policy=IntrospectionCachePolicy(issuer=_ISSUER, time_source=lambda: _NOW.replace(tzinfo=None)),
        poster=_poster(_active_body()),
    )
    assert (await active.introspect(_TOKEN)).active
    assert active_cache.writes == 0


async def test_signed_introspection_rejects_trust_and_freshness_failures() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    public_jwk.update(kid="as-signing", alg="ES256", use="sig")
    policy = SignedIntrospectionResponsePolicy(
        issuer=_ISSUER,
        audience="payments-api",
        jwks=BoundedJWKSClient(static_jwks={"keys": [public_jwk]}),
        time_source=lambda: _NOW,
    )

    def signed(
        *,
        issuer: str = _ISSUER,
        audience: object = "payments-api",
        issued_at: object = int(_NOW.timestamp()),
        headers: dict[str, object] | None = None,
        signing_key: ec.EllipticCurvePrivateKey = key,
        nested: object = None,
    ) -> bytes:
        return jwt.encode(
            {
                "iss": issuer,
                "aud": audience,
                "iat": issued_at,
                "token_introspection": {"active": False} if nested is None else nested,
            },
            signing_key,
            algorithm="ES256",
            headers=headers or {"typ": "token-introspection+jwt", "kid": "as-signing"},
        ).encode()

    payloads = (
        b"not-a-jwt",
        signed(headers={"typ": "JWT", "kid": "as-signing"}),
        signed(headers={"typ": "token-introspection+jwt"}),
        signed(issuer="https://wrong.example"),
        signed(audience="wrong-api"),
        signed(audience=["payments-api", "other-resource-server"]),
        signed(signing_key=other_key),
        signed(issued_at="bad"),
        signed(issued_at=int((_NOW + timedelta(minutes=1)).timestamp())),
        signed(issued_at=int((_NOW - timedelta(minutes=6)).timestamp())),
        signed(nested=[]),
    )
    for payload in payloads:
        with pytest.raises(IntrospectionValidationError):
            await parse_signed_introspection(payload, policy, now=_NOW)

    hs256 = jwt.encode(
        {"iss": _ISSUER, "aud": "payments-api", "iat": int(_NOW.timestamp()), "token_introspection": {"active": False}},
        "a sufficiently long test-only secret",
        algorithm="HS256",
        headers={"typ": "token-introspection+jwt", "kid": "as-signing"},
    ).encode()
    with pytest.raises(IntrospectionValidationError, match="algorithm"):
        await parse_signed_introspection(hs256, policy, now=_NOW)
    with pytest.raises(IntrospectionValidationError, match="key"):
        await parse_signed_introspection(
            signed(headers={"typ": "token-introspection+jwt", "kid": "unknown"}), policy, now=_NOW
        )
    with pytest.raises(ValueError, match="timezone"):
        await parse_signed_introspection(signed(), policy, now=_NOW.replace(tzinfo=None))

    class UnavailableKeys:
        async def get_key(self, _kid: str, _algorithm: str) -> object:
            from authweave_workload.jwks import JWKSUnavailableError

            raise JWKSUnavailableError

    with pytest.raises(IntrospectionUnavailableError):
        await parse_signed_introspection(signed(), replace(policy, jwks=cast("Any", UnavailableKeys())), now=_NOW)

    signed_payment = await parse_signed_introspection(
        signed(nested=json.loads(_active_body(authorization_details=_payment_details()))),
        policy,
        now=_NOW,
    )
    assert signed_payment.authorization_details is not None
    assert signed_payment.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE

    downgrade = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        signed_response=policy,
        poster=_poster(b'{"active":false}'),
    )
    with pytest.raises(IntrospectionValidationError, match="Content-Type"):
        await downgrade.introspect(_TOKEN)

    for changes in (
        {"issuer": ""},
        {"audience": ""},
        {"algorithms": frozenset({"HS256"})},
        {"maximum_age": timedelta(0)},
    ):
        with pytest.raises(ValueError, match="signed introspection"):
            replace(policy, **changes)


async def test_private_key_jwt_and_cache_policy_validation_edges() -> None:
    class Signer:
        result = "assertion"

        async def sign(self, **_kwargs: object) -> str:
            return self.result

    signer = Signer()
    valid = PrivateKeyJWTClientAuth(
        client_id="rs",
        audience="https://as.example/introspect",
        key_id="key",
        algorithm="ES256",
        signer=signer,
    )
    invalid_auth = (
        {"client_id": ""},
        {"key_id": ""},
        {"algorithm": "HS256"},
        {"lifetime": timedelta(0)},
    )
    for changes in invalid_auth:
        with pytest.raises(ValueError, match="policy"):
            replace(valid, **changes)
    with pytest.raises(ValueError, match="aware"):
        await replace(valid, time_source=lambda: _NOW.replace(tzinfo=None)).authorize(
            endpoint="https://as.example/introspect", form={}, headers={}
        )
    signer.result = ""
    with pytest.raises(IntrospectionValidationError, match="signer"):
        await valid.authorize(endpoint="https://as.example/introspect", form={}, headers={})

    for arguments in (
        {"issuer": ""},
        {"issuer": _ISSUER, "active_ttl_seconds": -1},
        {"issuer": _ISSUER, "inactive_ttl_seconds": -1},
        {"issuer": _ISSUER, "revocation_risk_ceiling_seconds": 0},
    ):
        with pytest.raises(ValueError, match="cache policy"):
            IntrospectionCachePolicy(**cast("Any", arguments))
    with pytest.raises(ValueError, match="configured together"):
        BoundedIntrospectionClient(
            endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
            cache=cast("Any", object()),
        )


async def test_redis_introspection_cache_bounds_and_failures() -> None:
    class Redis:
        value: object = None
        fail = False

        async def get(self, _key: str) -> object:
            if self.fail:
                raise OSError
            return self.value

        async def set(self, _key: str, value: bytes, *, ex: int) -> None:
            if self.fail:
                raise OSError
            self.value = value

    redis = Redis()
    cache = RedisIntrospectionCache(redis)
    assert await cache.get("authweave:introspection:key") is None
    redis.value = "text"
    assert await cache.get("authweave:introspection:key") == b"text"
    redis.value = object()
    with pytest.raises(ValueError, match="value"):
        await cache.get("authweave:introspection:key")
    for key, value, ttl in (
        ("bad", b"x", 1),
        ("authweave:introspection:key", b"", 1),
        ("authweave:introspection:key", b"x", 0),
    ):
        with pytest.raises(ValueError):
            await cache.set(key, value, ttl_seconds=ttl)
    redis.fail = True
    with pytest.raises(RuntimeError, match="unavailable"):
        await cache.get("authweave:introspection:key")
    with pytest.raises(RuntimeError, match="unavailable"):
        await cache.set("authweave:introspection:key", b"x", ttl_seconds=1)


async def test_dpop_introspection_negative_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    from authweave_workload import introspection as mod

    request = RequestView(
        method="POST",
        target_uri="https://api.example/payments",
        headers=((b"authorization", b"DPoP opaque"), (b"dpop", b"proof")),
        timestamp=_NOW,
    )
    base_claims = IntrospectionClaims(
        active=True,
        subject="merchant-1",
        client_id="client-1",
        audiences=("payments-api",),
        expires_at=_NOW + timedelta(minutes=5),
        token_type="DPoP",
        confirmation_jkt="A" * 43,
    )

    class Client:
        claims = base_claims
        error: Exception | None = None

        async def introspect(self, _token: str) -> IntrospectionClaims:
            if self.error is not None:
                raise self.error
            return self.claims

    class Replay:
        outcome = ReplayOutcome.STORED

        async def check_and_store(self, _key: str, *, ttl_seconds: float) -> ReplayOutcome:
            assert ttl_seconds > 0
            return self.outcome

    client = Client()
    replay = Replay()

    def provider(
        *,
        profile: IntrospectionIssuerProfile | None = None,
        event_callback: Any = None,
    ) -> DPoPBoundIntrospectionProvider:
        return DPoPBoundIntrospectionProvider(
            name="opaque-dpop",
            client=cast("Any", client),
            profile=profile or IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox"),
            dpop=DPoPPolicy(resource_server_id="payments-api"),
            replay_store=cast("Any", replay),
            event_callback=event_callback,
        )

    async def valid_proof(*_args: object, **_kwargs: object) -> tuple[str, str]:
        return "A" * 43, "proof-jti"

    monkeypatch.setattr(mod, "verify_dpop_proof", valid_proof)
    assert provider().match(RequestView(method="GET", timestamp=_NOW)) is CredentialMatch.NOT_APPLICABLE
    assert (
        provider().match(RequestView(method="GET", headers=((b"dpop", b"proof"),), timestamp=_NOW))
        is CredentialMatch.OWNED
    )
    assert (
        provider().match(
            RequestView(method="GET", headers=((b"authorization", b"DPoP x"), (b"cookie", b"x")), timestamp=_NOW)
        )
        is CredentialMatch.AMBIGUOUS
    )
    assert (
        provider().match(RequestView(method="GET", headers=((b"authorization", b"Bearer x"),), timestamp=_NOW))
        is CredentialMatch.NOT_APPLICABLE
    )
    assert (
        provider().match(RequestView(method="GET", headers=((b"authorization", b"Basic x"),), timestamp=_NOW))
        is CredentialMatch.NOT_APPLICABLE
    )
    malformed = await provider().authenticate(RequestView(method="POST", timestamp=_NOW), AuthenticationRuntime())
    assert malformed == Invalid(FailureCode.MALFORMED)

    async def invalid_proof(*_args: object, **_kwargs: object) -> FailureCode:
        return FailureCode.SENDER_CONSTRAINT_MISMATCH

    monkeypatch.setattr(mod, "verify_dpop_proof", invalid_proof)
    assert await provider().authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.SENDER_CONSTRAINT_MISMATCH
    )
    monkeypatch.setattr(mod, "verify_dpop_proof", valid_proof)

    for error, expected in (
        (IntrospectionUnavailableError(), Unavailable()),
        (IntrospectionValidationError(), Invalid(FailureCode.MALFORMED)),
    ):
        client.error = error
        assert await provider().authenticate(request, AuthenticationRuntime()) == expected
    client.error = None

    for claims, code in (
        (replace(base_claims, active=False), FailureCode.INVALID),
        (replace(base_claims, token_type="Bearer"), FailureCode.SENDER_CONSTRAINT_MISMATCH),
    ):
        client.claims = claims
        assert await provider().authenticate(request, AuthenticationRuntime()) == Invalid(code)
    client.claims = base_claims

    payment_profile = IntrospectionIssuerProfile(
        issuer=_ISSUER,
        environment="sandbox",
        payment_authorization=_payment_policy(),
    )
    client.claims = replace(
        base_claims,
        scopes=("payments:write",),
        authorization_details=payment_authorization_evidence(
            _payment_details(),
            policy=_payment_policy(),
            scopes=("payments:write",),
        ),
    )
    payment_decision = await provider(profile=payment_profile).authenticate(request, AuthenticationRuntime())
    assert isinstance(payment_decision, Authenticated)
    assert payment_decision.context.evidence.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE
    client.claims = base_claims
    assert await provider(profile=payment_profile).authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.INVALID
    )

    mismatched_profile = IntrospectionIssuerProfile(
        issuer=_ISSUER,
        environment="sandbox",
        audiences=frozenset({"other-api"}),
    )
    assert await provider(profile=mismatched_profile).authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.AUDIENCE_MISMATCH
    )
    replay.outcome = ReplayOutcome.UNAVAILABLE
    assert await provider().authenticate(request, AuthenticationRuntime()) == Unavailable()
    replay.outcome = ReplayOutcome.STORED
    invalid_principal = IntrospectionIssuerProfile(issuer=_ISSUER, environment="sandbox", principal_kind="")
    assert await provider(profile=invalid_principal).authenticate(request, AuthenticationRuntime()) == Invalid(
        FailureCode.INVALID
    )

    def fail_event(_event: object) -> None:
        raise RuntimeError

    assert await provider(event_callback=fail_event).authenticate(request, AuthenticationRuntime()) == Unavailable()


async def test_client_applies_bounds_headers_and_transport_error_mapping() -> None:
    captured: dict[str, object] = {}

    async def record(
        url: str,
        headers: object,
        body: bytes,
        timeout_seconds: float,
        maximum: int,
    ) -> tuple[int, bytes, str]:
        captured.update(url=url, headers=headers, body=body, timeout=timeout_seconds, maximum=maximum)
        return _HTTP_OK, b'{"active":false}', "Application/JSON; charset=utf-8"

    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(
            url="https://as.example/introspect",
            timeout_seconds=1.5,
            maximum_response_bytes=512,
        ),
        client_auth=StaticBearerClientAuth("secret"),
        poster=record,
    )
    assert await client.introspect(_TOKEN) == IntrospectionClaims(active=False)
    assert captured["body"] == b"token=opaque-access-token"
    assert cast("dict[str, str]", captured["headers"])["authorization"] == "Bearer secret"

    for token in ("", "x" * 16_385):
        with pytest.raises(ValueError, match="empty or oversized"):
            await client.introspect(token)

    async def unexpected(*_args: object) -> tuple[int, bytes, str]:
        raise RuntimeError

    failing = BoundedIntrospectionClient(endpoint=client.endpoint, poster=unexpected)
    with pytest.raises(IntrospectionUnavailableError, match="request failed"):
        await failing.introspect(_TOKEN)

    async def invalid_response(*_args: object) -> tuple[int, bytes, str]:
        raise IntrospectionValidationError("invalid response")

    invalid = BoundedIntrospectionClient(endpoint=client.endpoint, poster=invalid_response)
    with pytest.raises(IntrospectionValidationError, match="invalid response"):
        await invalid.introspect(_TOKEN)

    oversized = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url=client.endpoint.url, maximum_response_bytes=16),
        poster=_poster(b'{"active":false}' + b" " * 16),
    )
    with pytest.raises(IntrospectionValidationError, match="configured size limit"):
        await oversized.introspect(_TOKEN)


@pytest.mark.parametrize(
    ("status", "content_type", "error"),
    [
        (503, "application/json", IntrospectionUnavailableError),
        (_HTTP_OK, "text/plain", IntrospectionValidationError),
    ],
)
async def test_client_rejects_transport_status_and_media_type(
    status: int,
    content_type: str,
    error: type[Exception],
) -> None:
    client = BoundedIntrospectionClient(
        endpoint=IntrospectionEndpoint(url="https://as.example/introspect"),
        poster=_poster(b'{"active":false}', status=status, content_type=content_type),
    )
    with pytest.raises(error):
        await client.introspect(_TOKEN)


@pytest.mark.parametrize(
    "authorization",
    [
        b"Basic secret",
        b"Bearer",
        b"Bearer ",
        b"Bearer " + b"x" * 16_385,
    ],
)
def test_provider_match_classifies_nonowned_and_owned_malformed_presentations(authorization: bytes) -> None:
    request = RequestView(method="POST", headers=((b"authorization", authorization),), timestamp=_NOW)
    expected = CredentialMatch.NOT_APPLICABLE if authorization.startswith(b"Basic") else CredentialMatch.OWNED
    assert _provider().match(request) is expected


@pytest.mark.parametrize(
    ("presentation", "expected_type", "expected_code"),
    [
        (
            RequestView(method="POST", headers=((b"authorization", b"Bearer"),), timestamp=_NOW),
            Invalid,
            FailureCode.MALFORMED,
        ),
        (
            _request(peer=replace(_peer(), tls_version="TLSv1.2")),
            Invalid,
            FailureCode.SENDER_CONSTRAINT_MISMATCH,
        ),
        (
            _request(peer=replace(_peer(), trust_anchor="other-ca")),
            Invalid,
            FailureCode.SENDER_CONSTRAINT_MISMATCH,
        ),
        (
            _request(peer=replace(_peer(), certificate_not_after=_NOW)),
            Invalid,
            FailureCode.SENDER_CONSTRAINT_MISMATCH,
        ),
        (
            _request(peer=replace(_peer(), revocation_checked_at=_NOW - timedelta(hours=1))),
            Unavailable,
            None,
        ),
        (
            _request(peer=replace(_peer(), revocation_checked_at=_NOW + timedelta(seconds=1))),
            Invalid,
            FailureCode.INTERNAL_INVARIANT,
        ),
    ],
)
async def test_provider_rejects_presentation_and_tls_matrix(
    presentation: RequestView,
    expected_type: type[Invalid | Unavailable],
    expected_code: FailureCode | None,
) -> None:
    decision = await _provider().authenticate(presentation, AuthenticationRuntime())
    assert isinstance(decision, expected_type)
    if isinstance(decision, Invalid):
        assert decision.code is expected_code


@pytest.mark.parametrize(
    ("body", "profile", "code"),
    [
        (_active_body(client_id=None), None, FailureCode.MALFORMED),
        (
            _active_body(sub=None),
            IntrospectionIssuerProfile(
                issuer=_ISSUER,
                environment="sandbox",
                require_client_id=False,
            ),
            FailureCode.MALFORMED,
        ),
        (_active_body(nbf=int((_NOW + timedelta(seconds=1)).timestamp())), None, FailureCode.NOT_YET_VALID),
        (_active_body(exp=int(_NOW.timestamp())), None, FailureCode.EXPIRED),
    ],
)
async def test_provider_rejects_active_claim_mapping_matrix(
    body: bytes,
    profile: IntrospectionIssuerProfile | None,
    code: FailureCode,
) -> None:
    decision = await _provider(body, profile=profile).authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is code


async def test_provider_maps_client_subject_and_unrestricted_audience() -> None:
    profile = IntrospectionIssuerProfile(
        issuer=_ISSUER,
        environment="sandbox",
        subject_claim="client_id",
    )
    decision = await _provider(_active_body(sub=None, aud=["payments-api"]), profile=profile).authenticate(
        _request(),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Authenticated)
    assert decision.context.subject.subject == "client-1"
    assert decision.context.evidence.audiences == ("payments-api",)


async def test_provider_maps_client_validation_errors_without_leaking() -> None:
    class _FailingClient:
        def __init__(self, error: Exception) -> None:
            self.error = error

        async def introspect(self, _token: str) -> IntrospectionClaims:
            raise self.error

    for error in (ValueError("bad token"), IntrospectionValidationError("bad response")):
        provider = _provider()
        provider.client = cast("BoundedIntrospectionClient", _FailingClient(error))
        decision = await provider.authenticate(_request(), AuthenticationRuntime())
        assert isinstance(decision, Invalid)
        assert decision.code is FailureCode.MALFORMED


async def test_provider_rejects_invalid_mapped_principal() -> None:
    profile = IntrospectionIssuerProfile(
        issuer=_ISSUER,
        environment="sandbox",
        principal_kind="INVALID",
    )
    decision = await _provider(profile=profile).authenticate(_request(), AuthenticationRuntime())
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.INVALID


@pytest.mark.parametrize(
    "headers",
    [
        ((b"authorization", b"Bearer one"), (b"authorization", b"Bearer two")),
        ((b"authorization", b"Bearer " + b"x" * 16_385),),
        ((b"authorization", b"Bearer \xff"),),
    ],
)
async def test_authenticate_rejects_malformed_bearer_bytes(headers: tuple[tuple[bytes, bytes], ...]) -> None:
    decision = await _provider().authenticate(
        RequestView(method="POST", headers=headers, tls_peer=_peer(), timestamp=_NOW),
        AuthenticationRuntime(),
    )
    assert isinstance(decision, Invalid)
    assert decision.code is FailureCode.MALFORMED


async def test_default_poster_reports_missing_httpx() -> None:
    from authweave_workload import introspection as mod

    real_import = __import__

    def missing_httpx(name: str, *args: object, **kwargs: object) -> object:
        if name == "httpx":
            raise ImportError
        return cast("Any", real_import)(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=missing_httpx), pytest.raises(ImportError, match="introspection"):
        await mod._post_introspection(
            "https://as.example/introspect",
            {"accept": "application/json"},
            b"token=x",
            1.0,
            8,
        )
