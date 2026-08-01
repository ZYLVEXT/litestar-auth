"""Outbound RFC 8693 token exchange and authority-narrowing tests."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, Self, cast
from urllib.parse import parse_qs

import jwt
import pytest
from authweave_core import AuthenticationContext, AuthenticationEvidence, PrincipalRef
from authweave_workload.authorization_details import (
    PAYMENT_AUTHORIZATION_TYPE,
    PaymentAuthorizationDetail,
    PaymentAuthorizationPolicy,
)
from authweave_workload.token_exchange import (
    ACCESS_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    DPoPTokenEndpointBinding,
    MTLSTokenEndpointBinding,
    PrivateKeyJWTClientAuth,
    TokenExchangeClient,
    TokenExchangeCredential,
    TokenExchangeProfile,
    TokenExchangeRejectedError,
    TokenExchangeUnavailableError,
    TokenExchangeValidationError,
)
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Mapping

_NOW = datetime(2026, 8, 1, 12, tzinfo=UTC)
_ENDPOINT = "https://sts.example/oauth/token"
_SOURCE_ISSUER = "https://issuer.example"
_SOURCE_AUDIENCE = "frontend-api"
_ISSUER = "https://sts.example"
_RESOURCE = "https://backend.example/v1/payments"
_AUDIENCE = "backend-api"
_THUMBPRINT = "A" * 43
_CERTIFICATE_THUMBPRINT = "B" * 43


class _Signer:
    def __init__(
        self,
        key: ec.EllipticCurvePrivateKey,
        *,
        result: str | None = None,
        error: Exception | None = None,
    ) -> None:
        self.key = key
        self.result = result
        self.error = error
        self.messages: list[tuple[dict[str, object], dict[str, object]]] = []

    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        self.messages.append((dict(protected_headers), dict(claims)))
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return self.result
        return jwt.encode(dict(claims), self.key, algorithm="ES256", headers=cast("Any", dict(protected_headers)))


class _Verifier:
    def __init__(self, context: AuthenticationContext | None = None, error: Exception | None = None) -> None:
        self.context = context
        self.error = error
        self.calls: list[tuple[str, str, str]] = []

    async def verify(
        self,
        access_token: str,
        *,
        token_type: str,
        confirmation_thumbprint: str,
    ) -> AuthenticationContext:
        self.calls.append((access_token, token_type, confirmation_thumbprint))
        if self.error is not None:
            raise self.error
        return cast("AuthenticationContext", self.context)


class _Headers:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = dict(values)
        self.nonce_values: tuple[str, ...] = ()

    def get(self, name: str, default: str = "") -> str:
        return self.values.get(name, default)

    def get_list(self, name: str) -> list[str]:
        return list(self.nonce_values) if name == "dpop-nonce" else []


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, object]:
    value = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    assert isinstance(value, dict)
    return value


def _policy(*, required: bool = True) -> PaymentAuthorizationPolicy:
    return PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"}), "payments:read": frozenset({"status"})},
        allowed_locations=frozenset({_RESOURCE}),
        currency_limits={"EUR": "1000.00"},
        required=required,
    )


def _details(
    amount: str = "100.00",
    *,
    action: str = "initiate",
    location: str = _RESOURCE,
) -> tuple[PaymentAuthorizationDetail, ...]:
    return (
        PaymentAuthorizationDetail(
            actions=cast("Any", (action,)),
            locations=(location,),
            currency="EUR",
            amount=Decimal(amount),
            identifier="payment-1",
        ),
    )


def _raw_details(amount: str = "100.00", *, action: str = "initiate") -> list[dict[str, object]]:
    return [
        {
            "type": PAYMENT_AUTHORIZATION_TYPE,
            "actions": [action],
            "locations": [_RESOURCE],
            "instructedAmount": {"currency": "EUR", "amount": amount},
            "identifier": "payment-1",
        }
    ]


def _context(
    *,
    issuer: str = _SOURCE_ISSUER,
    audience: str = _SOURCE_AUDIENCE,
    subject: str = "subject-1",
    actor: str | None = None,
    chain: tuple[str, ...] = (),
    scopes: tuple[str, ...] = ("payments:write", "payments:read"),
    details: tuple[PaymentAuthorizationDetail, ...] = (),
    thumbprint: str = _THUMBPRINT,
    expires_at: datetime = _NOW + timedelta(minutes=5),
    not_before: datetime | None = _NOW - timedelta(minutes=1),
    issued_at: datetime | None = _NOW - timedelta(seconds=5),
) -> AuthenticationContext:
    principal = PrincipalRef(issuer, subject, "service")
    chain_principals = tuple(PrincipalRef(issuer, value, "service") for value in chain)
    actor_ref = PrincipalRef(issuer, actor or (chain[0] if chain else subject), "service")
    evidence = AuthenticationEvidence(
        provider="test",
        profile="token",
        method="jwt",
        issuer=issuer,
        audiences=(audience,),
        scopes=scopes,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        confirmation_thumbprint=thumbprint,
        authorization_details=tuple(detail.as_evidence() for detail in details),
    )
    return AuthenticationContext(
        subject=principal,
        actor=actor_ref,
        evidence=evidence,
        delegation_chain=chain_principals,
    )


def _client_auth(key: ec.EllipticCurvePrivateKey, *, signer: _Signer | None = None) -> PrivateKeyJWTClientAuth:
    return PrivateKeyJWTClientAuth(
        client_id="exchange-client",
        audience=_ENDPOINT,
        key_id="client-key",
        algorithm="ES256",
        signer=signer or _Signer(key),
        time_source=lambda: _NOW,
        jti_source=lambda: "assertion-jti",
    )


def _profile(
    *,
    verifier: _Verifier,
    binding: DPoPTokenEndpointBinding | MTLSTokenEndpointBinding,
    payment_policy: PaymentAuthorizationPolicy | None = None,
    client_auth: PrivateKeyJWTClientAuth | None = None,
) -> TokenExchangeProfile:
    key = ec.derive_private_key(5, ec.SECP256R1())
    return TokenExchangeProfile(
        endpoint=_ENDPOINT,
        issuer=_ISSUER,
        source_issuer=_SOURCE_ISSUER,
        source_audience=_SOURCE_AUDIENCE,
        resource=_RESOURCE,
        audience=_AUDIENCE,
        client_auth=client_auth or _client_auth(key),
        sender_binding=binding,
        verifier=verifier,
        allowed_scopes=frozenset({"payments:write", "payments:read"}),
        payment_authorization=payment_policy,
        time_source=lambda: _NOW,
    )


def _dpop_binding(*, signer: _Signer | None = None, jti: str = "proof-jti") -> DPoPTokenEndpointBinding:
    key = ec.derive_private_key(7, ec.SECP256R1())
    return DPoPTokenEndpointBinding(
        signer=signer or _Signer(key),
        public_jwk=_public_jwk(key),
        algorithm="ES256",
        jti_source=lambda: jti,
    )


def _response(
    *,
    token_type: object = "DPoP",
    scope: object = "payments:write",
    details: object = None,
    **updates: object,
) -> bytes:
    value: dict[str, object] = {
        "access_token": "issued-access-token",
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": token_type,
        "expires_in": 300,
    }
    if scope is not None:
        value["scope"] = scope
    if details is not None:
        value["authorization_details"] = details
    value.update(updates)
    return json.dumps(value).encode()


def _poster(
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "application/json",
    cache_control: str = "private, no-store",
    dpop_nonce: str | None = None,
    captured: dict[str, object] | None = None,
) -> Callable[[str, Mapping[str, str], bytes, float, int], Awaitable[tuple[int, bytes, Mapping[str, str]]]]:
    async def poster(
        url: str,
        headers: Mapping[str, str],
        request_body: bytes,
        timeout: float,
        maximum: int,
    ) -> tuple[int, bytes, dict[str, str]]:
        if captured is not None:
            captured.update(url=url, headers=dict(headers), body=request_body, timeout=timeout, maximum=maximum)
        response_headers = {"content-type": content_type, "cache-control": cache_control}
        if dpop_nonce is not None:
            response_headers["dpop-nonce"] = dpop_nonce
        return status, body, response_headers

    return poster


pytestmark = pytest.mark.unit


async def test_dpop_exchange_narrows_payment_and_adds_one_actor() -> None:
    """One protocol run binds client auth, DPoP, authority, and delegation."""
    binding = _dpop_binding()
    issued_details = _details("50.00")
    output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        actor="actor-1",
        chain=("actor-1",),
        scopes=("payments:write",),
        details=issued_details,
        thumbprint=binding.confirmation_thumbprint,
    )
    verifier = _Verifier(output)
    profile = _profile(verifier=verifier, binding=binding, payment_policy=_policy())
    captured: dict[str, object] = {}
    subject = TokenExchangeCredential("subject-token", _context(details=_details("200.00")))
    actor = TokenExchangeCredential("actor-token", _context(subject="actor-1"))

    result = await TokenExchangeClient(
        profile,
        poster=_poster(_response(details=_raw_details("50.00")), captured=captured),
    ).exchange(
        subject,
        actor=actor,
        scopes=("payments:write",),
        authorization_details=_details("100.00"),
    )

    form = parse_qs(cast("bytes", captured["body"]).decode())
    headers = cast("dict[str, str]", captured["headers"])
    proof_header = jwt.get_unverified_header(headers["dpop"])
    proof = jwt.decode(headers["dpop"], options={"verify_signature": False})
    assert form["grant_type"] == [TOKEN_EXCHANGE_GRANT_TYPE]
    assert form["resource"] == [_RESOURCE]
    assert form["audience"] == [_AUDIENCE]
    assert form["subject_token"] == ["subject-token"]
    assert form["actor_token"] == ["actor-token"]
    assert json.loads(form["authorization_details"][0]) == _raw_details("100.00")
    assert proof_header["typ"] == "dpop+jwt"
    assert proof == {"jti": "proof-jti", "htm": "POST", "htu": _ENDPOINT, "iat": int(_NOW.timestamp())}
    assert result.context is output
    assert result.token_type == "DPoP"
    assert result.expires_at == _NOW + timedelta(seconds=300)
    assert verifier.calls == [("issued-access-token", "DPoP", binding.confirmation_thumbprint)]
    assert "subject-token" not in repr(subject)
    assert "actor-token" not in repr(actor)
    assert "issued-access-token" not in repr(result)


async def test_dpop_nonce_challenge_continues_once_with_fresh_credentials() -> None:
    proof_jtis = iter(("proof-1", "proof-2", "proof-3"))
    assertion_jtis = iter(("assertion-1", "assertion-2", "assertion-3"))
    binding = replace(_dpop_binding(), jti_source=lambda: next(proof_jtis))
    key = ec.derive_private_key(5, ec.SECP256R1())
    client_auth = replace(_client_auth(key), jti_source=lambda: next(assertion_jtis))
    output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:read",),
        thumbprint=binding.confirmation_thumbprint,
    )
    requests: list[tuple[dict[str, str], dict[str, str]]] = []
    nonce_response_number = 2

    async def poster(
        _url: str,
        headers: Mapping[str, str],
        body: bytes,
        _timeout: float,
        _maximum: int,
    ) -> tuple[int, bytes, Mapping[str, str]]:
        requests.append((dict(headers), {name: values[0] for name, values in parse_qs(body.decode()).items()}))
        if len(requests) == 1:
            return (
                400,
                b'{"error":"use_dpop_nonce"}',
                {"content-type": "application/json", "dpop-nonce": "server-nonce"},
            )
        response_headers = {"content-type": "application/json", "cache-control": "no-store"}
        if len(requests) == nonce_response_number:
            response_headers["dpop-nonce"] = "rotated-nonce"
        return 200, _response(scope="payments:read"), response_headers

    client = TokenExchangeClient(
        _profile(verifier=_Verifier(output), binding=binding, client_auth=client_auth),
        poster=poster,
    )
    credential = TokenExchangeCredential("token", _context())
    result = await client.exchange(credential, scopes=("payments:read",))
    repeated = await client.exchange(credential, scopes=("payments:read",))

    proofs = [jwt.decode(headers["dpop"], options={"verify_signature": False}) for headers, _form in requests]
    assertions = [
        jwt.decode(form["client_assertion"], options={"verify_signature": False}) for _headers, form in requests
    ]
    assert result.context is output
    assert repeated.context is output
    assert proofs[0]["jti"] == "proof-1"
    assert "nonce" not in proofs[0]
    assert proofs[1]["jti"] == "proof-2"
    assert proofs[1]["nonce"] == "server-nonce"
    assert proofs[2]["jti"] == "proof-3"
    assert proofs[2]["nonce"] == "rotated-nonce"
    assert [claims["jti"] for claims in assertions] == ["assertion-1", "assertion-2", "assertion-3"]


@pytest.mark.parametrize("nonce", [None, "", "bad nonce", "x" * 513])
async def test_dpop_nonce_challenge_rejects_missing_or_invalid_nonce(nonce: str | None) -> None:
    calls = 0

    async def poster(*_args: object) -> tuple[int, bytes, Mapping[str, str]]:
        nonlocal calls
        calls += 1
        headers = {"content-type": "application/json"}
        if nonce is not None:
            headers["dpop-nonce"] = nonce
        return 400, b'{"error":"use_dpop_nonce"}', headers

    with pytest.raises(TokenExchangeValidationError, match="nonce"):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=_dpop_binding()), poster=poster).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )
    assert calls == 1


async def test_dpop_nonce_continuation_is_bounded_and_not_used_for_mtls() -> None:
    calls = 0

    async def poster(*_args: object) -> tuple[int, bytes, Mapping[str, str]]:
        nonlocal calls
        calls += 1
        return (
            400,
            b'{"error":"use_dpop_nonce"}',
            {
                "content-type": "application/json",
                "dpop-nonce": "server-nonce",
            },
        )

    with pytest.raises(TokenExchangeRejectedError) as rejected:
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=_dpop_binding()), poster=poster).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )
    assert rejected.value.error == "use_dpop_nonce"
    expected_calls = 2
    assert calls == expected_calls

    calls = 0
    with pytest.raises(TokenExchangeRejectedError):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=MTLSTokenEndpointBinding(_CERTIFICATE_THUMBPRINT)),
            poster=poster,
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))
    assert calls == 1


async def test_exchange_propagates_cancellation_without_retry() -> None:
    calls = 0

    async def poster(*_args: object) -> tuple[int, bytes, Mapping[str, str]]:
        nonlocal calls
        calls += 1
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=_dpop_binding()), poster=poster).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )
    assert calls == 1


async def test_mtls_exchange_requires_transport_and_accepts_unchanged_scope() -> None:
    binding = MTLSTokenEndpointBinding(_CERTIFICATE_THUMBPRINT)
    output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:read",),
        thumbprint=_CERTIFICATE_THUMBPRINT,
    )
    profile = _profile(verifier=_Verifier(output), binding=binding)
    with pytest.raises(ValueError, match="certificate-owning"):
        TokenExchangeClient(profile)
    captured: dict[str, object] = {}

    result = await TokenExchangeClient(
        profile,
        poster=_poster(_response(token_type="bearer", scope=None), captured=captured),
    ).exchange(TokenExchangeCredential("subject-token", _context()), scopes=("payments:read",))

    assert result.token_type == "Bearer"
    assert "dpop" not in cast("dict[str, str]", captured["headers"])


@pytest.mark.parametrize(
    "mutator",
    [
        lambda profile: replace(profile, endpoint="http://sts.example/token"),
        lambda profile: replace(profile, endpoint=cast("Any", None)),
        lambda profile: replace(profile, endpoint="https://sts.example:invalid/token"),
        lambda profile: replace(profile, endpoint=_ENDPOINT + "?tenant=x"),
        lambda profile: replace(profile, issuer=""),
        lambda profile: replace(profile, audience="*"),
        lambda profile: replace(profile, allowed_scopes=frozenset()),
        lambda profile: replace(profile, allowed_scopes=frozenset({"bad scope"})),
        lambda profile: replace(profile, maximum_delegation_depth=0),
        lambda profile: replace(profile, maximum_token_lifetime=timedelta(0)),
        lambda profile: replace(profile, clock_skew=timedelta(seconds=-1)),
        lambda profile: replace(profile, timeout_seconds=0),
        lambda profile: replace(profile, maximum_response_bytes=65_537),
        lambda profile: replace(
            profile, client_auth=replace(profile.client_auth, audience="https://other.example/token")
        ),
        lambda profile: replace(
            profile,
            payment_authorization=replace(_policy(), allowed_locations=frozenset({"https://other.example/payments"})),
        ),
        lambda profile: replace(profile, sender_binding=cast("Any", object())),
        lambda profile: replace(profile, verifier=cast("Any", object())),
    ],
)
def test_profile_rejects_open_or_inconsistent_policy(mutator: Any) -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    with pytest.raises((TypeError, ValueError)):
        mutator(profile)


def test_bindings_and_credentials_reject_invalid_material() -> None:
    key = ec.derive_private_key(7, ec.SECP256R1())
    with pytest.raises(ValueError, match="DPoP"):
        replace(_dpop_binding(), algorithm="PS256")
    with pytest.raises(ValueError, match="DPoP"):
        DPoPTokenEndpointBinding(_Signer(key), {**_public_jwk(key), "d": "private"}, "ES256")
    with pytest.raises(ValueError, match="DPoP"):
        DPoPTokenEndpointBinding(_Signer(key), cast("Any", None), "ES256")
    with pytest.raises(ValueError, match="DPoP"):
        DPoPTokenEndpointBinding(_Signer(key), {}, "ES256")
    with pytest.raises(TypeError, match="signer"):
        DPoPTokenEndpointBinding(cast("Any", object()), _public_jwk(key), "ES256")
    with pytest.raises(ValueError, match="mTLS"):
        MTLSTokenEndpointBinding("short")
    with pytest.raises(ValueError, match="credential"):
        TokenExchangeCredential("bad token", _context())
    with pytest.raises(ValueError, match="credential"):
        TokenExchangeCredential("token", _context(), token_type="unknown")


@pytest.mark.parametrize(
    "context",
    [
        _context(issuer="https://wrong.example"),
        _context(audience="wrong-api"),
        _context(
            expires_at=_NOW - timedelta(minutes=1),
            not_before=_NOW - timedelta(minutes=3),
            issued_at=_NOW - timedelta(minutes=2),
        ),
        _context(not_before=_NOW + timedelta(minutes=1)),
        _context(actor="wrong-actor"),
        _context(chain=("actor-1", "actor-1")),
    ],
)
async def test_exchange_rejects_invalid_source_context(context: AuthenticationContext) -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    with pytest.raises(TokenExchangeValidationError, match="source"):
        await TokenExchangeClient(profile, poster=_poster(b"{}")).exchange(
            TokenExchangeCredential("subject-token", context),
            scopes=("payments:read",),
        )


@pytest.mark.parametrize(
    "scopes",
    [(), ("payments:read", "payments:read"), ("bad scope",), ("admin",), ("payments:read", "admin")],
)
async def test_exchange_rejects_scope_widening(scopes: tuple[str, ...]) -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    raw_token = "private-source-token"
    with pytest.raises(TokenExchangeValidationError, match="scopes") as failure:
        await TokenExchangeClient(profile, poster=_poster(b"{}")).exchange(
            TokenExchangeCredential(raw_token, _context()),
            scopes=scopes,
        )
    assert raw_token not in str(failure.value)


async def test_exchange_rejects_payment_widening_and_unconfigured_details() -> None:
    subject_with_details = TokenExchangeCredential("subject-token", _context(details=_details("100.00")))
    disabled = _profile(verifier=_Verifier(), binding=_dpop_binding())
    with pytest.raises(TokenExchangeValidationError, match="not enabled"):
        await TokenExchangeClient(disabled, poster=_poster(b"{}")).exchange(
            subject_with_details,
            scopes=("payments:write",),
            authorization_details=_details("50.00"),
        )
    enabled = _profile(verifier=_Verifier(), binding=_dpop_binding(), payment_policy=_policy())
    for details in ((), _details("101.00"), _details("50.00", action="status")):
        with pytest.raises(TokenExchangeValidationError, match="payment authority"):
            await TokenExchangeClient(enabled, poster=_poster(b"{}")).exchange(
                subject_with_details,
                scopes=("payments:write",),
                authorization_details=details,
            )

    optional = _profile(
        verifier=_Verifier(),
        binding=_dpop_binding(),
        payment_policy=_policy(required=False),
    )
    malformed = replace(
        subject_with_details.context,
        evidence=replace(
            subject_with_details.context.evidence,
            authorization_details=cast("Any", ({"type": PAYMENT_AUTHORIZATION_TYPE},)),
        ),
    )
    with pytest.raises(TokenExchangeValidationError, match="subject payment"):
        await TokenExchangeClient(optional, poster=_poster(b"{}")).exchange(
            TokenExchangeCredential("token", malformed), scopes=("payments:read",)
        )

    output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:read",),
        thumbprint=optional.sender_binding.confirmation_thumbprint,
    )
    result = await TokenExchangeClient(
        replace(optional, verifier=_Verifier(output)),
        poster=_poster(_response(scope="payments:read")),
    ).exchange(TokenExchangeCredential("token", _context(details=())), scopes=("payments:read",))
    assert result.context is output

    other = "https://backend.example/v1/other"
    broad_policy = replace(_policy(), allowed_locations=frozenset({_RESOURCE, other}))
    broad = _profile(verifier=_Verifier(), binding=_dpop_binding(), payment_policy=broad_policy)
    with pytest.raises(TokenExchangeValidationError, match="configured resource"):
        await TokenExchangeClient(broad, poster=_poster(b"{}")).exchange(
            TokenExchangeCredential("token", _context(details=_details(location=other))),
            scopes=("payments:write",),
            authorization_details=_details("50.00", location=other),
        )


async def test_exchange_rejects_invalid_actor_transition() -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    subject = TokenExchangeCredential("subject-token", _context(chain=("old-actor",)))
    invalid_actors = (
        TokenExchangeCredential("actor-token", _context(subject="actor-1", chain=("nested",))),
        TokenExchangeCredential("actor-token", _context(subject="actor-1", scopes=("payments:read",))),
        TokenExchangeCredential("actor-token", _context(subject="subject-1")),
        TokenExchangeCredential("actor-token", _context(subject="old-actor")),
    )
    for actor in invalid_actors:
        with pytest.raises(TokenExchangeValidationError, match=r"actor|delegation"):
            await TokenExchangeClient(profile, poster=_poster(b"{}")).exchange(
                subject,
                actor=actor,
                scopes=("payments:write",),
            )


async def test_exchange_maps_signer_and_transport_failures() -> None:
    key = ec.derive_private_key(7, ec.SECP256R1())
    invalid_proof = _dpop_binding(signer=_Signer(key, result="invalid"))
    with pytest.raises(TokenExchangeValidationError, match="DPoP signer"):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=invalid_proof), poster=_poster(b"{}")
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))
    with pytest.raises(TokenExchangeValidationError, match="jti"):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=_dpop_binding(jti=" ")), poster=_poster(b"{}")
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))

    invalid_assertion = _client_auth(key, signer=_Signer(key, result=""))
    with pytest.raises(TokenExchangeValidationError, match="client assertion"):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=_dpop_binding(), client_auth=invalid_assertion),
            poster=_poster(b"{}"),
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))

    unavailable_signer = _client_auth(key, signer=_Signer(key, error=OSError()))
    with pytest.raises(TokenExchangeUnavailableError, match="signer"):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=_dpop_binding(), client_auth=unavailable_signer),
            poster=_poster(b"{}"),
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))

    with pytest.raises(TokenExchangeValidationError, match="aware datetime"):
        await TokenExchangeClient(
            replace(
                _profile(verifier=_Verifier(), binding=_dpop_binding()),
                time_source=lambda: _NOW.replace(tzinfo=None),
            ),
            poster=_poster(b"{}"),
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))

    async def failed_poster(*_args: object) -> tuple[int, bytes, Mapping[str, str]]:
        raise OSError

    with pytest.raises(TokenExchangeUnavailableError, match="request failed"):
        await TokenExchangeClient(
            _profile(verifier=_Verifier(), binding=_dpop_binding()), poster=failed_poster
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))


@pytest.mark.parametrize(
    ("body", "status", "content_type", "cache_control", "error"),
    [
        (_response(), 200, "text/plain", "no-store", TokenExchangeValidationError),
        (_response(), 200, "application/json", "public", TokenExchangeValidationError),
        (b"{}", 503, "application/json", "no-store", TokenExchangeUnavailableError),
        (b'{"error":"invalid_target"}', 400, "application/json", "no-store", TokenExchangeRejectedError),
        (b'{"error":1}', 400, "application/json", "no-store", TokenExchangeValidationError),
        (
            b'{"error":"invalid_target","extra":1}',
            400,
            "application/json",
            "no-store",
            TokenExchangeValidationError,
        ),
        (
            b'{"error":"invalid_target","error_description":1}',
            400,
            "application/json",
            "no-store",
            TokenExchangeValidationError,
        ),
        (b"not-json", 400, "application/json", "no-store", TokenExchangeValidationError),
        (b"[]", 400, "application/json", "no-store", TokenExchangeValidationError),
        (b"x" * 65_537, 200, "application/json", "no-store", TokenExchangeValidationError),
    ],
)
async def test_exchange_rejects_transport_and_error_responses(
    body: bytes,
    status: int,
    content_type: str,
    cache_control: str,
    error: type[Exception],
) -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    with pytest.raises(error):
        await TokenExchangeClient(
            profile,
            poster=_poster(body, status=status, content_type=content_type, cache_control=cache_control),
        ).exchange(TokenExchangeCredential("token", _context()), scopes=("payments:read",))


@pytest.mark.parametrize(
    "updates",
    [
        {"extra": True},
        {"refresh_token": "forbidden"},
        {"access_token": "bad token"},
        {"issued_token_type": "urn:other"},
        {"token_type": "Bearer"},
        {"expires_in": True},
        {"expires_in": 0},
        {"expires_in": 601},
        {"scope": 1},
        {"scope": "payments:read payments:read"},
        {"scope": "admin"},
    ],
)
async def test_exchange_rejects_invalid_success_schema(updates: dict[str, object]) -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding())
    with pytest.raises(TokenExchangeValidationError):
        await TokenExchangeClient(profile, poster=_poster(_response(**updates))).exchange(
            TokenExchangeCredential("token", _context()),
            scopes=("payments:read",),
        )


async def test_exchange_rejects_response_payment_widening() -> None:
    profile = _profile(verifier=_Verifier(), binding=_dpop_binding(), payment_policy=_policy())
    subject = TokenExchangeCredential("token", _context(details=_details("200.00")))
    for details in (None, _raw_details("101.00"), _raw_details("50.00", action="status")):
        with pytest.raises(TokenExchangeValidationError, match="payment"):
            await TokenExchangeClient(profile, poster=_poster(_response(details=details))).exchange(
                subject,
                scopes=("payments:write",),
                authorization_details=_details("100.00"),
            )

    binding = _dpop_binding()
    valid_output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:write",),
        details=_details("50.00"),
        thumbprint=binding.confirmation_thumbprint,
    )
    malformed_output = replace(
        valid_output,
        evidence=replace(
            valid_output.evidence,
            authorization_details=cast("Any", ({"type": PAYMENT_AUTHORIZATION_TYPE},)),
        ),
    )
    for output in (malformed_output, valid_output):
        with pytest.raises(TokenExchangeValidationError, match="payment authority"):
            await TokenExchangeClient(
                _profile(verifier=_Verifier(output), binding=binding, payment_policy=_policy()),
                poster=_poster(_response(details=_raw_details("100.00"))),
            ).exchange(
                subject,
                scopes=("payments:write",),
                authorization_details=_details("150.00"),
            )


async def test_exchange_rejects_verifier_failures_and_mismatched_context() -> None:
    binding = _dpop_binding()
    subject = TokenExchangeCredential("token", _context())
    for error in (TokenExchangeUnavailableError("offline"), TokenExchangeValidationError("invalid"), OSError()):
        profile = _profile(verifier=_Verifier(error=error), binding=binding)
        expected = type(error) if not isinstance(error, OSError) else TokenExchangeValidationError
        with pytest.raises(expected):
            await TokenExchangeClient(profile, poster=_poster(_response(scope="payments:read"))).exchange(
                subject, scopes=("payments:read",)
            )
    valid_output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:read",),
        thumbprint=binding.confirmation_thumbprint,
    )
    invalid_outputs = (
        replace(valid_output, subject=PrincipalRef(_ISSUER, "other", "service")),
        replace(valid_output, actor=PrincipalRef(_ISSUER, "other", "service")),
        _context(
            issuer="https://wrong.example",
            audience=_AUDIENCE,
            scopes=("payments:read",),
            thumbprint=binding.confirmation_thumbprint,
        ),
        _context(
            issuer=_ISSUER, audience="wrong", scopes=("payments:read",), thumbprint=binding.confirmation_thumbprint
        ),
        _context(
            issuer=_ISSUER, audience=_AUDIENCE, scopes=("payments:write",), thumbprint=binding.confirmation_thumbprint
        ),
        _context(issuer=_ISSUER, audience=_AUDIENCE, scopes=("payments:read",), thumbprint="C" * 43),
        _context(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            scopes=("payments:read",),
            thumbprint=binding.confirmation_thumbprint,
            expires_at=_NOW - timedelta(minutes=1),
            not_before=_NOW - timedelta(minutes=3),
            issued_at=_NOW - timedelta(minutes=2),
        ),
        _context(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            scopes=("payments:read",),
            thumbprint=binding.confirmation_thumbprint,
            expires_at=_NOW + timedelta(minutes=6),
        ),
        _context(
            issuer=_ISSUER,
            audience=_AUDIENCE,
            scopes=("payments:read",),
            thumbprint=binding.confirmation_thumbprint,
            issued_at=_NOW + timedelta(minutes=1),
        ),
    )
    for output in invalid_outputs:
        with pytest.raises(TokenExchangeValidationError, match=r"identity|authority"):
            await TokenExchangeClient(
                _profile(verifier=_Verifier(output), binding=binding),
                poster=_poster(_response(scope="payments:read")),
            ).exchange(subject, scopes=("payments:read",))


async def test_default_poster_is_bounded_and_maps_http_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status_code = 200
        payload = _response(token_type="DPoP", scope="payments:read")
        headers: ClassVar[_Headers] = _Headers({"content-type": "application/json", "cache-control": "no-store"})

        async def aiter_bytes(self) -> AsyncIterator[bytes]:
            yield self.payload

    class Stream:
        async def __aenter__(self) -> Response:
            return Response()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            return None

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, *_args: object, **_kwargs: object) -> Stream:
            return Stream()

    class Httpx:
        HTTPError = OSError
        AsyncClient = Client

    monkeypatch.setitem(__import__("sys").modules, "httpx", cast("Any", Httpx))
    binding = _dpop_binding()
    output = _context(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        scopes=("payments:read",),
        thumbprint=binding.confirmation_thumbprint,
    )
    result = await TokenExchangeClient(_profile(verifier=_Verifier(output), binding=binding)).exchange(
        TokenExchangeCredential("token", _context()), scopes=("payments:read",)
    )
    assert result.context is output

    class FailingClient(Client):
        async def __aenter__(self) -> Self:
            raise TimeoutError

    cast("Any", Httpx).AsyncClient = FailingClient
    with pytest.raises(TokenExchangeUnavailableError):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=binding)).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )

    cast("Any", Httpx).AsyncClient = Client
    Response.payload = b"x" * 65_537
    with pytest.raises(TokenExchangeValidationError, match="size limit"):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=binding)).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )

    Response.payload = _response(token_type="DPoP", scope="payments:read")
    Response.headers.nonce_values = ("one", "two")
    with pytest.raises(TokenExchangeValidationError, match="duplicate DPoP nonce"):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=binding)).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )

    Response.payload = b'{"error":"use_dpop_nonce"}'
    Response.status_code = 400
    Response.headers.nonce_values = ("server-nonce",)
    with pytest.raises(TokenExchangeRejectedError):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=binding)).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )

    monkeypatch.setitem(__import__("sys").modules, "httpx", None)
    with pytest.raises(TokenExchangeUnavailableError, match="request failed"):
        await TokenExchangeClient(_profile(verifier=_Verifier(), binding=binding)).exchange(
            TokenExchangeCredential("token", _context()), scopes=("payments:read",)
        )
