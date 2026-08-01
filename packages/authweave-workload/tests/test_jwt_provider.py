"""External mTLS-bound access-token profile tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import jwt
import jwt.algorithms
import pytest
from authweave_core import Authenticated, AuthenticationRuntime, FailureCode, Invalid, RequestView, TlsPeerEvidence
from authweave_workload.authorization_details import PAYMENT_AUTHORIZATION_TYPE, PaymentAuthorizationPolicy
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.jwt import MTLSBoundJWTProvider, TrustedIssuer
from authweave_workload.provider import DirectMTLSPolicy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_ISSUER = "https://issuer.test"
_AUDIENCE = "payments-api"
_KID = "signing-1"


def _fixture() -> tuple[ec.EllipticCurvePrivateKey, dict[str, object], str]:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": _KID, "alg": "ES256", "use": "sig"})
    certificate_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(certificate_der).digest()).rstrip(b"=").decode()
    return key, {"keys": [jwk]}, thumbprint


def _request(token: str, thumbprint: str, now: datetime) -> RequestView:
    return RequestView(
        method="POST",
        headers=((b"authorization", f"Bearer {token}".encode()),),
        timestamp=now,
        tls_peer=TlsPeerEvidence(
            tls_version="TLSv1.3",
            certificate_thumbprint=thumbprint,
            certificate_not_before=now - timedelta(minutes=1),
            certificate_not_after=now + timedelta(minutes=10),
            revocation_checked_at=now,
            trust_anchor="ca",
            termination_boundary="envoy",
        ),
    )


def _token(
    key: ec.EllipticCurvePrivateKey,
    thumbprint: str,
    now: datetime,
    *,
    token_type: str = "at+jwt",
    claims: dict[str, object] | None = None,
) -> str:
    payload: dict[str, object] = {
        "iss": _ISSUER,
        "sub": "service-1",
        "aud": _AUDIENCE,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": "token-1",
        "client_id": "client-1",
        "scope": "payments:read payments:write",
        "cnf": {"x5t#S256": thumbprint},
    }
    if claims:
        payload.update(claims)
    return jwt.encode(
        payload,
        key,
        algorithm="ES256",
        headers={"kid": _KID, "typ": token_type},
    )


def _payment_policy() -> PaymentAuthorizationPolicy:
    return PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"})},
        allowed_locations=frozenset({"https://api.example/payments"}),
        currency_limits={"EUR": "500.00"},
    )


def _authorization_details(*, action: str = "initiate") -> list[dict[str, object]]:
    return [
        {
            "type": PAYMENT_AUTHORIZATION_TYPE,
            "actions": [action],
            "locations": ["https://api.example/payments"],
            "instructedAmount": {"currency": "EUR", "amount": "125.50"},
        }
    ]


pytestmark = pytest.mark.unit


async def test_mtls_bound_jwt_validates_access_token_and_sender() -> None:
    key, jwks, thumbprint = _fixture()
    now = datetime.now(UTC)
    provider = MTLSBoundJWTProvider(
        name="external_access_token",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        tls_policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
    )
    token = _token(key, thumbprint, now)

    decision = await provider.authenticate(_request(token, thumbprint, now), AuthenticationRuntime())

    assert isinstance(decision, Authenticated)
    assert decision.context.subject.subject == "service-1"
    assert decision.context.evidence.token_id == "token-1"
    assert decision.context.evidence.scopes == ("payments:read", "payments:write")

    mismatch = await provider.authenticate(_request(token, "A" * 43, now), AuthenticationRuntime())
    assert mismatch == Invalid(FailureCode.SENDER_CONSTRAINT_MISMATCH)

    wrong_type = await provider.authenticate(
        _request(_token(key, thumbprint, now, token_type="JWT"), thumbprint, now),
        AuthenticationRuntime(),
    )
    assert wrong_type == Invalid(FailureCode.TOKEN_TYPE_MISMATCH)

    wrong_audience = await provider.authenticate(
        _request(_token(key, thumbprint, now, claims={"aud": "other-api"}), thumbprint, now),
        AuthenticationRuntime(),
    )
    assert wrong_audience == Invalid(FailureCode.AUDIENCE_MISMATCH)


async def test_mtls_bound_jwt_maps_typed_payment_authority_and_rejects_widening() -> None:
    """Signed JWT details are typed only under the exact issuer and scope policy."""
    key, jwks, thumbprint = _fixture()
    now = datetime.now(UTC)
    issuer = TrustedIssuer(
        issuer=_ISSUER,
        audiences=frozenset({_AUDIENCE}),
        environment="sandbox",
        jwks=BoundedJWKSClient(static_jwks=jwks),
        payment_authorization=_payment_policy(),
    )
    provider = MTLSBoundJWTProvider(
        name="payment-jwt",
        issuer=issuer,
        tls_policy=DirectMTLSPolicy(trust_anchors=frozenset({"ca"}), termination_boundaries=frozenset({"envoy"})),
    )

    valid = _token(key, thumbprint, now, claims={"authorization_details": _authorization_details()})
    decision = await provider.authenticate(_request(valid, thumbprint, now), AuthenticationRuntime())

    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.authorization_details[0]["type"] == PAYMENT_AUTHORIZATION_TYPE
    widened = _token(key, thumbprint, now, claims={"authorization_details": _authorization_details(action="refund")})
    assert await provider.authenticate(_request(widened, thumbprint, now), AuthenticationRuntime()) == Invalid(
        FailureCode.INVALID
    )
    missing = _token(key, thumbprint, now)
    assert await provider.authenticate(_request(missing, thumbprint, now), AuthenticationRuntime()) == Invalid(
        FailureCode.INVALID
    )


async def test_mtls_bound_jwt_evidence_contains_only_signed_trusted_audiences() -> None:
    key, jwks, thumbprint = _fixture()
    now = datetime.now(UTC)
    provider = MTLSBoundJWTProvider(
        name="external_access_token",
        issuer=TrustedIssuer(
            issuer=_ISSUER,
            audiences=frozenset({_AUDIENCE, "reports-api"}),
            environment="sandbox",
            jwks=BoundedJWKSClient(static_jwks=jwks),
        ),
        tls_policy=DirectMTLSPolicy(
            trust_anchors=frozenset({"ca"}),
            termination_boundaries=frozenset({"envoy"}),
        ),
    )

    decision = await provider.authenticate(
        _request(_token(key, thumbprint, now, claims={"aud": "reports-api"}), thumbprint, now),
        AuthenticationRuntime(),
    )

    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.audiences == ("reports-api",)
    untrusted_extra = _token(key, thumbprint, now, claims={"aud": ["reports-api", "untrusted-api"]})
    assert await provider.authenticate(
        _request(untrusted_extra, thumbprint, now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.AUDIENCE_MISMATCH)


async def test_unknown_kid_refresh_is_bounded() -> None:
    _key, jwks, _thumbprint = _fixture()
    calls = 0

    async def fetcher(_url: str, _timeout: float, _maximum: int) -> dict[str, object]:
        nonlocal calls
        await asyncio.sleep(0)
        calls += 1
        return jwks

    client = BoundedJWKSClient(url="https://issuer.test/jwks", fetcher=fetcher)
    with pytest.raises(ValueError, match="unknown"):
        await client.get_key("unknown", "ES256")
    with pytest.raises(ValueError, match="unknown"):
        await client.get_key("unknown", "ES256")
    assert calls == 1
