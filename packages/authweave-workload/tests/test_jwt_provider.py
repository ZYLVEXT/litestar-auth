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
    audience: str | list[str] = _AUDIENCE,
) -> str:
    return jwt.encode(
        {
            "iss": _ISSUER,
            "sub": "service-1",
            "aud": audience,
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": "token-1",
            "client_id": "client-1",
            "scope": "payments:read payments:write",
            "cnf": {"x5t#S256": thumbprint},
        },
        key,
        algorithm="ES256",
        headers={"kid": _KID, "typ": token_type},
    )


@pytest.mark.asyncio
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
        _request(_token(key, thumbprint, now, audience="other-api"), thumbprint, now),
        AuthenticationRuntime(),
    )
    assert wrong_audience == Invalid(FailureCode.AUDIENCE_MISMATCH)


@pytest.mark.asyncio
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
        _request(_token(key, thumbprint, now, audience="reports-api"), thumbprint, now),
        AuthenticationRuntime(),
    )

    assert isinstance(decision, Authenticated)
    assert decision.context.evidence.audiences == ("reports-api",)
    untrusted_extra = _token(key, thumbprint, now, audience=["reports-api", "untrusted-api"])
    assert await provider.authenticate(
        _request(untrusted_extra, thumbprint, now),
        AuthenticationRuntime(),
    ) == Invalid(FailureCode.AUDIENCE_MISMATCH)


@pytest.mark.asyncio
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
