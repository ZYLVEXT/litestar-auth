#!/usr/bin/env python3
"""Exercise the real outbound RFC 8693 client against the HTTPS STS."""
# ruff: file-ignore[async-function-with-timeout, magic-value-comparison, print, raise-vanilla-args, raw-string-in-exception]

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import ssl
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import httpx
import jwt
import jwt.algorithms
from authweave_core import AuthenticationContext, AuthenticationEvidence, PrincipalRef
from authweave_workload.authorization_details import PaymentAuthorizationDetail, PaymentAuthorizationPolicy
from authweave_workload.token_exchange import (
    DPoPTokenEndpointBinding,
    MTLSTokenEndpointBinding,
    PrivateKeyJWTClientAuth,
    TokenExchangeClient,
    TokenExchangeCredential,
    TokenExchangeProfile,
    TokenExchangeRejectedError,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

if TYPE_CHECKING:
    from collections.abc import Mapping

ENDPOINT = "https://127.0.0.1:18444/oauth/token"
MTLS_ENDPOINT = "https://127.0.0.1:18445/oauth/token"
ISSUER = "https://sts.example"
SOURCE_ISSUER = "https://issuer.example"
SOURCE_AUDIENCE = "frontend-api"
RESOURCE = "https://backend.example/v1/payments"
AUDIENCE = "backend-api"
CLIENT_SIGNING_KEY = ec.derive_private_key(13, ec.SECP256R1())
STS_KEY = ec.derive_private_key(17, ec.SECP256R1()).public_key()
DPOP_KEY = ec.derive_private_key(19, ec.SECP256R1())


class Signer:
    """Keep signing keys outside AuthWeave's client objects."""

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key

    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        return jwt.encode(dict(claims), self.key, algorithm="ES256", headers=cast("Any", dict(protected_headers)))


class Verifier:
    """Verify the actual STS JWT and return the normalized context."""

    async def verify(
        self,
        access_token: str,
        *,
        token_type: str,
        confirmation_thumbprint: str,
    ) -> AuthenticationContext:
        if token_type not in {"DPoP", "Bearer"} or jwt.get_unverified_header(access_token) != {
            "alg": "ES256",
            "kid": "sts-signing",
            "typ": "at+jwt",
        }:
            raise ValueError("issued token header mismatch")
        claims = jwt.decode(
            access_token,
            STS_KEY,
            algorithms=["ES256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["sub", "act", "iat", "nbf", "exp", "scope", "cnf", "authorization_details"]},
        )
        member = "jkt" if token_type == "DPoP" else "x5t#S256"  # ruff: ignore[hardcoded-password-string] - Public OAuth token type.
        if claims["cnf"] != {member: confirmation_thumbprint} or claims["act"] != {"sub": "actor-1"}:
            raise ValueError("issued token binding mismatch")
        subject = PrincipalRef(ISSUER, claims["sub"], "service")
        actor = PrincipalRef(ISSUER, claims["act"]["sub"], "service")
        return AuthenticationContext(
            subject=subject,
            actor=actor,
            delegation_chain=(actor,),
            evidence=AuthenticationEvidence(
                provider="reference-sts",
                profile="token_exchange",
                method="jwt",
                issuer=claims["iss"],
                audiences=(claims["aud"],),
                scopes=tuple(claims["scope"].split()),
                issued_at=datetime.fromtimestamp(claims["iat"], tz=UTC),
                not_before=datetime.fromtimestamp(claims["nbf"], tz=UTC),
                expires_at=datetime.fromtimestamp(claims["exp"], tz=UTC),
                confirmation_thumbprint=claims["cnf"][member],
                authorization_details=tuple(claims["authorization_details"]),
            ),
        )


def _context(subject: str, *, details: tuple[PaymentAuthorizationDetail, ...] = ()) -> AuthenticationContext:
    principal = PrincipalRef(SOURCE_ISSUER, subject, "service")
    now = datetime.now(UTC)
    return AuthenticationContext(
        subject=principal,
        actor=principal,
        evidence=AuthenticationEvidence(
            provider="reference-source",
            profile="jwt",
            method="jwt",
            issuer=SOURCE_ISSUER,
            audiences=(SOURCE_AUDIENCE,),
            scopes=("payments:write",),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            confirmation_thumbprint="A" * 43,
            authorization_details=tuple(detail.as_evidence() for detail in details),
        ),
    )


def _payment(amount: str) -> tuple[PaymentAuthorizationDetail, ...]:
    return (
        PaymentAuthorizationDetail(
            actions=cast("Any", ("initiate",)),
            locations=(RESOURCE,),
            currency="EUR",
            amount=Decimal(amount),
            identifier="payment-1",
        ),
    )


async def _post(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
    maximum: int,
) -> tuple[int, bytes, dict[str, str]]:
    async with httpx.AsyncClient(verify=os.environ["CA_CERT"], follow_redirects=False, timeout=timeout) as client:
        response = await client.post(url, headers=dict(headers), content=body)
    return response.status_code, response.content[: maximum + 1], dict(response.headers)


async def _post_mtls(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
    maximum: int,
) -> tuple[int, bytes, dict[str, str]]:
    tls = ssl.create_default_context(cafile=os.environ["CA_CERT"])
    tls.load_cert_chain(os.environ["CLIENT_CERT"], os.environ["CLIENT_KEY"])
    async with httpx.AsyncClient(
        verify=tls,
        follow_redirects=False,
        timeout=timeout,
    ) as client:
        response = await client.post(url, headers=dict(headers), content=body)
    return response.status_code, response.content[: maximum + 1], dict(response.headers)


def _certificate_thumbprint() -> str:
    certificate = x509.load_pem_x509_certificate(Path(os.environ["CLIENT_CERT"]).read_bytes())
    digest = certificate.fingerprint(hashes.SHA256())
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def _wait() -> None:
    async with httpx.AsyncClient(verify=os.environ["CA_CERT"], timeout=2) as client:
        for _ in range(60):
            try:
                if (await client.get("https://127.0.0.1:18444/.well-known/jwks.json")).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    raise RuntimeError("token exchange reference did not become reachable")


async def main() -> int:
    await _wait()
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(DPOP_KEY.public_key()))
    binding = DPoPTokenEndpointBinding(Signer(DPOP_KEY), public_jwk, "ES256")
    policy = PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"})},
        allowed_locations=frozenset({RESOURCE}),
        currency_limits={"EUR": "1000.00"},
        required=True,
    )
    profile = TokenExchangeProfile(
        endpoint=ENDPOINT,
        issuer=ISSUER,
        source_issuer=SOURCE_ISSUER,
        source_audience=SOURCE_AUDIENCE,
        resource=RESOURCE,
        audience=AUDIENCE,
        client_auth=PrivateKeyJWTClientAuth(
            client_id="exchange-client",
            audience=ENDPOINT,
            key_id="client-key",
            algorithm="ES256",
            signer=Signer(CLIENT_SIGNING_KEY),
            jti_source=lambda: secrets.token_urlsafe(18),
        ),
        sender_binding=binding,
        verifier=Verifier(),
        allowed_scopes=frozenset({"payments:write"}),
        payment_authorization=policy,
    )
    result = await TokenExchangeClient(profile, poster=_post).exchange(
        TokenExchangeCredential("subject-token", _context("subject-1", details=_payment("100.00"))),
        actor=TokenExchangeCredential("actor-token", _context("actor-1")),
        scopes=("payments:write",),
        authorization_details=_payment("50.00"),
    )
    if result.context.actor.subject != "actor-1" or result.context.evidence.authorization_details != tuple(
        detail.as_evidence() for detail in _payment("50.00")
    ):
        raise RuntimeError("verified exchange context mismatch")
    print("ok  private_key_jwt + DPoP nonce + direct actor + narrowed payment authority accepted")

    certificate_thumbprint = _certificate_thumbprint()
    mtls_profile = replace(
        profile,
        endpoint=MTLS_ENDPOINT,
        client_auth=replace(profile.client_auth, audience=MTLS_ENDPOINT),
        sender_binding=MTLSTokenEndpointBinding(certificate_thumbprint),
    )
    mtls_result = await TokenExchangeClient(mtls_profile, poster=_post_mtls).exchange(
        TokenExchangeCredential("subject-token", _context("subject-1", details=_payment("100.00"))),
        actor=TokenExchangeCredential("actor-token", _context("actor-1")),
        scopes=("payments:write",),
        authorization_details=_payment("50.00"),
    )
    if (
        mtls_result.token_type != "Bearer"  # ruff: ignore[hardcoded-password-string] - Public OAuth token type.
        or mtls_result.context.evidence.confirmation_thumbprint != certificate_thumbprint
    ):
        raise RuntimeError("mTLS-bound exchange context mismatch")
    print("ok  private_key_jwt + TLS client certificate + certificate-bound output accepted")

    try:
        async with httpx.AsyncClient(verify=os.environ["CA_CERT"], timeout=5) as client:
            await client.post(MTLS_ENDPOINT, data={"grant_type": "client_credentials"})
    except httpx.HTTPError:
        print("ok  mTLS endpoint rejects clients without a trusted certificate")
    else:
        raise RuntimeError("mTLS endpoint accepted a client without a certificate")

    async with httpx.AsyncClient(verify=os.environ["CA_CERT"], timeout=5) as client:
        rejected = await client.post(ENDPOINT, data={"grant_type": "client_credentials"})
    if rejected.status_code != 400 or rejected.json().get("error") != "invalid_request":
        raise RuntimeError("STS accepted an unauthenticated or non-exchange request")
    print("ok  STS rejects unauthenticated and non-exchange requests")

    replay_profile = replace(
        profile,
        client_auth=PrivateKeyJWTClientAuth(
            client_id="exchange-client",
            audience=ENDPOINT,
            key_id="client-key",
            algorithm="ES256",
            signer=Signer(CLIENT_SIGNING_KEY),
            jti_source=lambda: secrets.token_urlsafe(18),
        ),
        sender_binding=DPoPTokenEndpointBinding(
            Signer(DPOP_KEY), public_jwk, "ES256", jti_source=lambda: "replayed-proof"
        ),
    )
    replay_client = TokenExchangeClient(replay_profile, poster=_post)
    credentials = (
        TokenExchangeCredential("subject-token", _context("subject-1", details=_payment("100.00"))),
        TokenExchangeCredential("actor-token", _context("actor-1")),
    )
    await replay_client.exchange(
        credentials[0], actor=credentials[1], scopes=("payments:write",), authorization_details=_payment("50.00")
    )
    try:
        await replay_client.exchange(
            credentials[0], actor=credentials[1], scopes=("payments:write",), authorization_details=_payment("50.00")
        )
    except TokenExchangeRejectedError:
        print("ok  STS rejects DPoP replay")
    else:
        raise RuntimeError("STS accepted a replayed DPoP proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
