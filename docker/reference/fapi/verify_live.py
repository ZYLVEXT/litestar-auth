#!/usr/bin/env python3
"""Exercise the live FAPI client, authorization server, and DPoP resource server."""
# ruff: file-ignore[async-function-with-timeout, complex-structure, f-string-in-exception, magic-value-comparison, print, raise-vanilla-args, raw-string-in-exception, too-many-branches, too-many-locals, too-many-statements]

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from authweave_core import AuthorizationValue, InMemoryReplayStore
from cryptography.hazmat.primitives.asymmetric import ec

from litestar_auth.oauth.fapi import (
    FAPIIssuerProfile,
    FAPIMessageSigningClient,
    FAPIUnavailableError,
    FAPIValidationError,
)

AS_URL = "https://127.0.0.1:18444"
ISSUER = "https://fapi-as.example"
CLIENT_ID = "fapi-client"
REDIRECT_URI = "https://client.example/callback"
TOKEN_TARGET = f"{ISSUER}/oauth/token"
RS_URL = "http://127.0.0.1:18084/v1/payments"
RS_TARGET = "https://api.example/v1/payments"
CLIENT_KEY = ec.derive_private_key(7, ec.SECP256R1())
PAYMENT_DETAILS = cast(
    "tuple[dict[str, AuthorizationValue], ...]",
    (
        {
            "type": "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1",
            "actions": ["initiate"],
            "locations": [RS_TARGET],
            "instructedAmount": {"currency": "EUR", "amount": "100.00"},
            "identifier": "reference-payment",
        },
    ),
)


class Signer:
    """Reference external signer."""

    async def sign(self, *, protected_headers: dict[str, object], claims: dict[str, object]) -> str:
        return jwt.encode(claims, CLIENT_KEY, algorithm="ES256", headers=protected_headers)


class Resolver:
    """Issuer-bound key resolver populated from the configured JWKS endpoint."""

    def __init__(self, jwk: dict[str, object]) -> None:
        self.key = jwt.PyJWK.from_dict(jwk)

    async def get_key(self, kid: str, algorithm: str) -> jwt.PyJWK:
        if kid != "fapi-as-key" or algorithm != "ES256":
            raise ValueError("unknown AS key")
        return self.key


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }


def _thumbprint(jwk: dict[str, str]) -> str:
    canonical = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def _proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    htu: str,
    token: str | None = None,
    nonce: str | None = None,
) -> str:
    claims: dict[str, object] = {"htm": "POST", "htu": htu, "iat": int(time.time()), "jti": secrets.token_urlsafe(18)}
    if token is not None:
        claims["ath"] = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(claims, key, algorithm="ES256", headers={"jwk": _public_jwk(key), "typ": "dpop+jwt"})


def _assertion() -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": ISSUER,
            "iat": now,
            "exp": now + 60,
            "jti": secrets.token_urlsafe(18),
        },
        CLIENT_KEY,
        algorithm="ES256",
        headers={"kid": "fapi-client-key", "typ": "JWT"},
    )


async def _wait(client: httpx.AsyncClient) -> dict[str, object]:
    for _ in range(60):
        try:
            jwks, rs = await asyncio.gather(client.get(f"{AS_URL}/.well-known/jwks.json"), client.post(RS_URL))
            if jwks.status_code == 200 and rs.status_code in {401, 503}:
                return jwks.json()["keys"][0]
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("FAPI AS/RS reference did not become reachable")


async def main() -> int:
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        as_jwk = await _wait(http)

        async def poster(
            url: str, headers: dict[str, str], body: bytes, timeout: float, maximum: int
        ) -> tuple[int, bytes, str]:
            response = await http.post(url, headers=headers, content=body, timeout=timeout)
            if len(response.content) > maximum:
                raise FAPIValidationError("oversized PAR response")
            return response.status_code, response.content, response.headers.get("content-type", "")

        profile = FAPIIssuerProfile(
            issuer=ISSUER,
            authorization_endpoint=f"{AS_URL}/oauth/authorize",
            par_endpoint=f"{AS_URL}/oauth/par",
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            key_id="fapi-client-key",
            algorithm="ES256",
            signer=Signer(),
            key_resolver=Resolver(as_jwk),
            replay_store=InMemoryReplayStore(capacity=32, time_source=time.monotonic),
        )
        fapi = FAPIMessageSigningClient(profile, poster=poster)
        authorization = await fapi.begin(
            scopes=("openid", "payments:write"),
            authorization_details=PAYMENT_DETAILS,
        )
        redirect = await http.get(authorization.authorization_url)
        if redirect.status_code != 302:
            raise RuntimeError(f"authorization endpoint failed: {redirect.status_code} {redirect.text}")
        response = parse_qs(urlsplit(redirect.headers["location"]).query)["response"][0]

        try:
            await fapi.verify_jarm(response, expected_state="wrong-state-" + "x" * 32)
        except FAPIValidationError:
            print("ok  JARM state mismatch rejected without consuming the protocol run")
        else:
            raise RuntimeError("JARM state mismatch was accepted")
        result = await fapi.verify_jarm(response, expected_state=authorization.state)
        code = result.require_code()
        try:
            await fapi.verify_jarm(response, expected_state=authorization.state)
        except FAPIValidationError:
            print("ok  JARM replay rejected")
        else:
            raise RuntimeError("JARM replay was accepted")

        proof_key = ec.generate_private_key(ec.SECP256R1())
        token_response = await http.post(
            f"{AS_URL}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": authorization.code_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": _assertion(),
            },
            headers={"dpop": _proof(proof_key, htu=TOKEN_TARGET)},
        )
        token_response.raise_for_status()
        tokens = token_response.json()
        access_token = tokens["access_token"]
        id_token = tokens["id_token"]
        identity = await fapi.verify_id_token(id_token, expected_nonce=authorization.nonce)
        if identity.subject != "merchant-1":
            raise RuntimeError("ID token subject mismatch")
        try:
            await fapi.verify_jarm(id_token, expected_state=authorization.state)
        except FAPIValidationError:
            print("ok  cross-JWT schema confusion rejected")
        else:
            raise RuntimeError("ID token was accepted as JARM")

        replayed_code = await http.post(
            f"{AS_URL}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": authorization.code_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": _assertion(),
            },
            headers={"dpop": _proof(proof_key, htu=TOKEN_TARGET)},
        )
        if replayed_code.status_code == 200:
            raise RuntimeError("authorization code replay was accepted")
        print("ok  authorization code replay rejected")

        challenge = await http.post(
            RS_URL,
            headers={
                "authorization": f"DPoP {access_token}",
                "dpop": _proof(proof_key, htu=RS_TARGET, token=access_token),
            },
        )
        nonce = challenge.headers.get("dpop-nonce")
        if challenge.status_code != 401 or not nonce:
            raise RuntimeError("resource server did not issue a DPoP nonce")
        proof = _proof(proof_key, htu=RS_TARGET, token=access_token, nonce=nonce)
        accepted = await http.post(RS_URL, headers={"authorization": f"DPoP {access_token}", "dpop": proof})
        if accepted.status_code != 200:
            raise RuntimeError(f"valid FAPI token was rejected: {accepted.status_code} {accepted.text}")
        if accepted.json().get("payment_authorized") is not True:
            raise RuntimeError("resource server did not apply its payment authorization guard")
        print("ok  typed payment authority accepted by DPoP resource-server guard")
        if (
            await http.post(RS_URL, headers={"authorization": f"DPoP {access_token}", "dpop": proof})
        ).status_code == 200:
            raise RuntimeError("DPoP replay was accepted")
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        if (
            _thumbprint(_public_jwk(wrong_key))
            == jwt.decode(access_token, options={"verify_signature": False})["cnf"]["jkt"]
        ):
            raise RuntimeError("test key collision")
        mismatch = await http.post(
            RS_URL,
            headers={
                "authorization": f"DPoP {access_token}",
                "dpop": _proof(wrong_key, htu=RS_TARGET, token=access_token),
            },
        )
        if mismatch.status_code == 200:
            raise RuntimeError("cnf.jkt mismatch was accepted")
        print("ok  DPoP replay and cnf.jkt mismatch rejected")

        async def outage_poster(*_args: object) -> tuple[int, bytes, str]:
            try:
                await http.post("https://127.0.0.1:1/oauth/par")
            except httpx.HTTPError as exc:
                raise FAPIUnavailableError("PAR request failed") from exc
            raise RuntimeError("unreachable")

        try:
            await FAPIMessageSigningClient(profile, poster=outage_poster).begin(scopes=("openid",))
        except FAPIUnavailableError:
            print("ok  authorization-server outage fails closed")
        else:
            raise RuntimeError("authorization-server outage did not fail closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
