#!/usr/bin/env python3
"""Exercise the HTTPS AS, signed introspection, opaque DPoP, and Redis replay."""
# ruff: file-ignore[print, raise-vanilla-args, raw-string-in-exception]

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time

import httpx
import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ec

AS_URL = "https://127.0.0.1:18443"
AS_TARGET = "https://authorization-server:8443/oauth/token"
RS_URL = "http://127.0.0.1:18083/v1/payments"
RS_TARGET = "https://api.example/v1/payments"
_HTTP_OK = 200
_HTTP_UNAUTHORIZED = 401
_HTTP_UNAVAILABLE = 503


def _jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    return json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))


def _proof(key: ec.EllipticCurvePrivateKey, *, target: str, token: str | None = None) -> str:
    claims: dict[str, object] = {
        "htm": "POST",
        "htu": target,
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(18),
    }
    if token is not None:
        claims["ath"] = base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
    return jwt.encode(claims, key, algorithm="ES256", headers={"jwk": _jwk(key), "typ": "dpop+jwt"})


async def _wait(client: httpx.AsyncClient) -> None:
    for _ in range(60):
        try:
            responses = await asyncio.gather(client.get(f"{AS_URL}/.well-known/jwks.json"), client.post(RS_URL))
            if responses[0].status_code == _HTTP_OK and responses[1].status_code in {
                _HTTP_UNAUTHORIZED,
                _HTTP_UNAVAILABLE,
            }:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("introspection reference did not become reachable")


async def main() -> int:
    async with httpx.AsyncClient(timeout=15) as client:
        await _wait(client)
        unauthenticated = await client.post(
            f"{AS_URL}/oauth/introspect",
            headers={"accept": "application/token-introspection+jwt"},
            data={"token": "unknown"},
        )
        if unauthenticated.status_code != _HTTP_UNAUTHORIZED:
            raise RuntimeError("AS accepted unauthenticated introspection")
        print("ok  AS rejects unauthenticated introspection")

        key = ec.generate_private_key(ec.SECP256R1())
        issued = await client.post(
            f"{AS_URL}/oauth/token",
            headers={"dpop": _proof(key, target=AS_TARGET)},
            data={"grant_type": "client_credentials"},
        )
        issued.raise_for_status()
        token = issued.json()["access_token"]
        proof = _proof(key, target=RS_TARGET, token=token)
        accepted = await client.post(RS_URL, headers={"authorization": f"DPoP {token}", "dpop": proof})
        if accepted.status_code != _HTTP_OK or accepted.json().get("profile") != "dpop_bound_introspection":
            msg = f"valid opaque DPoP presentation failed: {accepted.status_code} {accepted.text}"
            raise RuntimeError(msg)
        print("ok  private_key_jwt + RFC 9701 + opaque DPoP accepted")

        replay = await client.post(RS_URL, headers={"authorization": f"DPoP {token}", "dpop": proof})
        if replay.status_code != _HTTP_UNAUTHORIZED:
            raise RuntimeError("DPoP proof replay was accepted")
        print("ok  Redis rejects proof replay across workers")

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        mismatch = await client.post(
            RS_URL,
            headers={"authorization": f"DPoP {token}", "dpop": _proof(wrong_key, target=RS_TARGET, token=token)},
        )
        if mismatch.status_code != _HTTP_UNAUTHORIZED:
            raise RuntimeError("cnf.jkt mismatch was accepted")
        print("ok  cnf.jkt mismatch rejected")

        inactive = "unknown-opaque-token"
        rejected = await client.post(
            RS_URL,
            headers={"authorization": f"DPoP {inactive}", "dpop": _proof(key, target=RS_TARGET, token=inactive)},
        )
        if rejected.status_code != _HTTP_UNAUTHORIZED:
            raise RuntimeError("inactive opaque token was accepted")
        print("ok  inactive opaque token rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
