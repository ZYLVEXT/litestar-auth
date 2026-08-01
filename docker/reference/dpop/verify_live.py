#!/usr/bin/env python3
"""Exercise an external test AS/JWKS and the live multi-worker DPoP RS."""
# ruff: file-ignore[f-string-in-exception, hardcoded-password-string, print, raise-vanilla-args, raw-string-in-exception, too-many-arguments]

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec

AS_TOKEN_URL = "http://127.0.0.1:18082/oauth/token"
AS_EXTERNAL_TOKEN_TARGET = "https://as.example/oauth/token"
RS_URL = "http://127.0.0.1:18081/v1/payments"
RS_EXTERNAL_TARGET = "https://api.example/v1/payments"
_HTTP_OK = 200
_HTTP_UNAUTHORIZED = 401


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
    htm: str,
    htu: str,
    access_token: str | None = None,
    nonce: str | None = None,
    ath: str | None = None,
) -> str:
    claims: dict[str, object] = {
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(18),
    }
    if access_token is not None:
        claims["ath"] = (
            ath or base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).rstrip(b"=").decode()
        )
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(
        claims,
        key,
        algorithm="ES256",
        headers={"jwk": _public_jwk(key), "typ": "dpop+jwt"},
    )


async def _wait(client: httpx.AsyncClient) -> None:
    for _ in range(60):
        try:
            as_response, rs_response = await asyncio.gather(
                client.get("http://127.0.0.1:18082/.well-known/jwks.json"),
                client.post(RS_URL),
            )
            if as_response.status_code == _HTTP_OK and rs_response.status_code in {_HTTP_UNAUTHORIZED, 503}:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("DPoP AS/RS reference did not become reachable")


async def _issue_token(client: httpx.AsyncClient, key: ec.EllipticCurvePrivateKey) -> str:
    response = await client.post(
        AS_TOKEN_URL,
        content=b"grant_type=client_credentials",
        headers={"dpop": _proof(key, htm="POST", htu=AS_EXTERNAL_TOKEN_TARGET)},
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if payload.get("token_type") != "DPoP" or not isinstance(token, str):
        raise RuntimeError("test AS returned a non-DPoP token response")
    claims = jwt.decode(token, options={"verify_signature": False})
    if claims.get("cnf") != {"jkt": _thumbprint(_public_jwk(key))}:
        raise RuntimeError("test AS did not bind cnf.jkt to the token-endpoint proof")
    return token


async def _challenge(
    client: httpx.AsyncClient,
    key: ec.EllipticCurvePrivateKey,
    access_token: str,
) -> str:
    response = await client.post(
        RS_URL,
        headers={
            "authorization": f"DPoP {access_token}",
            "dpop": _proof(key, htm="POST", htu=RS_EXTERNAL_TARGET, access_token=access_token),
        },
    )
    if response.status_code != _HTTP_UNAUTHORIZED or "use_dpop_nonce" not in response.headers.get(
        "www-authenticate", ""
    ):
        raise RuntimeError(f"RS did not issue a nonce challenge: {response.status_code} {response.text}")
    nonce = response.headers.get("dpop-nonce")
    if not nonce or response.headers.get("cache-control") != "no-store":
        raise RuntimeError("RS nonce challenge headers are incomplete")
    return nonce


async def _present(
    client: httpx.AsyncClient,
    *,
    token: str,
    proof: str,
) -> httpx.Response:
    return await client.post(RS_URL, headers={"authorization": f"DPoP {token}", "dpop": proof})


def _expect_rejected(label: str, response: httpx.Response) -> None:
    if response.status_code == _HTTP_OK:
        raise RuntimeError(f"{label} was accepted")
    print(f"ok  live {label} rejected")


async def main() -> int:
    async with httpx.AsyncClient(timeout=15.0) as client:
        await _wait(client)
        proof_key = ec.generate_private_key(ec.SECP256R1())
        access_token = await _issue_token(client, proof_key)
        print("ok  external test AS issued a cnf.jkt-bound DPoP token")

        nonce = await _challenge(client, proof_key, access_token)
        valid_proof = _proof(
            proof_key,
            htm="POST",
            htu=RS_EXTERNAL_TARGET,
            access_token=access_token,
            nonce=nonce,
        )
        accepted = await _present(client, token=access_token, proof=valid_proof)
        if accepted.status_code != _HTTP_OK:
            raise RuntimeError(f"valid external-AS presentation failed: {accepted.status_code} {accepted.text}")
        print("ok  live multi-worker RS accepted external-AS token and proof")
        _expect_rejected("replay", await _present(client, token=access_token, proof=valid_proof))

        cases: list[tuple[str, ec.EllipticCurvePrivateKey, dict[str, Any]]] = [
            ("wrong htu", proof_key, {"htu": "https://evil.example/v1/payments"}),
            ("wrong htm", proof_key, {"htm": "GET"}),
            ("wrong ath", proof_key, {"ath": "A" * 43}),
            ("wrong nonce", proof_key, {"nonce": "A" * 43}),
        ]
        for label, key, overrides in cases:
            fresh_nonce = await _challenge(client, key, access_token)
            arguments: dict[str, Any] = {
                "htm": "POST",
                "htu": RS_EXTERNAL_TARGET,
                "access_token": access_token,
                "nonce": fresh_nonce,
                **overrides,
            }
            _expect_rejected(
                label,
                await _present(client, token=access_token, proof=_proof(key, **arguments)),
            )

        other_key = ec.generate_private_key(ec.SECP256R1())
        other_nonce = await _challenge(client, other_key, access_token)
        _expect_rejected(
            "cnf.jkt mismatch",
            await _present(
                client,
                token=access_token,
                proof=_proof(
                    other_key,
                    htm="POST",
                    htu=RS_EXTERNAL_TARGET,
                    access_token=access_token,
                    nonce=other_nonce,
                ),
            ),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
