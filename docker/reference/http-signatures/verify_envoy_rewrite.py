#!/usr/bin/env python3
"""Exercise DPoP authentication, identity binding, and Envoy message integrity."""
# ruff: file-ignore[f-string-in-exception, print, raise-vanilla-args, raw-string-in-exception, too-many-locals]

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import jwt
from authweave_http_signatures import HttpMessageView, PaymentSignaturePolicy, sign_payment_message
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_TARGET = "https://payments.example/v1/payments"
_AS_TOKEN = "http://127.0.0.1:18083/oauth/token"  # ruff: ignore[hardcoded-password-string] - OAuth endpoint URL, not a credential.
_AS_TOKEN_OTHER = "http://127.0.0.1:18083/oauth/token/other"  # ruff: ignore[hardcoded-password-string] - OAuth endpoint URL, not a credential.
_AS_TARGET = "https://as.example/oauth/token"
_AS_TARGET_OTHER = "https://as.example/oauth/token/other"
_ENVOY = "http://127.0.0.1:18080/v1/payments"
_HTTP_OK = 200
_EXPECTED_ARGC = 2


def _proof_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }


def _dpop_proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    target: str,
    access_token: str | None = None,
) -> str:
    claims: dict[str, object] = {
        "htm": "POST",
        "htu": target,
        "iat": int(time.time()),
        "jti": secrets.token_urlsafe(18),
    }
    if access_token is not None:
        claims["ath"] = (
            base64
            .urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest())
            .rstrip(
                b"=",
            )
            .decode()
        )
    return jwt.encode(
        claims,
        key,
        algorithm="ES256",
        headers={"jwk": _proof_jwk(key), "typ": "dpop+jwt"},
    )


async def _issue_token(
    client: httpx.AsyncClient,
    key: ec.EllipticCurvePrivateKey,
    *,
    alternate_identity: bool = False,
) -> str:
    endpoint = _AS_TOKEN_OTHER if alternate_identity else _AS_TOKEN
    target = _AS_TARGET_OTHER if alternate_identity else _AS_TARGET
    response = await client.post(
        endpoint,
        content=b"grant_type=client_credentials",
        headers={"dpop": _dpop_proof(key, target=target)},
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if payload.get("token_type") != "DPoP" or not isinstance(token, str):
        raise RuntimeError("test AS did not issue a DPoP token")
    return token


def _signed_headers(
    payment_key: Ed25519PrivateKey,
    proof_key: ec.EllipticCurvePrivateKey,
    access_token: str,
    *,
    body: bytes,
    nonce: str,
) -> dict[str, str]:
    authorization = f"DPoP {access_token}"
    view = HttpMessageView(
        method="POST",
        target_uri=_TARGET,
        headers=(
            ("content-type", "application/json"),
            ("idempotency-key", f"idem-{nonce}"),
            ("authorization", authorization),
        ),
        body=body,
    )
    now = datetime.now(tz=UTC)
    signed = sign_payment_message(
        view=view,
        policy=PaymentSignaturePolicy(require_authorization_component=True),
        key_id="merchant-key-1",
        private_key=payment_key,
        nonce=nonce,
        now=now,
        lifetime=timedelta(seconds=300),
    )
    return {
        **dict(signed.headers),
        "dpop": _dpop_proof(proof_key, target=_TARGET, access_token=access_token),
    }


async def _wait_for_stack(client: httpx.AsyncClient) -> None:
    for _ in range(90):
        try:
            jwks, envoy = await asyncio.gather(
                client.get("http://127.0.0.1:18083/.well-known/jwks.json"),
                client.post(_ENVOY, content=b"{}"),
            )
            if jwks.status_code == _HTTP_OK and envoy.status_code == httpx.codes.UNAUTHORIZED:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    raise RuntimeError("HTTP-signature DPoP/Envoy stack did not become ready")


def _expect_rejected(label: str, response: httpx.Response) -> None:
    if response.status_code == _HTTP_OK:
        raise RuntimeError(f"{label} was accepted")
    print(f"ok  {label} rejected")


async def main() -> int:
    if len(sys.argv) != _EXPECTED_ARGC:
        print("usage: verify_envoy_rewrite.py <runtime-dir>", file=sys.stderr)
        return 2
    payment_key = Ed25519PrivateKey.from_private_bytes((Path(sys.argv[1]) / "payment_private.der").read_bytes())
    proof_key = ec.generate_private_key(ec.SECP256R1())
    body = b'{"amount":"1.00","currency":"USD"}'

    async with httpx.AsyncClient(timeout=15.0) as client:
        await _wait_for_stack(client)
        token = await _issue_token(client, proof_key)

        valid = _signed_headers(payment_key, proof_key, token, body=body, nonce="valid-1")
        accepted = await client.post(_ENVOY, content=body, headers=valid)
        if accepted.status_code != _HTTP_OK:
            raise RuntimeError(f"valid DPoP + signature request failed: {accepted.status_code} {accepted.text}")
        payload = accepted.json()
        if payload.get("subject") != "payments-worker" or payload.get("key_id") != "merchant-key-1":
            raise RuntimeError("verified response did not retain authenticated identity and signing key")
        print("ok  DPoP authentication -> HTTP signature identity binding")

        spoof = _signed_headers(payment_key, proof_key, token, body=body, nonce="host-spoof")
        spoof["host"] = "evil.example"
        host_response = await client.post(_ENVOY, content=body, headers=spoof)
        if host_response.status_code != _HTTP_OK:
            raise RuntimeError(f"host spoof changed trusted target: {host_response.status_code}")
        print("ok  client Host ignored by trusted target projection")

        forged = _signed_headers(payment_key, proof_key, token, body=body, nonce="target-forgery")
        forged["x-auth-external-target"] = "https://evil.example/v1/payments"
        forged_response = await client.post(_ENVOY, content=body, headers=forged)
        if forged_response.status_code != _HTTP_OK:
            raise RuntimeError(f"Envoy did not replace forged target: {forged_response.status_code}")
        print("ok  forged external-target header stripped by Envoy")

        mutation = _signed_headers(payment_key, proof_key, token, body=body, nonce="body-mutation")
        _expect_rejected(
            "raw body mutation",
            await client.post(_ENVOY, content=b'{"amount":"9.99","currency":"USD"}', headers=mutation),
        )

        replay_headers = _signed_headers(payment_key, proof_key, token, body=body, nonce="signature-replay")
        first = await client.post(_ENVOY, content=body, headers=replay_headers)
        if first.status_code != _HTTP_OK:
            raise RuntimeError("signature replay setup request failed")
        replay_headers["dpop"] = _dpop_proof(proof_key, target=_TARGET, access_token=token)
        _expect_rejected(
            "signature nonce replay with fresh DPoP proof",
            await client.post(_ENVOY, content=body, headers=replay_headers),
        )

        other_token = await _issue_token(client, proof_key, alternate_identity=True)
        mismatched = _signed_headers(payment_key, proof_key, other_token, body=body, nonce="identity-mismatch")
        _expect_rejected(
            "authenticated identity/signing-key mismatch", await client.post(_ENVOY, content=body, headers=mismatched)
        )

        missing_proof = _signed_headers(payment_key, proof_key, token, body=body, nonce="missing-proof")
        del missing_proof["dpop"]
        _expect_rejected("missing DPoP proof", await client.post(_ENVOY, content=body, headers=missing_proof))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
