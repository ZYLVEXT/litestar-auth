"""External test Authorization Server issuing RFC 9449-bound access tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ec

_ISSUER = os.environ.get("AS_ISSUER", "https://as.example")
_AUDIENCE = os.environ.get("AS_AUDIENCE", "payments-api")
_TOKEN_TARGET = os.environ.get("AS_TOKEN_TARGET", f"{_ISSUER}/oauth/token")
_CLIENT_ID = os.environ.get("AS_CLIENT_ID", "reference-dpop-client")
_SUBJECT = os.environ.get("AS_SUBJECT", "reference-merchant-workload")
_ALTERNATE_TOKEN_TARGET = os.environ.get("AS_ALTERNATE_TOKEN_TARGET", f"{_ISSUER}/oauth/token/other")
_ALTERNATE_CLIENT_ID = os.environ.get("AS_ALTERNATE_CLIENT_ID", "other-reference-client")
_ALTERNATE_SUBJECT = os.environ.get("AS_ALTERNATE_SUBJECT", "other-reference-workload")
_KEY_ID = "reference-as-1"
_PROOF_WINDOW_SECONDS = 90
_SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())


def _b64uint(value: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()


_PUBLIC_NUMBERS = _SIGNING_KEY.public_key().public_numbers()
_PUBLIC_JWK: dict[str, str] = {
    "alg": "ES256",
    "crv": "P-256",
    "kid": _KEY_ID,
    "kty": "EC",
    "use": "sig",
    "x": _b64uint(_PUBLIC_NUMBERS.x),
    "y": _b64uint(_PUBLIC_NUMBERS.y),
}


type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Serve a network JWKS and a minimal client-credentials token endpoint."""
    if scope["type"] != "http":
        return
    method = str(scope.get("method", "GET"))
    path = str(scope.get("path", ""))
    if method == "GET" and path == "/.well-known/jwks.json":
        await _respond(send, 200, {"keys": [_PUBLIC_JWK]})
        return
    if method != "POST" or path not in {"/oauth/token", "/oauth/token/other"}:
        await _respond(send, 404, {"error": "not_found"})
        return
    await _read_body(receive)
    proof_values = _header_values(scope, b"dpop")
    if len(proof_values) != 1:
        await _respond(send, 400, {"error": "invalid_dpop_proof"})
        return
    try:
        alternate = path == "/oauth/token/other"
        expected_target = _ALTERNATE_TOKEN_TARGET if alternate else _TOKEN_TARGET
        jkt = _proof_jkt(proof_values[0].decode("ascii"), expected_target=expected_target)
    except (KeyError, TypeError, ValueError, UnicodeError, jwt.PyJWTError):
        await _respond(send, 400, {"error": "invalid_dpop_proof"})
        return
    issued_at = int(time.time())
    access_token = jwt.encode(
        {
            "aud": _AUDIENCE,
            "client_id": _ALTERNATE_CLIENT_ID if alternate else _CLIENT_ID,
            "cnf": {"jkt": jkt},
            "exp": issued_at + 300,
            "iat": issued_at,
            "iss": _ISSUER,
            "jti": secrets.token_urlsafe(18),
            "scope": "payments:write",
            "sub": _ALTERNATE_SUBJECT if alternate else _SUBJECT,
        },
        _SIGNING_KEY,
        algorithm="ES256",
        headers={"kid": _KEY_ID, "typ": "at+jwt"},
    )
    await _respond(
        send,
        200,
        {"access_token": access_token, "expires_in": 300, "token_type": "DPoP"},
        headers=[(b"cache-control", b"no-store")],
    )


def _header_values(scope: dict[str, Any], name: bytes) -> list[bytes]:
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, (list, tuple)):
        return []
    return [
        value
        for key, value in raw_headers
        if isinstance(key, bytes) and isinstance(value, bytes) and key.lower() == name
    ]


def _proof_jkt(proof: str, *, expected_target: str) -> str:
    """Validate a token-endpoint proof and return its JWK thumbprint.

    Returns:
        The RFC 7638 base64url thumbprint.

    Raises:
        ValueError: If the proof profile or request binding is invalid.
    """
    header = jwt.get_unverified_header(proof)
    jwk = header["jwk"]
    if not isinstance(jwk, dict) or header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or "d" in jwk:
        raise ValueError
    key = cast("ec.EllipticCurvePublicKey", jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk)))
    claims = jwt.decode(
        proof,
        key,
        algorithms=["ES256"],
        options={"require": ["jti", "htm", "htu", "iat"], "verify_iat": False},
    )
    now = int(time.time())
    invalid_binding = (
        claims["htm"] != "POST" or claims["htu"] != expected_target or abs(now - claims["iat"]) > _PROOF_WINDOW_SECONDS
    )
    if invalid_binding:
        raise ValueError
    return _thumbprint(jwk)


def _thumbprint(jwk: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


async def _read_body(receive: Receive) -> None:
    while True:
        message = await receive()
        if message["type"] != "http.request" or not message.get("more_body"):
            return


async def _respond(
    send: Send,
    status: int,
    payload: dict[str, object],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), *(headers or [])],
        },
    )
    await send({"type": "http.response.body", "body": body})
