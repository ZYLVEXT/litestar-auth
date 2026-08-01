"""Independent HTTPS AS fixture for signed opaque-token introspection."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any, cast
from urllib.parse import parse_qs

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ec

_ISSUER = "https://authorization-server:8443"
_AUDIENCE = "payments-api"
_CLIENT_ID = "reference-resource-server"
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_MEDIA_TYPE = "application/token-introspection+jwt"
_PROOF_WINDOW_SECONDS = 90
_AS_KEY = ec.derive_private_key(2, ec.SECP256R1())
_CLIENT_KEY = ec.derive_private_key(3, ec.SECP256R1())
_TOKENS: dict[str, tuple[str, int]] = {}
_ASSERTION_JTIS: set[str] = set()

type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Issue DPoP-bound opaque tokens and serve authenticated RFC 9701 responses."""
    if scope["type"] != "http":
        return
    method = str(scope.get("method", "GET"))
    path = str(scope.get("path", ""))
    if method == "GET" and path == "/.well-known/jwks.json":
        await _json(send, 200, {"keys": [_public_jwk(_AS_KEY, kid="as-signing")]})
        return
    body = await _read_body(receive)
    if method == "POST" and path == "/oauth/token":
        await _token(scope, send)
        return
    if method == "POST" and path == "/oauth/introspect":
        await _introspect(scope, body, send)
        return
    await _json(send, 404, {"error": "not_found"})


async def _token(scope: dict[str, Any], send: Send) -> None:
    proofs = _headers(scope, b"dpop")
    try:
        jkt = _proof_jkt(proofs[0].decode()) if len(proofs) == 1 else None
    except (KeyError, TypeError, ValueError, UnicodeError, jwt.PyJWTError):
        jkt = None
    if jkt is None:
        await _json(send, 400, {"error": "invalid_dpop_proof"})
        return
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + 300
    _TOKENS[token] = jkt, expires_at
    await _json(send, 200, {"access_token": token, "expires_in": 300, "token_type": "DPoP"})


async def _introspect(scope: dict[str, Any], body: bytes, send: Send) -> None:
    if _headers(scope, b"accept") != [_MEDIA_TYPE.encode()]:
        await _json(send, 406, {"error": "signed_response_required"})
        return
    form = parse_qs(body.decode("ascii"), strict_parsing=True)
    token = _one(form, "token")
    assertion = _one(form, "client_assertion")
    if _one(form, "client_assertion_type") != _ASSERTION_TYPE or not _valid_assertion(assertion):
        await _json(send, 401, {"error": "invalid_client"})
        return
    now = int(time.time())
    stored = _TOKENS.get(token)
    nested: dict[str, object] = {"active": False}
    if stored is not None and stored[1] > now:
        nested = {
            "active": True,
            "aud": _AUDIENCE,
            "client_id": "reference-client",
            "cnf": {"jkt": stored[0]},
            "exp": stored[1],
            "iat": now,
            "scope": "payments:write",
            "sub": "reference-workload",
            "token_type": "DPoP",
        }
    response = jwt.encode(
        {"iss": _ISSUER, "aud": _AUDIENCE, "iat": now, "token_introspection": nested},
        _AS_KEY,
        algorithm="ES256",
        headers={"kid": "as-signing", "typ": "token-introspection+jwt"},
    ).encode()
    await _respond(send, 200, response, _MEDIA_TYPE)


def _valid_assertion(assertion: str) -> bool:
    try:
        claims = jwt.decode(
            assertion,
            _CLIENT_KEY.public_key(),
            algorithms=["ES256"],
            audience=f"{_ISSUER}/oauth/introspect",
            issuer=_CLIENT_ID,
            options={"require": ["iss", "sub", "aud", "iat", "exp", "jti"]},
        )
        jti = claims["jti"]
        if claims["sub"] != _CLIENT_ID or not isinstance(jti, str) or jti in _ASSERTION_JTIS:
            return False
        _ASSERTION_JTIS.add(jti)
        return True
    except jwt.PyJWTError:
        return False


def _proof_jkt(proof: str) -> str:
    header = jwt.get_unverified_header(proof)
    jwk = header.get("jwk")
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or not isinstance(jwk, dict):
        raise ValueError
    key = cast("ec.EllipticCurvePublicKey", jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk)))
    claims = jwt.decode(
        proof,
        key,
        algorithms=["ES256"],
        options={"require": ["jti", "htm", "htu", "iat"], "verify_iat": False},
    )
    if (
        claims["htm"] != "POST"
        or claims["htu"] != f"{_ISSUER}/oauth/token"
        or abs(time.time() - claims["iat"]) > _PROOF_WINDOW_SECONDS
    ):
        raise ValueError
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def _public_jwk(key: ec.EllipticCurvePrivateKey, *, kid: str | None = None) -> dict[str, str]:
    value = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    if kid is not None:
        value.update(alg="ES256", kid=kid, use="sig")
    return cast("dict[str, str]", value)


def _headers(scope: dict[str, Any], name: bytes) -> list[bytes]:
    return [value for key, value in scope.get("headers", ()) if key.lower() == name]


def _one(form: dict[str, list[str]], name: str) -> str:
    values = form.get(name, [])
    return values[0] if len(values) == 1 else ""


async def _read_body(receive: Receive) -> bytes:
    content = bytearray()
    while True:
        message = await receive()
        content.extend(message.get("body", b""))
        if not message.get("more_body"):
            return bytes(content)


async def _json(send: Send, status: int, payload: dict[str, object]) -> None:
    await _respond(send, status, json.dumps(payload, separators=(",", ":")).encode(), "application/json")


async def _respond(send: Send, status: int, body: bytes, content_type: str) -> None:
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", content_type.encode())]})
    await send({"type": "http.response.body", "body": body})
