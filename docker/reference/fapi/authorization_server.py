"""Minimal external FAPI authorization server for the Docker reference."""
# ruff: file-ignore[any-type, raise-vanilla-args, raise-within-try, raw-string-in-exception, too-many-statements-in-try-clause, type-check-without-type-error]

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlencode

import jwt
import jwt.algorithms
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "https://fapi-as.example"
CLIENT_ID = "fapi-client"
REDIRECT_URI = "https://client.example/callback"
TOKEN_TARGET = f"{ISSUER}/oauth/token"
AUDIENCE = "payments-api"
PAYMENT_AUTHORIZATION_TYPE = "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1"
PAYMENT_AUTHORIZATION_DETAILS = [
    {
        "type": PAYMENT_AUTHORIZATION_TYPE,
        "actions": ["initiate"],
        "locations": ["https://api.example/v1/payments"],
        "instructedAmount": {"currency": "EUR", "amount": "100.00"},
        "identifier": "reference-payment",
    }
]
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLIENT_KEY = ec.derive_private_key(7, ec.SECP256R1()).public_key()
AS_KEY = ec.derive_private_key(11, ec.SECP256R1())
AS_KEY_ID = "fapi-as-key"
_requests: dict[str, dict[str, Any]] = {}
_codes: dict[str, dict[str, Any]] = {}


async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """Serve JWKS, PAR, authorization, and authorization-code token endpoints."""
    if scope["type"] != "http":
        return
    method = scope.get("method")
    path = scope.get("path")
    if method == "GET" and path == "/.well-known/jwks.json":
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(AS_KEY.public_key()))
        jwk.update(kid=AS_KEY_ID, alg="ES256", use="sig")
        await _json(send, 200, {"keys": [jwk]})
        return
    if method == "POST" and path == "/oauth/par":
        await _par(receive, send)
        return
    if method == "GET" and path == "/oauth/authorize":
        await _authorize(scope, send)
        return
    if method == "POST" and path == "/oauth/token":
        await _token(scope, receive, send)
        return
    await _json(send, 404, {"error": "not_found"})


async def _par(receive: Any, send: Any) -> None:
    form = await _form(receive)
    if set(form) != {"request", "client_assertion_type", "client_assertion"}:
        await _json(send, 400, {"error": "invalid_request"})
        return
    try:
        if form["client_assertion_type"] != ASSERTION_TYPE:
            raise ValueError("client assertion type mismatch")
        _verify_client_assertion(form["client_assertion"])
        header = jwt.get_unverified_header(form["request"])
        if header != {"alg": "ES256", "kid": "fapi-client-key", "typ": "oauth-authz-req+jwt"}:
            raise ValueError("request header mismatch")
        claims = jwt.decode(
            form["request"],
            CLIENT_KEY,
            algorithms=["ES256"],
            audience=ISSUER,
            issuer=CLIENT_ID,
            options={"require": ["exp", "nbf", "jti"]},
        )
        required = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge_method": "S256",
            "response_mode": "jwt",
        }
        if any(claims.get(name) != value for name, value in required.items()):
            raise ValueError("request claims mismatch")
        for name in ("state", "nonce", "code_challenge", "scope"):
            if not isinstance(claims.get(name), str):
                raise ValueError("request binding missing")
        if claims.get("scope") != "openid payments:write":
            raise ValueError("request scope mismatch")
        if claims.get("authorization_details") != PAYMENT_AUTHORIZATION_DETAILS:
            raise ValueError("request authorization details mismatch")
    except (KeyError, TypeError, ValueError, jwt.PyJWTError):
        await _json(send, 400, {"error": "invalid_request"})
        return
    request_uri = f"urn:authweave:par:{secrets.token_urlsafe(18)}"
    _requests[request_uri] = claims
    await _json(send, 201, {"request_uri": request_uri, "expires_in": 90})


async def _authorize(scope: dict[str, Any], send: Any) -> None:
    query = _single(parse_qs(scope.get("query_string", b"").decode()))
    claims = _requests.pop(query.get("request_uri", ""), None)
    if query.get("client_id") != CLIENT_ID or claims is None:
        await _json(send, 400, {"error": "invalid_request_uri"})
        return
    code = secrets.token_urlsafe(24)
    _codes[code] = claims
    now = int(time.time())
    response = jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 120,
            "jti": secrets.token_urlsafe(18),
            "state": claims["state"],
            "code": code,
        },
        AS_KEY,
        algorithm="ES256",
        headers={"kid": AS_KEY_ID, "typ": "oauth-authz-resp+jwt"},
    )
    location = f"{REDIRECT_URI}?{urlencode({'response': response})}"
    await send({"type": "http.response.start", "status": 302, "headers": [(b"location", location.encode())]})
    await send({"type": "http.response.body", "body": b""})


async def _token(scope: dict[str, Any], receive: Any, send: Any) -> None:
    form = await _form(receive)
    headers = {name.decode().lower(): value.decode() for name, value in scope.get("headers", ())}
    try:
        if form["client_assertion_type"] != ASSERTION_TYPE:
            raise ValueError("client assertion type mismatch")
        _verify_client_assertion(form["client_assertion"])
        code = form["code"]
        claims = _codes[code]
        verifier = form["code_verifier"]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if form.get("grant_type") != "authorization_code" or form.get("redirect_uri") != REDIRECT_URI:
            raise ValueError("token request mismatch")
        if challenge != claims["code_challenge"]:
            raise ValueError("PKCE mismatch")
        proof = headers["dpop"]
        proof_header = jwt.get_unverified_header(proof)
        proof_key = jwt.PyJWK.from_dict(proof_header["jwk"])
        proof_claims = jwt.decode(proof, proof_key, algorithms=["ES256"], options={"require": ["iat", "jti"]})
        if proof_header.get("typ") != "dpop+jwt" or proof_claims.get("htm") != "POST":
            raise ValueError("DPoP mismatch")
        if proof_claims.get("htu") != TOKEN_TARGET:
            raise ValueError("DPoP target mismatch")
        jkt = _thumbprint(proof_header["jwk"])
        del _codes[code]
    except (KeyError, TypeError, ValueError, jwt.PyJWTError):
        await _json(send, 400, {"error": "invalid_grant"})
        return
    now = int(time.time())
    access_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "merchant-1",
            "client_id": CLIENT_ID,
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": secrets.token_urlsafe(18),
            "cnf": {"jkt": jkt},
            "scope": claims["scope"],
            "authorization_details": claims["authorization_details"],
        },
        AS_KEY,
        algorithm="ES256",
        headers={"kid": AS_KEY_ID, "typ": "at+jwt"},
    )
    id_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "merchant-1",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": claims["nonce"],
            "auth_time": now,
        },
        AS_KEY,
        algorithm="ES256",
        headers={"kid": AS_KEY_ID, "typ": "JWT"},
    )
    await _json(
        send,
        200,
        {"access_token": access_token, "id_token": id_token, "token_type": "DPoP", "expires_in": 300},
    )


def _verify_client_assertion(assertion: str) -> None:
    header = jwt.get_unverified_header(assertion)
    if header != {"alg": "ES256", "kid": "fapi-client-key", "typ": "JWT"}:
        raise ValueError("client assertion header mismatch")
    claims = jwt.decode(
        assertion,
        CLIENT_KEY,
        algorithms=["ES256"],
        audience=ISSUER,
        issuer=CLIENT_ID,
        options={"require": ["sub", "exp", "iat", "jti"]},
    )
    if claims.get("sub") != CLIENT_ID:
        raise ValueError("client assertion subject mismatch")


def _thumbprint(jwk: dict[str, str]) -> str:
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


async def _form(receive: Any) -> dict[str, str]:
    body = bytearray()
    while True:
        message = await receive()
        body.extend(message.get("body", b""))
        if not message.get("more_body"):
            break
    return _single(parse_qs(body.decode()))


def _single(values: dict[str, list[str]]) -> dict[str, str]:
    return {name: items[0] for name, items in values.items() if len(items) == 1}


async def _json(send: Any, status: int, value: dict[str, Any]) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")],
    })
    await send({"type": "http.response.body", "body": body})
