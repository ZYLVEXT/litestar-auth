"""Independent HTTPS RFC 8693 security token service fixture."""
# ruff: file-ignore[complex-structure, docstring-missing-exception, hardcoded-password-string, magic-value-comparison, raise-vanilla-args, raise-within-try, raw-string-in-exception, too-many-statements-in-try-clause]

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import jwt
import jwt.algorithms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ENDPOINT = "https://127.0.0.1:18444/oauth/token"
MTLS_ENDPOINT = "https://127.0.0.1:18445/oauth/token"
ISSUER = "https://sts.example"
CLIENT_ID = "exchange-client"
AUDIENCE = "backend-api"
RESOURCE = "https://backend.example/v1/payments"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
PAYMENT_TYPE = "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1"
CLIENT_KEY = ec.derive_private_key(13, ec.SECP256R1()).public_key()
STS_KEY = ec.derive_private_key(17, ec.SECP256R1())
_JTIS: set[str] = set()
_DPOP_NONCE = "reference-as-nonce"

type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]


class _DPoPNonceRequiredError(Exception):
    """Signal the RFC 9449 nonce challenge path."""


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Serve one exact token-exchange endpoint and its verification key."""
    if scope["type"] != "http":
        return
    if scope.get("method") == "GET" and scope.get("path") == "/.well-known/jwks.json":
        key = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(STS_KEY.public_key()))
        key.update(kid="sts-signing", alg="ES256", use="sig")
        await _json(send, 200, {"keys": [key]})
        return
    if scope.get("method") != "POST" or scope.get("path") != "/oauth/token":
        await _json(send, 404, {"error": "not_found"})
        return
    body = bytearray()
    while True:
        message = await receive()
        body.extend(message.get("body", b""))
        if not message.get("more_body"):
            break
    headers = {name.decode().lower(): value.decode() for name, value in scope.get("headers", ())}
    try:
        endpoint = _endpoint(headers)
        form = _single(parse_qs(body.decode("ascii"), strict_parsing=True))
        _validate_form(form)
        _validate_client_assertion(form["client_assertion"], endpoint)
        if endpoint == ENDPOINT:
            confirmation = {"jkt": _validate_dpop(headers["dpop"], endpoint)}
            token_type = "DPoP"
        else:
            if "dpop" in headers:
                raise ValueError("mixed sender constraints")
            confirmation = {"x5t#S256": _client_certificate_thumbprint()}
            token_type = "Bearer"
        details = json.loads(form["authorization_details"])
        if details != [_payment("50.00")]:
            raise ValueError("authority mismatch")
    except _DPoPNonceRequiredError:
        await _json(
            send,
            400,
            {"error": "use_dpop_nonce"},
            extra_headers=((b"dpop-nonce", _DPOP_NONCE.encode()),),
        )
        return
    except (KeyError, TypeError, ValueError, UnicodeError, jwt.PyJWTError):
        await _json(send, 400, {"error": "invalid_request"})
        return

    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "subject-1",
            "act": {"sub": "actor-1"},
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "scope": "payments:write",
            "cnf": confirmation,
            "authorization_details": details,
        },
        STS_KEY,
        algorithm="ES256",
        headers={"kid": "sts-signing", "typ": "at+jwt"},
    )
    await _json(
        send,
        200,
        {
            "access_token": token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": token_type,
            "expires_in": 300,
            "scope": "payments:write",
            "authorization_details": details,
        },
    )


def _validate_form(form: dict[str, str]) -> None:
    expected = {
        "grant_type": GRANT_TYPE,
        "resource": RESOURCE,
        "audience": AUDIENCE,
        "scope": "payments:write",
        "requested_token_type": ACCESS_TOKEN_TYPE,
        "subject_token": "subject-token",
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": "actor-token",
        "actor_token_type": ACCESS_TOKEN_TYPE,
        "client_assertion_type": ASSERTION_TYPE,
    }
    if set(form) != {*expected, "client_assertion", "authorization_details"}:
        raise ValueError("form mismatch")
    if any(form[name] != value for name, value in expected.items()):
        raise ValueError("form mismatch")


def _validate_client_assertion(assertion: str, endpoint: str) -> None:
    header = jwt.get_unverified_header(assertion)
    if header != {"alg": "ES256", "kid": "client-key", "typ": "JWT"}:
        raise ValueError("assertion header mismatch")
    claims = jwt.decode(
        assertion,
        CLIENT_KEY,
        algorithms=["ES256"],
        audience=endpoint,
        issuer=CLIENT_ID,
        options={"require": ["sub", "iat", "exp", "jti"]},
    )
    jti = claims["jti"]
    if claims["sub"] != CLIENT_ID or not isinstance(jti, str) or jti in _JTIS:
        raise ValueError("assertion replay")
    _JTIS.add(jti)


def _validate_dpop(proof: str, endpoint: str) -> str:
    header = jwt.get_unverified_header(proof)
    jwk = header.get("jwk")
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256" or not isinstance(jwk, dict):
        raise ValueError("DPoP header mismatch")
    key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(proof, key, algorithms=["ES256"], options={"require": ["jti", "htm", "htu", "iat"]})
    jti = claims["jti"]
    if (
        claims["htm"] != "POST"
        or claims["htu"] != endpoint
        or abs(time.time() - claims["iat"]) > 90
        or not isinstance(jti, str)
        or jti in _JTIS
    ):
        raise ValueError("DPoP mismatch")
    if claims.get("nonce") != _DPOP_NONCE:
        raise _DPoPNonceRequiredError
    _JTIS.add(jti)
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
    ).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def _endpoint(headers: dict[str, str]) -> str:
    endpoints = {
        "127.0.0.1:18444": ENDPOINT,
        "127.0.0.1:18445": MTLS_ENDPOINT,
    }
    try:
        return endpoints[headers["host"]]
    except KeyError as exc:
        raise ValueError("unexpected token endpoint") from exc


def _client_certificate_thumbprint() -> str:
    certificate = x509.load_pem_x509_certificate(Path("/certs/client.crt").read_bytes())
    return base64.urlsafe_b64encode(certificate.fingerprint(hashes.SHA256())).rstrip(b"=").decode()


def _payment(amount: str) -> dict[str, object]:
    return {
        "type": PAYMENT_TYPE,
        "actions": ["initiate"],
        "locations": [RESOURCE],
        "instructedAmount": {"currency": "EUR", "amount": amount},
        "identifier": "payment-1",
    }


def _single(values: dict[str, list[str]]) -> dict[str, str]:
    if any(len(members) != 1 for members in values.values()):
        raise ValueError("duplicate form member")
    return {name: members[0] for name, members in values.items()}


async def _json(
    send: Send,
    status: int,
    payload: dict[str, object],
    *,
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"cache-control", b"no-store"),
            *extra_headers,
        ],
    })
    await send({"type": "http.response.body", "body": body})


__all__ = ("app",)
