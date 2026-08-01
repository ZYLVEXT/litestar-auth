"""Multi-worker DPoP resource-server upstream using network JWKS and Redis."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import jwt
from authweave_core import Authenticated, AuthenticationRuntime, RequestView, Unavailable
from authweave_workload.authorization_details import (
    PaymentAuthorizationDetail,
    PaymentAuthorizationPolicy,
    find_payment_authorization,
)
from authweave_workload.dpop import DPoPBoundJWTProvider, DPoPPolicy
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.jwt import TrustedIssuer
from authweave_workload.redis_store import RedisDPoPNonceStore, RedisDPoPReplayStore
from redis.asyncio import Redis

_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
_AS_INTERNAL_JWKS_URL = os.environ.get(
    "AS_INTERNAL_JWKS_URL",
    "http://127.0.0.1:18082/.well-known/jwks.json",
)
_AS_ISSUER = os.environ.get("AS_ISSUER", "https://as.example")
_AS_AUDIENCE = os.environ.get("AS_AUDIENCE", "payments-api")
_EXTERNAL_TARGET = os.environ.get(
    "EXTERNAL_TARGET",
    "https://api.example/v1/payments",
)
_PAYMENT_DETAILS_ENABLED = os.environ.get("PAYMENT_AUTHORIZATION_DETAILS") == "1"
_PAYMENT_POLICY = (
    PaymentAuthorizationPolicy(
        scope_actions={"payments:write": frozenset({"initiate"})},
        allowed_locations=frozenset({_EXTERNAL_TARGET}),
        currency_limits={"EUR": "1000.00"},
    )
    if _PAYMENT_DETAILS_ENABLED
    else None
)
type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]

_redis = Redis.from_url(_REDIS_URL, decode_responses=True)
_nonce_store = RedisDPoPNonceStore(_redis)


async def _fetch_reference_jwks(_url: str, timeout_seconds: float, maximum_response_bytes: int) -> dict[str, object]:
    """Fetch the separate test AS over the Compose network with production bounds.

    Returns:
        A decoded JWKS object.

    Raises:
        TypeError: If the response is not a JSON object.
        ValueError: If the response exceeds the configured bound.
    """
    async with (
        httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client,
        client.stream("GET", _AS_INTERNAL_JWKS_URL) as response,
    ):
        response.raise_for_status()
        content = bytearray()
        async for chunk in response.aiter_bytes():
            content.extend(chunk)
            if len(content) > maximum_response_bytes:
                msg = "reference JWKS response exceeded limit"
                raise ValueError(msg)
    value = json.loads(content)
    if not isinstance(value, dict):
        msg = "reference JWKS was not an object"
        raise TypeError(msg)
    return value


_provider = DPoPBoundJWTProvider(
    name="docker_live_rs",
    issuer=TrustedIssuer(
        issuer=_AS_ISSUER,
        audiences=frozenset({_AS_AUDIENCE}),
        environment="sandbox",
        jwks=BoundedJWKSClient(
            url=f"{_AS_ISSUER}/.well-known/jwks.json",
            fetcher=_fetch_reference_jwks,
        ),
        payment_authorization=_PAYMENT_POLICY,
    ),
    dpop=DPoPPolicy(resource_server_id="payments-rs", require_nonce=True, nonce_store=_nonce_store),
    replay_store=RedisDPoPReplayStore(_redis),
)


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Authenticate one DPoP presentation using the application-owned target URI."""
    if scope["type"] != "http":
        return
    method = str(scope.get("method", "GET"))
    path = str(scope.get("path", ""))
    if method != "POST" or path != "/v1/payments":
        await _respond(send, 404, b'{"error":"not_found"}')
        return
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, (list, tuple)):
        await _respond(send, 400, b'{"error":"bad_headers"}')
        return
    await _read_body(receive)
    request = RequestView(
        method="POST",
        headers=tuple(raw_headers),
        timestamp=datetime.now(tz=UTC),
        target_uri=_EXTERNAL_TARGET,
    )
    decision = await _provider.authenticate(request, AuthenticationRuntime())
    if isinstance(decision, Authenticated):
        if _PAYMENT_POLICY is not None:
            details = _PAYMENT_POLICY.from_evidence(decision.context.evidence)
            requested = PaymentAuthorizationDetail(
                actions=("initiate",),
                locations=(_EXTERNAL_TARGET,),
                currency="EUR",
                amount=Decimal("75.00"),
                identifier="reference-payment",
            )
            if find_payment_authorization(details, requested) is None:
                await _respond(send, 403, b'{"error":"insufficient_payment_authority"}')
                return
        body = json.dumps(
            {
                "ok": True,
                "subject": decision.context.subject.subject,
                "profile": decision.context.evidence.profile,
                "payment_authorized": _PAYMENT_POLICY is not None,
            },
        ).encode()
        await _respond(send, 200, body)
        return
    if isinstance(decision, Unavailable):
        await _respond(send, 503, b'{"error":"temporarily_unavailable"}')
        return
    challenge_headers = await _nonce_challenge_headers(raw_headers)
    await _respond(send, 401, b'{"error":"use_dpop_nonce"}', headers=challenge_headers)


async def _nonce_challenge_headers(
    raw_headers: list[tuple[bytes, bytes]] | tuple[tuple[bytes, bytes], ...],
) -> list[tuple[bytes, bytes]]:
    proof_values = [value for name, value in raw_headers if name.lower() == b"dpop"]
    if len(proof_values) != 1:
        return [(b"www-authenticate", b'DPoP error="use_dpop_nonce"'), (b"cache-control", b"no-store")]
    try:
        header = jwt.get_unverified_header(proof_values[0].decode("ascii"))
        jkt = _thumbprint(header["jwk"])
        nonce = await _nonce_store.issue(origin=_EXTERNAL_TARGET, jkt=jkt)
    except (KeyError, TypeError, ValueError, UnicodeError, RuntimeError, jwt.PyJWTError):
        return [(b"www-authenticate", b'DPoP error="use_dpop_nonce"'), (b"cache-control", b"no-store")]
    return [
        (b"www-authenticate", b'DPoP error="use_dpop_nonce"'),
        (b"dpop-nonce", nonce.encode()),
        (b"cache-control", b"no-store"),
    ]


def _thumbprint(jwk: dict[str, Any]) -> str:
    if set(jwk) - {"alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"} or jwk.get("kty") != "EC":
        msg = "invalid proof JWK"
        raise ValueError(msg)
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    value = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        msg = "invalid proof thumbprint"
        raise ValueError(msg)
    return value


async def _read_body(receive: Receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body"):
            break
    return b"".join(chunks)


async def _respond(
    send: Send,
    status: int,
    body: bytes,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), *(headers or [])],
        },
    )
    await send({"type": "http.response.body", "body": body})
