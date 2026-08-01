"""DPoP-authenticated payment signature upstream behind an Envoy rewrite."""
# ruff: file-ignore[too-many-return-statements]

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from authweave_core import Authenticated, AuthenticationRuntime, RequestView, Unavailable
from authweave_http_signatures import (
    UNIX_SOCKET_PROXY,
    AllowlistedProxyExternalTarget,
    HttpMessageView,
    HttpSignatureFailureCode,
    HttpSignatureVerificationError,
    PaymentHttpSignatureVerifier,
    PaymentSignaturePolicy,
    SignatureKeyBinding,
    SignatureNonceGuard,
)
from authweave_http_signatures.redis_store import RedisHttpSignatureReplayStore
from authweave_workload.dpop import DPoPBoundJWTProvider, DPoPPolicy
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.jwt import TrustedIssuer
from authweave_workload.redis_store import RedisDPoPReplayStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from redis.asyncio import Redis

type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]

_KEY_PATH = Path(os.environ.get("PAYMENT_PUBLIC_KEY", "/shared/payment_public.der"))
_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
_AS_INTERNAL_JWKS_URL = os.environ.get(
    "AS_INTERNAL_JWKS_URL",
    "http://127.0.0.1:18083/.well-known/jwks.json",
)
_AS_ISSUER = os.environ.get("AS_ISSUER", "https://as.example")
_AS_AUDIENCE = os.environ.get("AS_AUDIENCE", "payments-api")
_EXTERNAL_TARGET = os.environ.get("EXTERNAL_TARGET", "https://payments.example/v1/payments")
_HEADER_PAIR_SIZE = 2
_BINDING = SignatureKeyBinding(
    key_id="merchant-key-1",
    application_id="payments-app",
    principal_subject="payments-worker",
    environment="sandbox",
)
_TARGET_FACTORY = AllowlistedProxyExternalTarget(frozenset({UNIX_SOCKET_PROXY}))
_redis = Redis.from_url(_REDIS_URL, decode_responses=True)


async def _fetch_reference_jwks(
    _url: str,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> dict[str, object]:
    """Fetch the separate test-AS JWKS with redirect, size, and timeout bounds.

    Returns:
        The decoded JWKS object.

    Raises:
        TypeError: If the payload is not an object.
        ValueError: If the response exceeds the configured size.
    """
    async with (
        httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client,
        client.stream("GET", _AS_INTERNAL_JWKS_URL, headers={"accept": "application/json"}) as response,
    ):
        response.raise_for_status()
        content = bytearray()
        async for chunk in response.aiter_bytes():
            content.extend(chunk)
            if len(content) > maximum_response_bytes:
                msg = "reference JWKS response exceeded its bound"
                raise ValueError(msg)
    value = json.loads(content)
    if not isinstance(value, dict):
        msg = "reference JWKS response must be an object"
        raise TypeError(msg)
    return value


_dpop_provider = DPoPBoundJWTProvider(
    name="http_signature_reference_dpop",
    issuer=TrustedIssuer(
        issuer=_AS_ISSUER,
        audiences=frozenset({_AS_AUDIENCE}),
        environment="sandbox",
        jwks=BoundedJWKSClient(
            url=f"{_AS_ISSUER}/.well-known/jwks.json",
            fetcher=_fetch_reference_jwks,
        ),
    ),
    dpop=DPoPPolicy(resource_server_id="http-signature-payments-rs"),
    replay_store=RedisDPoPReplayStore(_redis),
)
_signature_verifier = PaymentHttpSignatureVerifier(
    policy=PaymentSignaturePolicy(require_authorization_component=True),
    public_keys={"merchant-key-1": Ed25519PublicKey.from_public_bytes(_KEY_PATH.read_bytes())},
    bindings={"merchant-key-1": _BINDING},
    nonce_guard=SignatureNonceGuard(
        RedisHttpSignatureReplayStore(_redis),
        profile_tag="authweave-payment-http-sig-v1",
        ttl_seconds=600,
    ),
)


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Authenticate DPoP, then verify identity-bound payment message integrity."""
    if scope["type"] != "http":
        return
    if str(scope.get("method", "GET")) != "POST" or str(scope.get("path", "")) != "/internal/payments":
        await _respond(send, 404, b'{"error":"not_found"}')
        return
    try:
        target = _TARGET_FACTORY(scope)
    except ValueError:
        await _respond(send, 401, b'{"error":"untrusted_target"}')
        return
    if target != _EXTERNAL_TARGET:
        await _respond(send, 401, b'{"error":"target_mismatch"}')
        return
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, (list, tuple)) or not all(
        isinstance(item, tuple) and len(item) == _HEADER_PAIR_SIZE and all(isinstance(value, bytes) for value in item)
        for item in raw_headers
    ):
        await _respond(send, 400, b'{"error":"bad_headers"}')
        return
    headers = tuple(raw_headers)
    request = RequestView(
        method="POST",
        headers=headers,
        timestamp=datetime.now(tz=UTC),
        target_uri=target,
    )
    authentication = await _dpop_provider.authenticate(request, AuthenticationRuntime())
    if isinstance(authentication, Unavailable):
        await _respond(send, 503, b'{"error":"authentication_unavailable"}')
        return
    if not isinstance(authentication, Authenticated):
        await _respond(send, 401, b'{"error":"authentication_invalid"}')
        return
    body = await _read_body(receive)
    view = HttpMessageView(
        method="POST",
        target_uri=target,
        headers=_ascii_headers(headers),
        body=body,
    )
    try:
        verified = await _signature_verifier.verify(view, context=authentication.context)
    except HttpSignatureVerificationError as exc:
        status = 503 if exc.code is HttpSignatureFailureCode.STORE_UNAVAILABLE else 401
        await _respond(send, status, b'{"error":"signature_invalid"}')
        return
    payload = json.dumps(
        {
            "ok": True,
            "target": target,
            "subject": authentication.context.subject.subject,
            "key_id": verified.key_id,
        },
        separators=(",", ":"),
    ).encode()
    await _respond(send, 200, payload)


def _ascii_headers(headers: tuple[tuple[bytes, bytes], ...]) -> tuple[tuple[str, str], ...]:
    return tuple((name.decode("latin-1"), value.decode("latin-1")) for name, value in headers)


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


async def _respond(send: Send, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        },
    )
    await send({"type": "http.response.body", "body": body})
