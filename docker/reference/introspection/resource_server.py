"""Four-worker opaque DPoP RS using private_key_jwt, RFC 9701, and Redis."""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from authweave_core import Authenticated, AuthenticationRuntime, RequestView, Unavailable
from authweave_workload.dpop import DPoPPolicy
from authweave_workload.introspection import (
    BoundedIntrospectionClient,
    DPoPBoundIntrospectionProvider,
    IntrospectionCachePolicy,
    IntrospectionEndpoint,
    IntrospectionIssuerProfile,
    IntrospectionUnavailableError,
    IntrospectionValidationError,
    PrivateKeyJWTClientAuth,
    SignedIntrospectionResponsePolicy,
)
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.redis_store import RedisDPoPReplayStore, RedisIntrospectionCache
from cryptography.hazmat.primitives.asymmetric import ec
from redis.asyncio import Redis

_ISSUER = "https://authorization-server:8443"
_AUDIENCE = "payments-api"
_TARGET = "https://api.example/v1/payments"
_CERTIFICATE = "/certs/server.crt"
_CLIENT_KEY = ec.derive_private_key(3, ec.SECP256R1())
_redis = Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))

type Receive = Callable[[], Awaitable[dict[str, Any]]]
type Send = Callable[[dict[str, Any]], Awaitable[None]]


class _Signer:
    async def sign(
        self,
        *,
        protected_headers: Mapping[str, object],
        claims: Mapping[str, object],
    ) -> str:
        return jwt.encode(claims, _CLIENT_KEY, algorithm="ES256", headers=protected_headers)


async def _fetch_jwks(_url: str, timeout_seconds: float, maximum: int) -> dict[str, object]:
    async with httpx.AsyncClient(verify=_CERTIFICATE, timeout=timeout_seconds, follow_redirects=False) as client:
        response = await client.get(f"{_ISSUER}/.well-known/jwks.json")
    response.raise_for_status()
    if len(response.content) > maximum:
        msg = "JWKS response is oversized"
        raise ValueError(msg)
    value = response.json()
    if not isinstance(value, dict):
        raise TypeError
    return value


async def _post(
    _url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    maximum: int,
) -> tuple[int, bytes, str]:
    try:
        async with httpx.AsyncClient(verify=_CERTIFICATE, timeout=timeout_seconds, follow_redirects=False) as client:
            response = await client.post(f"{_ISSUER}/oauth/introspect", headers=dict(headers), content=body)
    except httpx.HTTPError as exc:
        raise IntrospectionUnavailableError from exc
    if len(response.content) > maximum:
        msg = "introspection response is oversized"
        raise IntrospectionValidationError(msg)
    return response.status_code, response.content, response.headers.get("content-type", "")


_client = BoundedIntrospectionClient(
    endpoint=IntrospectionEndpoint(url=f"{_ISSUER}/oauth/introspect"),
    client_auth=PrivateKeyJWTClientAuth(
        client_id="reference-resource-server",
        audience=f"{_ISSUER}/oauth/introspect",
        key_id="rs-signing",
        algorithm="ES256",
        signer=_Signer(),
    ),
    signed_response=SignedIntrospectionResponsePolicy(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        jwks=BoundedJWKSClient(url=f"{_ISSUER}/.well-known/jwks.json", fetcher=_fetch_jwks),
    ),
    cache=RedisIntrospectionCache(_redis),
    cache_policy=IntrospectionCachePolicy(issuer=_ISSUER, active_ttl_seconds=5),
    poster=_post,
)
_provider = DPoPBoundIntrospectionProvider(
    name="reference-introspection",
    client=_client,
    profile=IntrospectionIssuerProfile(
        issuer=_ISSUER,
        environment="sandbox",
        audiences=frozenset({_AUDIENCE}),
    ),
    dpop=DPoPPolicy(resource_server_id=_AUDIENCE),
    replay_store=RedisDPoPReplayStore(_redis),
)


async def app(scope: dict[str, Any], receive: Receive, send: Send) -> None:
    """Authenticate the application-owned HTTPS target and return a typed outcome."""
    if scope["type"] != "http":
        return
    if scope.get("method") != "POST" or scope.get("path") != "/v1/payments":
        await _respond(send, 404, {"error": "not_found"})
        return
    await _read_body(receive)
    request = RequestView(
        method="POST",
        headers=tuple(scope.get("headers", ())),
        timestamp=datetime.now(UTC),
        target_uri=_TARGET,
    )
    decision = await _provider.authenticate(request, AuthenticationRuntime())
    if isinstance(decision, Authenticated):
        await _respond(
            send,
            200,
            {
                "ok": True,
                "profile": decision.context.evidence.profile,
                "subject": decision.context.subject.subject,
            },
        )
        return
    await _respond(send, 503 if isinstance(decision, Unavailable) else 401, {"error": "rejected"})


async def _read_body(receive: Receive) -> None:
    while True:
        message = await receive()
        if not message.get("more_body"):
            return


async def _respond(send: Send, status: int, payload: dict[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})
