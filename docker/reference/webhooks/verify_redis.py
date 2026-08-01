#!/usr/bin/env python3
"""Real-Redis Standard Webhooks rotation and duplicate-claim smoke."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from typing import Any

from authweave_webhooks import (
    Ed25519PublicKey,
    LocalEd25519KeyringSigner,
    PublicKeyDocument,
    StandardWebhooksVerifier,
    WebhookDelivery,
    WebhookFailureCode,
    WebhookVerificationError,
    create_delivery,
)
from authweave_webhooks.redis_store import RedisReplayStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redis.asyncio import Redis

REDIS_URL = os.environ.get("AUTHWEAVE_WEBHOOK_REDIS_URL", "redis://127.0.0.1:16381/0")
NOW = 1_700_000_000
ENDPOINT = "https://merchant.example/hooks/payments"
CALLERS = 32
DOCUMENT_KEY = "authweave:reference:webhooks:key-document"
RESOLVE_COUNT_KEY = "authweave:reference:webhooks:resolve-count"
ROTATION_READY_KEY = "authweave:reference:webhooks:rotation-ready"


def _private(seed_start: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(seed_start, seed_start + 32)))


def _document(version: str, keys: tuple[bytes, ...]) -> PublicKeyDocument:
    return PublicKeyDocument(
        version=version,
        environment="sandbox",
        owner="merchant-demo",
        endpoint=ENDPOINT,
        not_before=0,
        retire_after=None,
        keys=tuple(Ed25519PublicKey(key) for key in keys),
    )


def _encode_document(document: PublicKeyDocument) -> str:
    return json.dumps(
        {
            "version": document.version,
            "environment": document.environment,
            "owner": document.owner,
            "endpoint": document.endpoint,
            "not_before": document.not_before,
            "retire_after": document.retire_after,
            "keys": [base64.b64encode(key.public_key).decode("ascii") for key in document.keys],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_document(raw: str) -> PublicKeyDocument:
    data: dict[str, Any] = json.loads(raw)
    return PublicKeyDocument(
        version=str(data["version"]),
        environment=str(data["environment"]),
        owner=str(data["owner"]),
        endpoint=str(data["endpoint"]),
        not_before=int(data["not_before"]),
        retire_after=None if data["retire_after"] is None else int(data["retire_after"]),
        keys=tuple(Ed25519PublicKey(base64.b64decode(encoded, validate=True)) for encoded in data["keys"]),
    )


class _RedisRotationResolver:
    """Reference resolver with a cold snapshot and atomic Redis publication."""

    def __init__(self, redis: Redis, initial: PublicKeyDocument) -> None:
        self._redis = redis
        self._current = initial
        self._initial_resolved = False

    async def resolve(self) -> PublicKeyDocument:
        if self._initial_resolved:
            return self._current
        self._initial_resolved = True
        snapshot = self._current
        await self._redis.incr(RESOLVE_COUNT_KEY)
        rotation_ready = bool(await self._redis.exists(ROTATION_READY_KEY))
        while not rotation_ready:
            await asyncio.sleep(0.001)
            rotation_ready = bool(await self._redis.exists(ROTATION_READY_KEY))
        return snapshot

    async def refresh(self) -> PublicKeyDocument | None:
        raw = await self._redis.get(DOCUMENT_KEY)
        if raw is None:
            return None
        candidate = _decode_document(str(raw))
        if int(candidate.version) <= int(self._current.version):
            return None
        self._current = candidate
        return candidate


async def _publish_after_all_old_snapshots(redis: Redis, document: PublicKeyDocument) -> None:
    resolved_count = int(await redis.get(RESOLVE_COUNT_KEY) or 0)
    while resolved_count < CALLERS:
        await asyncio.sleep(0.001)
        resolved_count = int(await redis.get(RESOLVE_COUNT_KEY) or 0)
    async with redis.pipeline(transaction=True) as transaction:
        transaction.set(DOCUMENT_KEY, _encode_document(document))
        transaction.set(ROTATION_READY_KEY, "1")
        await transaction.execute()


async def _verify(
    verifier: StandardWebhooksVerifier,
    delivery: WebhookDelivery,
) -> bool | WebhookFailureCode:
    try:
        verified = await verifier.verify(headers=delivery.headers(), body=delivery.body)
    except WebhookVerificationError as exc:
        return exc.code
    return verified.replay_detected


async def main() -> int:
    retiring_private = _private(0)
    active_private = _private(32)
    next_private = _private(64)
    old_document = _document("1", (retiring_private.public_key().public_bytes_raw(),))
    rotated_document = _document(
        "2",
        tuple(key.public_key().public_bytes_raw() for key in (active_private, next_private, retiring_private)),
    )
    signer = LocalEd25519KeyringSigner({"active": active_private})
    deliveries = [
        await create_delivery(
            signer=signer,
            key_refs=["active"],
            webhook_id=f"msg_real_redis_rotation_{index}",
            timestamp=NOW,
            body=b'{"event":"payment.captured"}',
        )
        for index in range(CALLERS)
    ]

    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.flushdb()
        replay_store = RedisReplayStore(redis)
        verifiers = [
            StandardWebhooksVerifier(
                _RedisRotationResolver(redis, old_document),
                replay_store=replay_store,
                expected_environment="sandbox",
                expected_owner="merchant-demo",
                expected_endpoint=ENDPOINT,
                time_source=lambda: NOW,
            )
            for _ in range(CALLERS)
        ]
        publisher = asyncio.create_task(_publish_after_all_old_snapshots(redis, rotated_document))
        verified = await asyncio.gather(
            *(
                verifier.verify(headers=delivery.headers(), body=delivery.body)
                for verifier, delivery in zip(verifiers, deliveries, strict=True)
            ),
        )
        await publisher
        if {result.key_document_version for result in verified} != {"2"}:
            sys.stderr.write("rotation race did not converge on version 2\n")
            return 1

        duplicate_delivery = await create_delivery(
            signer=signer,
            key_refs=["active"],
            webhook_id="msg_real_redis_duplicate",
            timestamp=NOW,
            body=b'{"event":"payment.captured"}',
        )
        outcomes = await asyncio.gather(*(_verify(verifier, duplicate_delivery) for verifier in verifiers))
        if outcomes.count(False) != 1 or outcomes.count(True) != CALLERS - 1:
            sys.stderr.write(f"unexpected duplicate verification outcomes: {outcomes!r}\n")
            return 1

        await redis.set(DOCUMENT_KEY, _encode_document(old_document))
        if await _RedisRotationResolver(redis, rotated_document).refresh() is not None:
            sys.stderr.write("key-document rollback was accepted\n")
            return 1
    finally:
        await redis.flushdb()
        await redis.aclose()

    sys.stdout.write(f"ok  {CALLERS} concurrent key refreshes converged on version 2\n")
    sys.stdout.write(f"ok  {CALLERS} verifications returned one fresh and {CALLERS - 1} replay observations\n")
    sys.stdout.write("ok  key-document rollback was rejected\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
