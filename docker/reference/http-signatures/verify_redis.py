#!/usr/bin/env python3
"""Exercise real Redis HTTP-signature nonce race, outage, and capacity behavior."""
# ruff: file-ignore[print]

from __future__ import annotations

import asyncio
import sys
from typing import cast

from authweave_http_signatures import HttpSignatureFailureCode, HttpSignatureVerificationError, SignatureNonceGuard
from authweave_http_signatures.redis_store import RedisHttpSignatureReplayStore
from redis.asyncio import Redis

REDIS_URL = "redis://127.0.0.1:16380/0"
UNAVAILABLE_REDIS_URL = "redis://127.0.0.1:16382/0"
_WORKERS = 32


async def main() -> int:
    redis = Redis.from_url(REDIS_URL, decode_responses=True)
    unavailable = Redis.from_url(
        UNAVAILABLE_REDIS_URL,
        decode_responses=True,
        socket_connect_timeout=0.2,
        socket_timeout=0.2,
    )
    try:
        await redis.flushdb()
        guards = [
            SignatureNonceGuard(
                RedisHttpSignatureReplayStore(redis),
                profile_tag="authweave-payment-http-sig-v1",
                ttl_seconds=600,
            )
            for _ in range(_WORKERS)
        ]

        async def claim(
            guard: SignatureNonceGuard,
            *,
            nonce: str = "concurrent-nonce",
        ) -> HttpSignatureFailureCode | None:
            try:
                await guard.consume(key_id="merchant-key-1", nonce=nonce)
            except HttpSignatureVerificationError as exc:
                return exc.code
            return None

        outcomes = await asyncio.gather(*(claim(guard) for guard in guards))
        if outcomes.count(None) != 1 or outcomes.count(HttpSignatureFailureCode.NONCE_REPLAY) != _WORKERS - 1:
            print(f"unexpected nonce race outcomes: {outcomes}", file=sys.stderr)
            return 1
        print(f"ok  redis nonce race: exactly one of {_WORKERS} workers won")

        outage_guard = SignatureNonceGuard(
            RedisHttpSignatureReplayStore(unavailable),
            profile_tag="authweave-payment-http-sig-v1",
            ttl_seconds=600,
        )
        if await claim(outage_guard) is not HttpSignatureFailureCode.STORE_UNAVAILABLE:
            print("Redis outage did not fail closed", file=sys.stderr)
            return 1
        print("ok  redis connection outage fails closed")

        original_maxmemory = cast("str", (await redis.config_get("maxmemory"))["maxmemory"])
        original_policy = cast("str", (await redis.config_get("maxmemory-policy"))["maxmemory-policy"])
        try:
            await redis.config_set("maxmemory-policy", "noeviction")
            await redis.config_set("maxmemory", "1")
            capacity = await claim(guards[0], nonce="capacity-nonce")
        finally:
            await redis.config_set("maxmemory", original_maxmemory)
            await redis.config_set("maxmemory-policy", original_policy)
        if capacity is not HttpSignatureFailureCode.STORE_UNAVAILABLE:
            print(f"Redis noeviction capacity did not fail closed: {capacity}", file=sys.stderr)
            return 1
        print("ok  redis noeviction capacity fails closed")
    finally:
        await unavailable.aclose()
        await redis.aclose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
