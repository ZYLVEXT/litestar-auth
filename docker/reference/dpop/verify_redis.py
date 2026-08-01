#!/usr/bin/env python3
"""Exercise Redis DPoP replay/nonce atomicity, outage, and capacity behavior."""
# ruff: file-ignore[print]

from __future__ import annotations

import asyncio
import sys
from typing import cast

from authweave_core import ReplayOutcome
from authweave_workload.redis_store import RedisDPoPNonceStore, RedisDPoPReplayStore
from redis.asyncio import Redis

REDIS_URL = "redis://127.0.0.1:16379/0"
UNAVAILABLE_REDIS_URL = "redis://127.0.0.1:16380/0"
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
        replay = RedisDPoPReplayStore(redis)
        outcomes = await asyncio.gather(
            *(replay.check_and_store("dpop:concurrent:proof", ttl_seconds=90) for _ in range(_WORKERS))
        )
        if outcomes.count(ReplayOutcome.STORED) != 1 or outcomes.count(ReplayOutcome.REPLAY) != _WORKERS - 1:
            print(f"unexpected replay race outcomes: {outcomes}", file=sys.stderr)
            return 1
        print(f"ok  redis replay race: exactly one of {_WORKERS} workers won")

        nonce_store = RedisDPoPNonceStore(redis, ttl_seconds=120)
        nonce = await nonce_store.issue(origin="https://api.example/payments", jkt="A" * 43)
        nonce_outcomes = await asyncio.gather(
            *(
                nonce_store.consume(origin="https://api.example/payments", jkt="A" * 43, nonce=nonce)
                for _ in range(_WORKERS)
            )
        )
        if (
            nonce_outcomes.count(ReplayOutcome.STORED) != 1
            or nonce_outcomes.count(ReplayOutcome.REPLAY) != _WORKERS - 1
        ):
            print(f"unexpected nonce race outcomes: {nonce_outcomes}", file=sys.stderr)
            return 1
        print(f"ok  redis nonce race: exactly one of {_WORKERS} workers consumed")

        outage = RedisDPoPReplayStore(unavailable)
        if await outage.check_and_store("dpop:outage:proof", ttl_seconds=30) is not ReplayOutcome.UNAVAILABLE:
            print("Redis connection outage did not map to Unavailable", file=sys.stderr)
            return 1
        print("ok  redis connection outage maps to fail-closed Unavailable")

        original_maxmemory = cast("str", (await redis.config_get("maxmemory"))["maxmemory"])
        original_policy = cast("str", (await redis.config_get("maxmemory-policy"))["maxmemory-policy"])
        try:
            await redis.config_set("maxmemory-policy", "noeviction")
            await redis.config_set("maxmemory", "1")
            capacity = await replay.check_and_store("dpop:capacity:proof", ttl_seconds=30)
        finally:
            await redis.config_set("maxmemory", original_maxmemory)
            await redis.config_set("maxmemory-policy", original_policy)
        if capacity is not ReplayOutcome.UNAVAILABLE:
            print(f"Redis noeviction capacity did not fail closed: {capacity}", file=sys.stderr)
            return 1
        print("ok  redis noeviction capacity maps to fail-closed Unavailable")
    finally:
        await unavailable.aclose()
        await redis.aclose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
