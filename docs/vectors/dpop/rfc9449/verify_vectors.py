#!/usr/bin/env python3
"""Verify language-neutral DPoP RS vectors against authweave-workload[dpop]."""
# ruff: file-ignore[print]

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path

from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    InMemoryReplayStore,
    Invalid,
    RequestView,
)
from authweave_workload.dpop import DPoPBoundJWTProvider, DPoPPolicy
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.jwt import TrustedIssuer

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"


class _Clock:
    def __call__(self) -> float:
        return 0.0


async def _run() -> int:
    data = json.loads(MANIFEST.read_text())
    now = datetime.fromisoformat(data["now"])
    failures = 0
    for case in data["cases"]:
        provider = DPoPBoundJWTProvider(
            name="vector_rs",
            issuer=TrustedIssuer(
                issuer=data["issuer"],
                audiences=frozenset({data["audience"]}),
                environment="sandbox",
                jwks=BoundedJWKSClient(static_jwks=data["jwks"]),
            ),
            dpop=DPoPPolicy(resource_server_id=data["resource_server_id"]),
            replay_store=InMemoryReplayStore(capacity=64, time_source=_Clock()),
        )
        headers: list[tuple[bytes, bytes]] = []
        if case.get("authorization"):
            headers.append((b"authorization", case["authorization"].encode()))
        if case.get("dpop"):
            headers.append((b"dpop", case["dpop"].encode()))
        request = RequestView(
            method=case["method"],
            headers=tuple(headers),
            timestamp=now,
            target_uri=case["target_uri"],
        )
        match = provider.match(request)
        if case["expect"] == "ambiguous":
            ok = match is CredentialMatch.AMBIGUOUS
            if not ok:
                print(f"FAIL {case['id']}: match={match}")
                failures += 1
            else:
                print(f"ok  {case['id']}")
            continue
        if match is not CredentialMatch.OWNED:
            print(f"FAIL {case['id']}: expected OWNED got {match}")
            failures += 1
            continue
        decision = await provider.authenticate(request, AuthenticationRuntime())
        if case["expect"] == "pass":
            ok = isinstance(decision, Authenticated)
        else:
            expected = FailureCode(case["failure"])
            ok = isinstance(decision, Invalid) and decision.code is expected
        if not ok:
            print(f"FAIL {case['id']}: decision={decision!r}")
            failures += 1
        else:
            print(f"ok  {case['id']}")
    return failures


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_run()))
