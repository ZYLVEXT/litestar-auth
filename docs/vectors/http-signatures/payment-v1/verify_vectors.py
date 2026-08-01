#!/usr/bin/env python3
"""Verify language-neutral AuthWeave HTTP signature vectors."""
# ruff: file-ignore[hardcoded-password-func-arg, print]

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime
from pathlib import Path

from authweave_core import (
    AuthenticationContext,
    AuthenticationEvidence,
    InMemoryReplayStore,
    PrincipalRef,
)
from authweave_http_signatures import (
    HttpMessageView,
    HttpSignatureVerificationError,
    PaymentHttpSignatureVerifier,
    PaymentSignaturePolicy,
    SignatureKeyBinding,
    SignatureNonceGuard,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"


class _Clock:
    def __call__(self) -> float:
        return 0.0


def _context(*, principal_subject: str, binding: dict[str, str]) -> AuthenticationContext:
    principal = PrincipalRef("https://issuer.test", principal_subject, "service")
    evidence = AuthenticationEvidence(
        provider="dpop_rs",
        profile="dpop_bound_access_token",
        method="dpop",
        issuer="https://issuer.test",
        audiences=("payments-api",),
        scopes=("payments:write",),
        issued_at=datetime.fromisoformat("2026-07-31T12:00:00+00:00"),
        expires_at=datetime.fromisoformat("2026-07-31T12:05:00+00:00"),
        token_id="vector-at-1",
        confirmation_thumbprint="A" * 43,
        environment=binding["environment"],
        extensions={"authweave-workload:application_id": binding["application_id"]},
    )
    return AuthenticationContext(subject=principal, actor=principal, evidence=evidence)


async def _run() -> int:
    data = json.loads(MANIFEST.read_text())
    now = datetime.fromisoformat(data["now"])
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(data["public_key_raw_b64"]))
    binding_cfg = data["binding"]
    failures = 0
    for case in data["cases"]:
        policy = PaymentSignaturePolicy(
            require_authorization_component=bool(case.get("require_authorization_component")),
        )
        verifier = PaymentHttpSignatureVerifier(
            policy=policy,
            public_keys={data["key_id"]: public_key},
            bindings={
                data["key_id"]: SignatureKeyBinding(
                    key_id=data["key_id"],
                    application_id=binding_cfg["application_id"],
                    principal_subject=binding_cfg["principal_subject"],
                    environment=binding_cfg["environment"],
                )
            },
            nonce_guard=SignatureNonceGuard(
                InMemoryReplayStore(capacity=64, time_source=_Clock()),
                profile_tag=policy.profile_tag,
                ttl_seconds=policy.nonce_ttl_seconds,
            ),
            time_source=lambda: now,
        )
        if "headers_list" in case:
            headers = tuple((name, value) for name, value in case["headers_list"])
        else:
            headers = tuple((name, value) for name, value in case["headers"].items())
        view = HttpMessageView(
            method=case["method"],
            target_uri=case["target_uri"],
            headers=headers,
            body=base64.b64decode(case["body_b64"]),
        )
        principal = case.get("override_principal_subject", binding_cfg["principal_subject"])
        try:
            await verifier.verify(view, context=_context(principal_subject=principal, binding=binding_cfg))
            passed = True
            code = None
        except HttpSignatureVerificationError as exc:
            passed = False
            code = exc.code.value
        ok = passed if case["expect"] == "pass" else not passed and code == case.get("failure")
        if ok:
            print(f"ok  {case['id']}")
        else:
            print(f"FAIL {case['id']}: passed={passed} code={code}")
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_run()))
