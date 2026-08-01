"""Show trusted-target vs Host-spoof outcomes for payment HTTP signatures."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime
from pathlib import Path

import anyio
from authweave_core import (
    AuthenticationContext,
    AuthenticationEvidence,
    InMemoryReplayStore,
    PrincipalRef,
)
from authweave_http_signatures import (
    HttpMessageView,
    HttpSignatureFailureCode,
    HttpSignatureVerificationError,
    PaymentHttpSignatureVerifier,
    PaymentSignaturePolicy,
    SignatureKeyBinding,
    SignatureNonceGuard,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST = Path("docs/vectors/http-signatures/payment-v1/manifest.json")


async def main() -> int:
    data = json.loads(await anyio.Path(MANIFEST).read_text(encoding="utf-8"))
    case = next(item for item in data["cases"] if item["id"] == "trusted-external-target")
    spoof = next(item for item in data["cases"] if item["id"] == "wrong-target-uri")
    now = datetime.fromisoformat(data["now"])
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(data["public_key_raw_b64"]))
    binding = data["binding"]

    def context() -> AuthenticationContext:
        principal = PrincipalRef("https://issuer.test", binding["principal_subject"], "service")
        evidence = AuthenticationEvidence(
            provider="dpop_rs",
            profile="dpop_bound_access_token",
            method="dpop",
            issuer="https://issuer.test",
            audiences=("payments-api",),
            scopes=("payments:write",),
            issued_at=now,
            expires_at=now,
            token_id="proxy-demo",
            confirmation_thumbprint="A" * 43,
            environment=binding["environment"],
            extensions={"authweave-workload:application_id": binding["application_id"]},
        )
        return AuthenticationContext(subject=principal, actor=principal, evidence=evidence)

    def verifier() -> PaymentHttpSignatureVerifier:
        return PaymentHttpSignatureVerifier(
            policy=PaymentSignaturePolicy(),
            public_keys={data["key_id"]: public_key},
            bindings={
                data["key_id"]: SignatureKeyBinding(
                    key_id=data["key_id"],
                    application_id=binding["application_id"],
                    principal_subject=binding["principal_subject"],
                    environment=binding["environment"],
                )
            },
            nonce_guard=SignatureNonceGuard(
                InMemoryReplayStore(capacity=8, time_source=lambda: 0.0),
                profile_tag="authweave-payment-http-sig-v1",
                ttl_seconds=600,
            ),
            time_source=lambda: now,
        )

    ok_view = HttpMessageView(
        method=case["method"],
        target_uri=case["target_uri"],
        headers=tuple(case["headers"].items()),
        body=base64.b64decode(case["body_b64"]),
    )
    await verifier().verify(ok_view, context=context())

    bad_view = HttpMessageView(
        method=spoof["method"],
        target_uri=spoof["target_uri"],
        headers=tuple(spoof["headers"].items()),
        body=base64.b64decode(spoof["body_b64"]),
    )
    try:
        await verifier().verify(bad_view, context=context())
    except HttpSignatureVerificationError as exc:
        if exc.code is not HttpSignatureFailureCode.SIGNATURE_INVALID:
            return 1
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
