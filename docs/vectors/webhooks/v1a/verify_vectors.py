#!/usr/bin/env python3
"""Verify Standard Webhooks v1a vectors with authweave-webhooks."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path
from typing import Any

from authweave_webhooks import (
    Ed25519PublicKey,
    PublicKeyDocument,
    StandardWebhooksVerifier,
    StaticPublicKeyResolver,
)
from authweave_webhooks.errors import WebhookVerificationError

MANIFEST = Path(__file__).resolve().parent / "manifest.json"


def _headers(case: dict[str, Any]) -> list[tuple[str, str]]:
    return [(str(name), str(value)) for name, value in case["headers"]]


def _signing_input(case: dict[str, Any], body: bytes) -> bytes:
    header_values: dict[str, list[str]] = {}
    for name, value in _headers(case):
        header_values.setdefault(name.lower(), []).append(value)
    webhook_id = header_values["webhook-id"][0]
    timestamp = header_values["webhook-timestamp"][0]
    return f"{webhook_id}.{timestamp}.".encode("ascii") + body


async def _run() -> int:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected_document = data["key_document"]
    failures = 0
    for case in data["cases"]:
        trusted_roles = case.get("trusted_key_roles", list(data["public_keys_raw_b64"]))
        public_keys = tuple(
            Ed25519PublicKey(base64.b64decode(data["public_keys_raw_b64"][role], validate=True))
            for role in trusted_roles
        )
        document = dict(expected_document)
        document["environment"] = case.get("override_environment", document["environment"])
        document["owner"] = case.get("override_owner", document["owner"])
        document["endpoint"] = case.get("override_endpoint", document["endpoint"])
        resolver = StaticPublicKeyResolver(
            PublicKeyDocument(
                version=document["version"],
                environment=document["environment"],
                owner=document["owner"],
                endpoint=document["endpoint"],
                not_before=document["not_before"],
                retire_after=document["retire_after"],
                keys=public_keys,
            ),
        )
        verifier = StandardWebhooksVerifier(
            resolver,
            expected_environment=expected_document["environment"],
            expected_owner=expected_document["owner"],
            expected_endpoint=expected_document["endpoint"],
            time_source=lambda now=case["now"]: now,
        )
        body = base64.b64decode(case["body_b64"], validate=True)
        exact_bytes_match = base64.b64encode(_signing_input(case, body)).decode("ascii") == case["signing_input_b64"]
        try:
            await verifier.verify(headers=_headers(case), body=body)
            passed = True
            code = None
        except WebhookVerificationError as exc:
            passed = False
            code = exc.code.value
        expected = case["expect"]
        result_matches = passed if expected == "pass" else (not passed and case.get("failure") in {None, code})
        if exact_bytes_match and result_matches:
            sys.stdout.write(f"ok  {case['id']}\n")
        else:
            sys.stderr.write(
                f"FAIL {case['id']}: exact_bytes={exact_bytes_match} passed={passed} code={code}\n",
            )
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_run()))
