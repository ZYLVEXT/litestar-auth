#!/usr/bin/env python3
"""Validate the example Standard Webhooks merchant environment packs."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PACK_DIR = Path(__file__).resolve().parent
EXPECTED_ENVIRONMENTS = {"sandbox", "live"}
EXPECTED_ROLES = {"active", "next", "retiring"}
ED25519_PUBLIC_KEY_BYTES = 32
EXPECTED_KEY_COUNT = 3


def _https_url(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        msg = f"{field} must be a string"
        raise TypeError(msg)
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        msg = f"{field} must be an explicit HTTPS URL without userinfo or fragment"
        raise ValueError(msg)
    return value


def _public_key(value: object) -> bytes:
    if not isinstance(value, str):
        msg = "public_key_raw_b64 must be a string"
        raise TypeError(msg)
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != ED25519_PUBLIC_KEY_BYTES or base64.b64encode(decoded).decode("ascii") != value:
        msg = "public_key_raw_b64 must be canonical base64 for 32 raw Ed25519 bytes"
        raise ValueError(msg)
    return decoded


def _validate_identity(path: Path, data: dict[str, Any]) -> tuple[str, str]:
    if data.get("schema") != "authweave.webhooks.merchant-environment-pack/v1":
        msg = f"{path.name}: unsupported schema"
        raise ValueError(msg)
    if data.get("status") != "example-do-not-deploy":
        msg = f"{path.name}: example status marker is required"
        raise ValueError(msg)
    if data.get("profile") != "authweave-standard-webhooks-v1a":
        msg = f"{path.name}: unexpected profile"
        raise ValueError(msg)

    environment = data.get("environment")
    if environment not in EXPECTED_ENVIRONMENTS:
        msg = f"{path.name}: environment must be sandbox or live"
        raise ValueError(msg)
    if not isinstance(data.get("owner"), str) or not data["owner"]:
        msg = f"{path.name}: owner is required"
        raise ValueError(msg)
    endpoint = _https_url(data.get("endpoint"), field="endpoint")
    _https_url(data.get("key_set_url"), field="key_set_url")
    return environment, endpoint


def _validate_document(path: Path, data: dict[str, Any]) -> set[bytes]:
    document = data.get("key_document")
    if not isinstance(document, dict) or not document.get("version"):
        msg = f"{path.name}: versioned key_document is required"
        raise ValueError(msg)
    not_before = document.get("not_before")
    retire_after = document.get("retire_after")
    if not isinstance(not_before, int) or not isinstance(retire_after, int) or retire_after < not_before:
        msg = f"{path.name}: invalid key-document validity window"
        raise ValueError(msg)
    keys = document.get("keys")
    if not isinstance(keys, list) or len(keys) != EXPECTED_KEY_COUNT:
        msg = f"{path.name}: exactly three role-labelled keys are required"
        raise ValueError(msg)
    roles = {entry.get("role") for entry in keys if isinstance(entry, dict)}
    if roles != EXPECTED_ROLES:
        msg = f"{path.name}: active, next, and retiring roles are required exactly once"
        raise ValueError(msg)
    public_keys = {_public_key(entry.get("public_key_raw_b64")) for entry in keys}
    if len(public_keys) != len(keys):
        msg = f"{path.name}: key reuse inside one environment is forbidden"
        raise ValueError(msg)

    return public_keys


def _validate_egress(path: Path, data: dict[str, Any], endpoint: str) -> None:
    egress = data.get("sender_egress")
    if not isinstance(egress, dict):
        msg = f"{path.name}: sender_egress is required"
        raise TypeError(msg)
    allowlist = egress.get("exact_endpoint_allowlist")
    if allowlist != [endpoint] or egress.get("controlled_proxy_required") is not True:
        msg = f"{path.name}: exact endpoint allowlist and controlled proxy are required"
        raise ValueError(msg)
    if egress.get("redirects_allowed") is not False:
        msg = f"{path.name}: redirects must be disabled"
        raise ValueError(msg)


def _validate_pack(path: Path) -> tuple[str, set[bytes]]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    environment, endpoint = _validate_identity(path, data)
    public_keys = _validate_document(path, data)
    _validate_egress(path, data, endpoint)
    return environment, public_keys


def main() -> int:
    """Validate both environment packs and their cross-pack isolation.

    Returns:
        Zero when both packs are valid.

    Raises:
        ValueError: If environments or public keys overlap, or one pack is
            missing.
    """
    seen_environments: set[str] = set()
    seen_keys: set[bytes] = set()
    for path in sorted(PACK_DIR.glob("*.json")):
        environment, keys = _validate_pack(path)
        if environment in seen_environments or seen_keys.intersection(keys):
            msg = "sandbox/live environments and keys must be disjoint"
            raise ValueError(msg)
        seen_environments.add(environment)
        seen_keys.update(keys)
        sys.stdout.write(f"ok  {path.name}\n")
    if seen_environments != EXPECTED_ENVIRONMENTS:
        msg = "both sandbox and live packs are required"
        raise ValueError(msg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
