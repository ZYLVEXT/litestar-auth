"""Internal keyed SHA-256 digest helpers."""

from __future__ import annotations

import hashlib
import hmac


def keyed_bytes(key: bytes, payload: bytes) -> bytes:
    """Return the HMAC-SHA-256 digest bytes for ``payload``."""
    return hmac.new(key, payload, hashlib.sha256).digest()


def keyed_hex(key: bytes, *parts: bytes) -> str:
    """Return the HMAC-SHA-256 hex digest for one or more byte payload parts."""
    hmac_digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        hmac_digest.update(part)
    return hmac_digest.hexdigest()
