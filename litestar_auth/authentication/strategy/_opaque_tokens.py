"""Shared opaque-token primitives for stateful authentication strategies."""

from __future__ import annotations

import hashlib
import hmac


def digest_opaque_token(*, token_hash_secret: bytes, token: str) -> str:
    """Return the keyed digest stored for a raw opaque token."""
    return hmac.new(
        token_hash_secret,
        token.encode(),
        hashlib.sha256,
    ).hexdigest()


def build_opaque_token_key(*, key_prefix: str, token_hash_secret: bytes, token: str) -> str:
    """Return the namespaced storage key for an opaque token digest."""
    return f"{key_prefix}{digest_opaque_token(token_hash_secret=token_hash_secret, token=token)}"
