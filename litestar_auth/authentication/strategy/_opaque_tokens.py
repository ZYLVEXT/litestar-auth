"""Shared opaque-token primitives for stateful authentication strategies."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def digest_opaque_token(*, token_hash_secret: bytes, token: str) -> str:
    """Return the keyed digest stored for a raw opaque token."""
    return hmac.new(
        token_hash_secret,
        token.encode(),
        hashlib.sha256,
    ).hexdigest()


def mint_opaque_token(*, token_bytes: int, token_hash_secret: bytes) -> tuple[str, str]:
    """Return a new raw opaque token and the keyed digest to persist."""
    token = secrets.token_urlsafe(token_bytes)
    return token, digest_opaque_token(token_hash_secret=token_hash_secret, token=token)


def build_opaque_token_key(*, key_prefix: str, token_hash_secret: bytes, token: str) -> str:
    """Return the namespaced storage key for an opaque token digest."""
    return f"{key_prefix}{digest_opaque_token(token_hash_secret=token_hash_secret, token=token)}"
