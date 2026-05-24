"""Rate-limit key derivation helpers and constants."""

from __future__ import annotations

import hashlib

DEFAULT_KEY_PREFIX = "litestar_auth:ratelimit:"
_RATE_LIMIT_KEY_DERIVATION_SALT = b"litestar-auth:rate-limit-key:v5"
_RATE_LIMIT_KEY_DERIVATION_ITERATIONS = 4096
_RATE_LIMIT_KEY_PART_BYTES = 16


def _safe_key_part(value: str) -> str:
    """Digest a key component to prevent delimiter injection and raw identifier storage.

    Returns:
        Scoped PBKDF2-HMAC-SHA-256 hex digest of the value for rate-limit key derivation.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        _RATE_LIMIT_KEY_DERIVATION_SALT,
        _RATE_LIMIT_KEY_DERIVATION_ITERATIONS,
        dklen=_RATE_LIMIT_KEY_PART_BYTES,
    ).hex()


def _bounded_hash_part(value: str, *, max_length: int) -> str | None:
    """Digest a trusted-bounded key component, or omit it when over cap.

    Returns:
        Digest for values up to ``max_length`` characters, otherwise ``None``.
    """
    if len(value) > max_length:
        return None
    return _safe_key_part(value)
