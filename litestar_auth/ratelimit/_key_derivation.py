"""Rate-limit key derivation helpers and constants."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from litestar_auth._keyed_digest import keyed_account_identifier_hex

from ._protocol import AccountLockoutKey

if TYPE_CHECKING:
    from litestar_auth.types import LoginIdentifier

DEFAULT_KEY_PREFIX = "litestar_auth:ratelimit:"
DEFAULT_ACCOUNT_LOCKOUT_KEY_PREFIX = "litestar_auth:account-lockout:"
_ACCOUNT_LOCKOUT_KEY_CONTEXT = b"litestar-auth:account-lockout-key:v1"
_RATE_LIMIT_KEY_DERIVATION_SALT = b"litestar-auth:rate-limit-key:v5"
_RATE_LIMIT_KEY_DERIVATION_ITERATIONS = 4096
_RATE_LIMIT_KEY_PART_BYTES = 16


def account_lockout_key(
    identifier: str,
    *,
    key: str | bytes,
    login_identifier: LoginIdentifier = "email",
) -> AccountLockoutKey:
    """Return the opaque keyed digest used for account lockout storage.

    The identifier is normalized with the same policy the user store uses for the
    given ``login_identifier`` mode, so the lockout key maps 1:1 to the resolved
    account and cannot be evaded or collided via normalization drift.

    Returns:
        Non-reversible digest of the store-normalized login identifier.
    """
    return AccountLockoutKey(
        keyed_account_identifier_hex(
            key,
            identifier,
            login_identifier=login_identifier,
            context=_ACCOUNT_LOCKOUT_KEY_CONTEXT,
        ),
    )


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
