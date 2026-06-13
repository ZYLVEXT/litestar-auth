"""Internal keyed SHA-256 digest helpers."""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from typing import TYPE_CHECKING

from litestar_auth._email import normalize_email

if TYPE_CHECKING:
    from litestar_auth.types import LoginIdentifier


def keyed_bytes(key: bytes, payload: bytes) -> bytes:
    """Return the HMAC-SHA-256 digest bytes for ``payload``."""
    return hmac.new(key, payload, hashlib.sha256).digest()


def keyed_hex(key: bytes, *parts: bytes) -> str:
    """Return the HMAC-SHA-256 hex digest for one or more byte payload parts."""
    hmac_digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        hmac_digest.update(part)
    return hmac_digest.hexdigest()


def normalize_login_identifier(identifier: str) -> str:
    """Return the canonical login identifier (stripped, casefolded) for keyed digests."""
    return identifier.strip().casefold()


def normalize_account_identifier(identifier: str, *, login_identifier: LoginIdentifier) -> str:
    """Return the identifier normalized to mirror user-store identity resolution.

    Account-keyed digests (e.g. lockout counters) must map 1:1 to the account the
    store would resolve. Email mode applies the account email policy (NFKC +
    lowercase); username mode applies the store's stripped + lowercase rule.
    Mirroring the store -- rather than an independent ``casefold()`` -- closes two
    normalization-drift gaps: an attacker can no longer mint multiple keys for one
    account via NFKC/compatibility variants (lockout evasion), nor collide two
    distinct accounts onto one key via casefold-vs-lower folding (e.g. German
    sharp-s ``ß`` -> ``ss``).

    Returns:
        The store-equivalent normalized identifier.
    """
    if login_identifier == "email":
        try:
            return normalize_email(identifier)
        except ValueError:
            # Failed the stricter email policy, so the store lookup will also miss;
            # fall back to the store-equivalent form (NFKC + lowercase) for a stable key.
            return unicodedata.normalize("NFKC", identifier.strip()).lower()
    # Username lookups intentionally skip NFKC to match UserPolicy.normalize_username_lookup.
    return identifier.strip().lower()


def keyed_account_identifier_hex(
    key: str | bytes,
    identifier: str,
    *,
    login_identifier: LoginIdentifier,
    context: bytes,
) -> str:
    """Return a keyed digest for a login identifier under a domain-separation context.

    The identifier is normalized to mirror user-store identity resolution (see
    :func:`normalize_account_identifier`) so the digest is a faithful 1:1 account key.

    Returns:
        HMAC-SHA-256 hex digest of the store-normalized identifier under ``context``.
    """
    digest_key = key.encode("utf-8") if isinstance(key, str) else key
    normalized_identifier = normalize_account_identifier(identifier, login_identifier=login_identifier).encode("utf-8")
    return keyed_hex(digest_key, context, b"\x00", normalized_identifier)


def hkdf_sha256_32(key_material: bytes, *, salt: bytes, info: bytes) -> bytes:
    """Derive a 32-byte HKDF-SHA256 output with explicit domain separation.

    Returns:
        The single-block HKDF-SHA256 output.
    """
    pseudorandom_key = keyed_bytes(salt, key_material)
    return keyed_bytes(pseudorandom_key, info + b"\x01")
