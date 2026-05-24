"""TOTP recovery-code helpers."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Protocol

from litestar_auth.password import PasswordHelper

DEFAULT_TOTP_RECOVERY_CODE_COUNT = 10
# DECISION: 28 hex chars gives 112 bits per single-use recovery code, matching
# NIST SP 800-63B lookup-secret entropy guidance while still remaining printable.
TOTP_RECOVERY_CODE_HEX_BYTES = 14

_DUMMY_ARGON2_HASH: str | None = None


def generate_totp_recovery_codes(*, count: int = DEFAULT_TOTP_RECOVERY_CODE_COUNT) -> tuple[str, ...]:
    """Return distinct plaintext recovery codes for a TOTP enrollment.

    Returns:
        A tuple of unique 112-bit hex recovery codes.

    Raises:
        ValueError: If ``count`` is negative.
    """
    if count < 0:
        msg = "Recovery-code count cannot be negative."
        raise ValueError(msg)

    codes: set[str] = set()
    while len(codes) < count:
        codes.add(secrets.token_hex(TOTP_RECOVERY_CODE_HEX_BYTES))
    return tuple(codes)


def _recovery_code_lookup_hex(code: str, *, lookup_secret: bytes) -> str:
    """Return the stable keyed lookup digest for a recovery code."""
    normalized_code = code.casefold()
    return hmac.new(lookup_secret, normalized_code.encode("utf-8"), hashlib.sha256).hexdigest()


def build_recovery_code_index(
    codes: tuple[str, ...],
    *,
    lookup_secret: bytes,
    password_helper: PasswordHelper | None = None,
) -> dict[str, str]:
    """Build a keyed lookup index for TOTP recovery-code hashes.

    Returns:
        Mapping of HMAC-SHA-256 lookup hex digests to Argon2 hashes.
    """
    helper = password_helper or PasswordHelper.from_defaults()
    return {
        _recovery_code_lookup_hex(code, lookup_secret=lookup_secret): helper.hash(code.casefold()) for code in codes
    }


class TotpRecoveryCodeUserManager[UP](Protocol):
    """User-manager behavior required to verify and consume TOTP recovery codes."""

    async def find_recovery_code_hash_by_lookup(self, user: UP, lookup_hex: str) -> str | None:
        """Return the Argon2 hash matching ``lookup_hex``, if active."""

    async def consume_recovery_code_by_lookup(self, user: UP, lookup_hex: str) -> bool:
        """Atomically consume the active recovery-code entry for ``lookup_hex``.

        Concurrent callers presenting the same recovery code MUST observe
        exactly one success and N-1 failures.
        """

    @property
    def recovery_code_lookup_secret(self) -> bytes | None:
        """Return the HMAC lookup key for recovery-code verification."""


async def _consume_matching_recovery_code[UP](
    user_manager: TotpRecoveryCodeUserManager[UP],
    user: UP,
    submitted_code: str,
    *,
    password_helper: PasswordHelper | None = None,
) -> bool:
    """Consume ``submitted_code`` when it matches one active TOTP recovery-code hash.

    Performs exactly one Argon2 verify per call, regardless of whether the
    submitted code's HMAC lookup hits an indexed entry. This both equalises
    timing across the no-hit / hit-and-mismatch / hit-and-match paths and
    bounds the per-request Argon2 work, since the previous implementation
    ran a second dummy verify on the hit-and-mismatch branch and gave
    attackers a 2x DoS amplification on submitted codes whose lookup digest
    happened to collide with an indexed entry.

    Returns:
        ``True`` when one active hash matched and was consumed.
    """
    lookup_secret = user_manager.recovery_code_lookup_secret
    if lookup_secret is None:
        return False

    helper = password_helper or PasswordHelper.from_defaults()
    normalized_code = submitted_code.casefold()
    lookup_hex = _recovery_code_lookup_hex(normalized_code, lookup_secret=lookup_secret)
    candidate_hash = await user_manager.find_recovery_code_hash_by_lookup(user, lookup_hex)
    target_hash = candidate_hash if candidate_hash is not None else _get_dummy_argon2_hash()
    matched = helper.verify(normalized_code, target_hash)
    if not matched or candidate_hash is None:
        return False
    return await user_manager.consume_recovery_code_by_lookup(user, lookup_hex)


def _get_dummy_argon2_hash() -> str:
    """Return the process-local dummy recovery-code hash, creating it lazily."""
    global _DUMMY_ARGON2_HASH  # noqa: PLW0603
    if _DUMMY_ARGON2_HASH is None:
        _DUMMY_ARGON2_HASH = PasswordHelper.from_defaults().hash(secrets.token_hex(16))
    return _DUMMY_ARGON2_HASH
