"""Time-based one-time password helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import secrets
import struct
import time
import warnings
from typing import Literal, Protocol
from urllib.parse import quote, urlencode

from litestar_auth import _totp_stores
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper

DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX = _totp_stores.DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX
DEFAULT_TOTP_USED_KEY_PREFIX = _totp_stores.DEFAULT_TOTP_USED_KEY_PREFIX
InMemoryTotpEnrollmentStore = _totp_stores.InMemoryTotpEnrollmentStore
InMemoryUsedTotpCodeStore = _totp_stores.InMemoryUsedTotpCodeStore
RedisTotpEnrollmentStore = _totp_stores.RedisTotpEnrollmentStore
RedisTotpEnrollmentStoreClient = _totp_stores.RedisTotpEnrollmentStoreClient
RedisUsedTotpCodeStore = _totp_stores.RedisUsedTotpCodeStore
RedisUsedTotpCodeStoreClient = _totp_stores.RedisUsedTotpCodeStoreClient
TotpEnrollmentStore = _totp_stores.TotpEnrollmentStore
TotpReplayProtection = _totp_stores.TotpReplayProtection
UsedTotpCodeStore = _totp_stores.UsedTotpCodeStore
UsedTotpMarkResult = _totp_stores.UsedTotpMarkResult

TIME_STEP_SECONDS = 30
TOTP_DRIFT_STEPS: int = 1

# RFC 4226 S4 recommends HMAC key length matching the hash output length.
_SECRET_BYTES_BY_ALGORITHM: dict[TotpAlgorithm, int] = {
    "SHA256": 32,
    "SHA512": 64,
}
# Match replay-store retention to the full drift-validation span: counters in
# ``range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1)`` cover ``2 * TOTP_DRIFT_STEPS + 1``
# step-sized windows (e.g. 90 s when drift is 1 and the step is 30 s).
USED_TOTP_CODE_TTL_SECONDS = TIME_STEP_SECONDS * (2 * TOTP_DRIFT_STEPS + 1)
TOTP_DIGITS = 6
TOTP_ALGORITHM = "SHA256"
DEFAULT_TOTP_RECOVERY_CODE_COUNT = 10
# DECISION: 28 hex chars gives 112 bits per single-use recovery code, matching
# NIST SP 800-63B lookup-secret entropy guidance while still remaining printable.
TOTP_RECOVERY_CODE_HEX_BYTES = 14

type TotpAlgorithm = Literal["SHA256", "SHA512"]

__all__ = (
    "DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX",
    "DEFAULT_TOTP_RECOVERY_CODE_COUNT",
    "DEFAULT_TOTP_USED_KEY_PREFIX",
    "TIME_STEP_SECONDS",
    "TOTP_ALGORITHM",
    "TOTP_DIGITS",
    "TOTP_DRIFT_STEPS",
    "TOTP_RECOVERY_CODE_HEX_BYTES",
    "InMemoryTotpEnrollmentStore",
    "InMemoryUsedTotpCodeStore",
    "RedisTotpEnrollmentStore",
    "RedisTotpEnrollmentStoreClient",
    "RedisUsedTotpCodeStore",
    "RedisUsedTotpCodeStoreClient",
    "SecurityWarning",
    "TotpAlgorithm",
    "TotpEnrollmentStore",
    "TotpRecoveryCodeUserManager",
    "TotpReplayProtection",
    "UsedTotpCodeStore",
    "UsedTotpMarkResult",
    "build_recovery_code_index",
    "generate_totp_recovery_codes",
    "generate_totp_secret",
    "generate_totp_uri",
    "verify_totp",
    "verify_totp_with_store",
)

_TOTP_HASH_MAP: dict[TotpAlgorithm, str] = {
    "SHA256": "sha256",
    "SHA512": "sha512",
}

logger = logging.getLogger(__name__)
_DUMMY_ARGON2_HASH = PasswordHelper.from_defaults().hash(secrets.token_hex(16))


def _validate_totp_algorithm(algorithm: TotpAlgorithm) -> TotpAlgorithm:
    """Return ``algorithm`` when supported, otherwise raise a clear error.

    Raises:
        ValueError: If ``algorithm`` is not supported.
    """
    if algorithm in _TOTP_HASH_MAP:
        return algorithm
    supported_algorithms = ", ".join(_TOTP_HASH_MAP)
    msg = f"Unsupported TOTP algorithm {algorithm!r}. Supported algorithms: {supported_algorithms}."
    raise ValueError(msg)


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


class SecurityWarning(UserWarning):
    """Warning emitted for security-sensitive insecure defaults (TOTP, plugin startup, etc.)."""


class TotpRecoveryCodeUserManager[UP](Protocol):
    """User-manager behavior required to verify and consume TOTP recovery codes."""

    async def find_recovery_code_hash_by_lookup(self, user: UP, lookup_hex: str) -> str | None:
        """Return the Argon2 hash matching ``lookup_hex``, if active."""

    async def consume_recovery_code_by_lookup(self, user: UP, lookup_hex: str) -> bool:
        """Atomically consume the active recovery-code entry for ``lookup_hex``."""

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
    if candidate_hash is None:
        _ = helper.verify(normalized_code, _DUMMY_ARGON2_HASH)
        return False

    if not helper.verify(normalized_code, candidate_hash):
        _ = helper.verify(normalized_code, _DUMMY_ARGON2_HASH)
        return False

    return await user_manager.consume_recovery_code_by_lookup(user, lookup_hex)


def generate_totp_secret(algorithm: TotpAlgorithm = TOTP_ALGORITHM) -> str:
    """Generate a base32-encoded TOTP secret sized to the algorithm's HMAC output.

    Per RFC 4226 Section 4, the shared secret length should match the HMAC
    output length: 32 bytes for SHA-256 or 64 bytes for SHA-512.

    Args:
        algorithm: TOTP hash algorithm; determines secret byte length.

    Returns:
        A random base32 secret without RFC padding.
    """
    secret_bytes = _SECRET_BYTES_BY_ALGORITHM[_validate_totp_algorithm(algorithm)]
    random_bytes = secrets.token_bytes(secret_bytes)
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def generate_totp_uri(
    secret: str,
    email: str,
    issuer: str,
    *,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
) -> str:
    """Build an otpauth URI suitable for QR-code generation.

    Returns:
        An ``otpauth://`` URI for authenticator apps.
    """
    algorithm = _validate_totp_algorithm(algorithm)
    label = quote(f"{issuer}:{email}")
    query_params: dict[str, str] = {
        "secret": secret,
        "issuer": issuer,
        "digits": str(TOTP_DIGITS),
        "period": str(TIME_STEP_SECONDS),
        "algorithm": algorithm,
    }
    query = urlencode(query_params)
    return f"otpauth://totp/{label}?{query}"


def verify_totp(secret: str, code: str, *, algorithm: TotpAlgorithm = TOTP_ALGORITHM) -> bool:
    """Validate a TOTP code for the current time window only.

    Returns:
        ``True`` when the code matches the current time step, otherwise ``False``.
    """
    return _verify_totp_counter(secret, code, algorithm=algorithm) is not None


async def verify_totp_with_store(
    secret: str,
    code: str,
    *,
    replay: TotpReplayProtection,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
) -> bool:
    """Validate a TOTP code and optionally reject same-window replays.

    Returns:
        ``True`` when the code is valid and has not already been used for ``replay.user_id``.

    Raises:
        ConfigurationError: If replay protection is required and no replay store is configured
            outside testing mode.
    """
    counter = _verify_totp_counter(secret, code, algorithm=algorithm)
    if counter is None:
        logger.warning("TOTP verification failed.", extra={"event": "totp_failed", "user_id": str(replay.user_id)})
        return False

    if replay.used_tokens_store is None:
        if replay.require_replay_protection and not replay.unsafe_testing:
            msg = "TOTP replay protection is required in production. Configure a UsedTotpCodeStore."
            raise ConfigurationError(msg)
        warnings.warn(
            "TOTP replay protection is DISABLED because used_tokens_store=None.",
            SecurityWarning,
            stacklevel=2,
        )
        return True

    mark_result = await replay.used_tokens_store.mark_used(replay.user_id, counter, USED_TOTP_CODE_TTL_SECONDS)
    if mark_result.stored:
        return True
    if mark_result.rejected_as_replay:
        logger.warning("TOTP replay detected.", extra={"event": "totp_replay", "user_id": str(replay.user_id)})
    else:
        logger.warning(
            "TOTP used-code store rejected verification under capacity pressure (fail closed).",
            extra={"event": "totp_replay_store_capacity", "user_id": str(replay.user_id)},
        )
    return False


def _current_counter() -> int:
    """Return the current RFC 6238 counter value."""
    return int(time.time() // TIME_STEP_SECONDS)


def _verify_totp_counter(secret: str, code: str, *, algorithm: TotpAlgorithm = TOTP_ALGORITHM) -> int | None:
    """Return the matched counter when the code is valid, otherwise ``None``."""
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None

    try:
        current_counter = _current_counter()
        for drift in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
            candidate_counter = current_counter + drift
            expected_code = _generate_totp_code(secret, candidate_counter, algorithm=algorithm)
            if hmac.compare_digest(expected_code, code):
                return candidate_counter
    except binascii.Error:
        return None

    return None


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret, restoring RFC padding when needed.

    Returns:
        The decoded secret bytes.
    """
    normalized_secret = secret.strip().upper()
    padding = "=" * (-len(normalized_secret) % 8)
    return base64.b32decode(f"{normalized_secret}{padding}", casefold=True)


def _generate_totp_code(
    secret: str,
    counter: int,
    *,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
) -> str:
    """Generate the 6-digit TOTP code for a specific counter.

    Returns:
        A zero-padded 6-digit TOTP string.
    """
    algorithm = _validate_totp_algorithm(algorithm)
    secret_bytes = _decode_secret(secret)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, _TOTP_HASH_MAP[algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated_hash = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = truncated_hash % (10**TOTP_DIGITS)
    return f"{otp:0{TOTP_DIGITS}d}"
