"""RFC 6238 TOTP primitive helpers."""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import struct
import sys
import time
from typing import Literal, cast
from urllib.parse import quote, urlencode

TIME_STEP_SECONDS = 30
TOTP_DRIFT_STEPS: int = 1
USED_TOTP_CODE_TTL_SECONDS = TIME_STEP_SECONDS * (2 * TOTP_DRIFT_STEPS + 1)
TOTP_DIGITS = 6
TOTP_ALGORITHM = "SHA256"

type TotpAlgorithm = Literal["SHA256", "SHA512"]

_TOTP_HASH_MAP: dict[TotpAlgorithm, str] = {
    "SHA256": "sha256",
    "SHA512": "sha512",
}

# RFC 4226 S4 recommends HMAC key length matching the hash output length.
_SECRET_BYTES_BY_ALGORITHM: dict[TotpAlgorithm, int] = {
    "SHA256": 32,
    "SHA512": 64,
}


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


def _current_counter() -> int:
    """Return the current RFC 6238 counter value."""
    return int(time.time() // TIME_STEP_SECONDS)


def _verify_totp_counter(secret: str, code: str, *, algorithm: TotpAlgorithm = TOTP_ALGORITHM) -> int | None:
    """Return the matched counter when the code is valid, otherwise ``None``."""
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None

    try:
        current_counter = _get_facade_override("_current_counter", _current_counter)()
        generate_totp_code = _get_facade_override("_generate_totp_code", _generate_totp_code)
        for drift in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
            candidate_counter = current_counter + drift
            expected_code = generate_totp_code(secret, candidate_counter, algorithm=algorithm)
            if hmac.compare_digest(expected_code, code):
                return candidate_counter
    except binascii.Error:
        return None

    return None


def _get_facade_override[CallableT](name: str, default: CallableT) -> CallableT:
    """Return a patched ``litestar_auth.totp`` helper when tests replace one."""
    facade = sys.modules.get("litestar_auth.totp")
    if facade is None:
        return default
    value = getattr(facade, name, default)
    if value is default:
        return default
    return cast("CallableT", value)


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
