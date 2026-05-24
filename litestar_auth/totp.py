"""Time-based one-time password helpers."""

from __future__ import annotations

# ruff: noqa: F401
from litestar_auth import _totp_stores
from litestar_auth._totp_primitive import (
    TIME_STEP_SECONDS,
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_DRIFT_STEPS,
    USED_TOTP_CODE_TTL_SECONDS,
    TotpAlgorithm,
    _current_counter,
    _decode_secret,
    _generate_totp_code,
    _verify_totp_counter,
    generate_totp_secret,
    generate_totp_uri,
    hmac,
    time,
    verify_totp,
)
from litestar_auth._totp_recovery import (
    DEFAULT_TOTP_RECOVERY_CODE_COUNT,
    TOTP_RECOVERY_CODE_HEX_BYTES,
    TotpRecoveryCodeUserManager,
    _consume_matching_recovery_code,
    _get_dummy_argon2_hash,
    _recovery_code_lookup_hex,
    build_recovery_code_index,
    generate_totp_recovery_codes,
)
from litestar_auth._totp_verify import SecurityWarning, logger, verify_totp_with_store
from litestar_auth.exceptions import ConfigurationError

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
