"""Time-based one-time password helpers."""

from __future__ import annotations

from litestar_auth import _totp_stores
from litestar_auth._totp_primitive import (
    TIME_STEP_SECONDS,
    TOTP_ALGORITHM,
    TOTP_DIGITS,
    TOTP_DRIFT_STEPS,
    TotpAlgorithm,
    generate_totp_secret,
    generate_totp_uri,
    verify_totp,
)
from litestar_auth._totp_recovery import (
    DEFAULT_TOTP_RECOVERY_CODE_COUNT,
    TOTP_RECOVERY_CODE_HEX_BYTES,
    TotpRecoveryCodeUserManager,
    build_recovery_code_index,
    generate_totp_recovery_codes,
)
from litestar_auth._totp_verify import verify_totp_with_store
from litestar_auth.exceptions import SecurityWarning

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
