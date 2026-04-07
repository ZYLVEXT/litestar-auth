"""Time-based one-time password helpers."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import secrets
import struct
import time
import warnings
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable
from urllib.parse import quote, urlencode

from litestar_auth._compat import _load_redis_asyncio as _load_redis_asyncio_compat
from litestar_auth._redis_protocols import RedisConditionalSetClient
from litestar_auth.config import is_testing
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

SECRET_BYTES = 20
TIME_STEP_SECONDS = 30

# RFC 4226 S4 recommends HMAC key length matching the hash output length.
_SECRET_BYTES_BY_ALGORITHM: dict[TotpAlgorithm, int] = {
    "SHA1": 20,
    "SHA256": 32,
    "SHA512": 64,
}
USED_TOTP_CODE_TTL_SECONDS = TIME_STEP_SECONDS * 2
TOTP_DIGITS = 6
# Default algorithm for new TOTP enrollments. Deployments that need legacy
# authenticator compatibility can override this via the totp_algorithm
# parameter and choose "SHA1" explicitly.
TOTP_ALGORITHM = "SHA256"
TOTP_DRIFT_STEPS: int = 1

type TotpAlgorithm = Literal["SHA1", "SHA256", "SHA512"]

_TOTP_HASH_MAP: dict[TotpAlgorithm, Any] = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

DEFAULT_TOTP_USED_KEY_PREFIX = "litestar_auth:totp:used:"

logger = logging.getLogger(__name__)

_load_redis_asyncio = partial(_load_redis_asyncio_compat, feature_name="RedisUsedTotpCodeStore")


class SecurityWarning(UserWarning):
    """Warning emitted for security-sensitive insecure defaults (TOTP, plugin startup, etc.)."""


@runtime_checkable
class UsedTotpCodeStore(Protocol):
    """Persistence for used TOTP codes keyed by user and counter."""

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> bool:
        """Atomically record a `(user_id, counter)` pair when unused.

        Returns:
            ``True`` when the pair was newly stored, otherwise ``False``.
        """


class RedisUsedTotpCodeStoreClient(RedisConditionalSetClient, Protocol):
    """Minimal Redis client interface for TOTP replay store (SET key value NX PX ttl_ms)."""


class RedisUsedTotpCodeStore:
    """Redis-backed replay store for TOTP codes; safe for multi-worker and multi-pod deployments.

    For the higher-level shared-client Redis preset that can also derive
    ``AuthRateLimitConfig``, see ``litestar_auth.contrib.redis.RedisAuthPreset``.
    """

    def __init__(
        self,
        *,
        redis: RedisUsedTotpCodeStoreClient,
        key_prefix: str = DEFAULT_TOTP_USED_KEY_PREFIX,
    ) -> None:
        """Store the Redis client and key prefix.

        Args:
            redis: Async Redis client supporting ``set(name, value, nx=True, px=ttl_ms)``
                (e.g. ``redis.asyncio.Redis``).
            key_prefix: Prefix for replay keys; keys are ``{key_prefix}{user_id}:{counter}``.
        """
        _load_redis_asyncio()
        self._redis = redis
        self._key_prefix = key_prefix

    def _key(self, user_id: Hashable, counter: int) -> str:
        """Return the Redis key for a (user_id, counter) pair."""
        return f"{self._key_prefix}{user_id!s}:{counter}"

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> bool:
        """Atomically record a used (user_id, counter) pair via SET key 1 NX PX ttl_ms.

        Returns:
            ``True`` when the pair was newly stored, ``False`` for a replay.
        """
        key = self._key(user_id, counter)
        ttl_ms = int(ttl_seconds * 1000)
        result = await self._redis.set(key, "1", nx=True, px=ttl_ms)
        return result is True


class InMemoryUsedTotpCodeStore:
    """Async-safe in-memory replay cache for successful TOTP verifications.

    Not safe for multi-process or multi-host deployments; use :class:`RedisUsedTotpCodeStore`
    for shared storage (e.g. multi-worker or multi-pod).
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 50_000,
    ) -> None:
        """Store the monotonic clock and initialize cache state.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self._clock = clock
        self.max_entries = max_entries
        self._entries: dict[tuple[Hashable, int], float] = {}
        self._lock = asyncio.Lock()

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> bool:
        """Store a used code pair until its TTL elapses.

        Returns:
            ``True`` when the pair was stored, otherwise ``False`` for a replay.
        """
        async with self._lock:
            now = self._clock()
            self._prune(now)
            key = (user_id, counter)
            if key in self._entries:
                return False

            if len(self._entries) >= self.max_entries:
                self._prune(now)
                self._evict_oldest_until_below_cap()

            self._entries[key] = now + ttl_seconds
            return True

    def _prune(self, now: float) -> None:
        """Drop expired replay-cache entries."""
        expired_keys = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired_keys:
            del self._entries[key]

    def _evict_oldest_until_below_cap(self) -> None:
        """Drop entries soonest to expire until a new item can be inserted.

        Security: evicting by nearest-expiry rather than insertion order
        minimizes the window in which a recently accepted TOTP code could
        be replayed after eviction pressure.
        """
        while len(self._entries) >= self.max_entries:
            soonest_key = min(
                self._entries,
                key=lambda k: self._entries[k],
            )
            del self._entries[soonest_key]
            logger.warning(
                "Evicted TOTP replay entry from in-memory store (cap=%d reached); "
                "use RedisUsedTotpCodeStore in production.",
                self.max_entries,
            )


def generate_totp_secret(algorithm: TotpAlgorithm = TOTP_ALGORITHM) -> str:
    """Generate a base32-encoded TOTP secret sized to the algorithm's HMAC output.

    Per RFC 4226 Section 4, the shared secret length should match the HMAC
    output length: 20 bytes for SHA-1, 32 bytes for SHA-256, 64 bytes for
    SHA-512.  The ``SECRET_BYTES`` constant is retained for backward
    compatibility but is no longer the sole source of truth.

    Args:
        algorithm: TOTP hash algorithm; determines secret byte length.

    Returns:
        A random base32 secret without RFC padding.
    """
    secret_bytes = _SECRET_BYTES_BY_ALGORITHM.get(algorithm, SECRET_BYTES)
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


async def verify_totp_with_store(  # noqa: PLR0913
    secret: str,
    code: str,
    *,
    user_id: Hashable,
    used_tokens_store: UsedTotpCodeStore | None = None,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
    require_replay_protection: bool = True,
) -> bool:
    """Validate a TOTP code and optionally reject same-window replays.

    Returns:
        ``True`` when the code is valid and has not already been used for ``user_id``.

    Raises:
        ConfigurationError: If ``require_replay_protection=True`` and no replay store is configured
            outside testing mode.
    """
    counter = _verify_totp_counter(secret, code, algorithm=algorithm)
    if counter is None:
        logger.warning("TOTP verification failed.", extra={"event": "totp_failed", "user_id": str(user_id)})
        return False

    if used_tokens_store is None:
        if require_replay_protection and not is_testing():
            msg = "TOTP replay protection is required in production. Configure a UsedTotpCodeStore."
            raise ConfigurationError(msg)
        warnings.warn(
            "TOTP replay protection is DISABLED because used_tokens_store=None.",
            SecurityWarning,
            stacklevel=2,
        )
        return True

    accepted = await used_tokens_store.mark_used(user_id, counter, USED_TOTP_CODE_TTL_SECONDS)
    if not accepted:
        logger.warning("TOTP replay detected.", extra={"event": "totp_replay", "user_id": str(user_id)})
        return False
    return True


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
    except (binascii.Error, ValueError):
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
    secret_bytes = _decode_secret(secret)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, _TOTP_HASH_MAP[algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated_hash = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = truncated_hash % (10**TOTP_DIGITS)
    return f"{otp:0{TOTP_DIGITS}d}"
