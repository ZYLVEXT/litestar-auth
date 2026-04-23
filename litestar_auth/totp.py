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
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable
from urllib.parse import quote, urlencode

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._redis_protocols import (
    RedisConditionalSetClient,
    RedisDeleteClient,
    RedisExpiringValueWriteClient,
    RedisNullableScriptEvalClient,
)
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

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

type TotpAlgorithm = Literal["SHA256", "SHA512"]

_TOTP_HASH_MAP: dict[TotpAlgorithm, str] = {
    "SHA256": "sha256",
    "SHA512": "sha512",
}

DEFAULT_TOTP_USED_KEY_PREFIX = "litestar_auth:totp:used:"
DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX = "litestar_auth:totp:enroll:"
_TOTP_ENROLLMENT_VALUE_SEPARATOR = ":"
_REDIS_TOTP_ENROLLMENT_CONSUME_SCRIPT = """
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
local expected_prefix = ARGV[1] .. ":"
if string.sub(value, 1, string.len(expected_prefix)) ~= expected_prefix then
  return nil
end
redis.call("DEL", KEYS[1])
return string.sub(value, string.len(expected_prefix) + 1)
"""

logger = logging.getLogger(__name__)

_load_used_totp_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisUsedTotpCodeStore")
_load_enrollment_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisTotpEnrollmentStore")


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


@dataclass(frozen=True, slots=True)
class _TotpEnrollmentEntry:
    """Process-local pending TOTP enrollment record."""

    jti: str
    secret: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class UsedTotpMarkResult:
    """Outcome of attempting to record a used ``(user_id, counter)`` pair in a replay store.

    Attributes:
        stored: ``True`` when the pair was newly recorded.
        rejected_as_replay: When ``stored`` is ``False``, ``True`` if the pair was already
            recorded (replay). ``False`` when the store rejected the insert for another reason,
            such as in-memory capacity exhaustion (fail-closed).
    """

    stored: bool
    rejected_as_replay: bool = False


class SecurityWarning(UserWarning):
    """Warning emitted for security-sensitive insecure defaults (TOTP, plugin startup, etc.)."""


@runtime_checkable
class TotpEnrollmentStore(Protocol):
    """Short-TTL store for pending TOTP enrollment secrets keyed by user and token JTI.

    Implementations must make ``consume`` atomic: two concurrent consumers for the
    same ``user_id`` and ``jti`` must not both receive the secret. ``save`` replaces
    any previous pending enrollment for the same user so only the latest
    enrollment token can be confirmed.
    """

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Persist a pending enrollment secret, replacing any previous one for the user.

        Returns:
            ``True`` when the secret was stored; ``False`` when the store refused
            the insert under capacity pressure and callers should fail closed.
        """

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Atomically return and delete the latest matching secret, or ``None`` if absent or stale."""

    async def clear(self, *, user_id: str) -> None:
        """Delete any pending enrollment for the user."""


@runtime_checkable
class UsedTotpCodeStore(Protocol):
    """Persistence for used TOTP codes keyed by user and counter."""

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Atomically record a `(user_id, counter)` pair when unused.

        Returns:
            :class:`UsedTotpMarkResult` with ``stored=True`` when the pair was newly recorded.
            When ``stored`` is ``False``, set ``rejected_as_replay=True`` if the pair was already
            stored; otherwise callers such as :func:`verify_totp_with_store` can surface
            non-replay failures (for example in-memory capacity pressure) as distinct telemetry.
        """


class RedisUsedTotpCodeStoreClient(RedisConditionalSetClient, Protocol):
    """Minimal Redis client interface for TOTP replay store (SET key value NX PX ttl_ms)."""


class RedisTotpEnrollmentStoreClient(
    RedisDeleteClient,
    RedisExpiringValueWriteClient,
    RedisNullableScriptEvalClient,
    Protocol,
):
    """Minimal Redis client interface for pending TOTP enrollment state."""


class RedisTotpEnrollmentStore:
    """Redis-backed pending-enrollment store; safe for multi-worker and multi-pod deployments."""

    def __init__(
        self,
        *,
        redis: RedisTotpEnrollmentStoreClient,
        key_prefix: str = DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX,
    ) -> None:
        """Store the Redis client and key prefix."""
        _load_enrollment_redis_asyncio()
        self._redis = redis
        self._key_prefix = key_prefix

    @property
    def is_shared_across_workers(self) -> bool:
        """Redis-backed enrollment state is visible across workers."""
        return True

    def _key(self, user_id: str) -> str:
        """Return the Redis key for a user's latest pending enrollment."""
        user_digest = hashlib.sha256(user_id.encode()).hexdigest()[:32]
        return f"{self._key_prefix}{user_digest}"

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Persist the latest pending enrollment secret for ``user_id`` with a TTL.

        Returns:
            ``True`` when the secret is stored.
        """
        value = f"{jti}{_TOTP_ENROLLMENT_VALUE_SEPARATOR}{secret}"
        await self._redis.setex(self._key(user_id), max(ttl_seconds, 1), value)
        return True

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Atomically consume the latest pending enrollment if its JTI matches.

        Returns:
            Stored secret value, or ``None`` if the state is absent or stale.
        """
        value = await self._redis.eval(_REDIS_TOTP_ENROLLMENT_CONSUME_SCRIPT, 1, self._key(user_id), jti)
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode()
        return str(value)

    async def clear(self, *, user_id: str) -> None:
        """Delete any pending enrollment for ``user_id``."""
        await self._redis.delete(self._key(user_id))


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
        _load_used_totp_redis_asyncio()
        self._redis = redis
        self._key_prefix = key_prefix

    def _key(self, user_id: Hashable, counter: int) -> str:
        """Return the Redis key for a (user_id, counter) pair."""
        return f"{self._key_prefix}{user_id!s}:{counter}"

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Atomically record a used (user_id, counter) pair via SET key 1 NX PX ttl_ms.

        Returns:
            ``UsedTotpMarkResult(stored=True)`` when the pair was newly stored, or
            ``UsedTotpMarkResult(stored=False, rejected_as_replay=True)`` when the key already
            existed (replay).
        """
        key = self._key(user_id, counter)
        ttl_ms = int(ttl_seconds * 1000)
        result = await self._redis.set(key, "1", nx=True, px=ttl_ms)
        if result is True:
            return UsedTotpMarkResult(stored=True)
        return UsedTotpMarkResult(stored=False, rejected_as_replay=True)


class InMemoryUsedTotpCodeStore:
    """Async-safe in-memory replay cache for successful TOTP verifications.

    Not safe for multi-process or multi-host deployments; use :class:`RedisUsedTotpCodeStore`
    for shared storage (e.g. multi-worker or multi-pod).

    **Capacity / replay protection:** When ``len(entries) >= max_entries`` after dropping
    expired rows, :meth:`mark_used` **fails closed** and returns a result with ``stored=False``
    (and ``rejected_as_replay=False``) instead of evicting
    still-valid replay records to make room. That avoids weakening replay protection under
    load (previously the store evicted the soonest-to-expire active entry). Operators
    should size ``max_entries`` for peak legitimate traffic or switch to Redis-backed storage.
    Prior releases evicted the soonest-to-expire active entry under pressure; that behavior
    was removed because it could widen replay windows.
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

    async def mark_used(self, user_id: Hashable, counter: int, ttl_seconds: float) -> UsedTotpMarkResult:
        """Store a used code pair until its TTL elapses.

        Returns:
            ``UsedTotpMarkResult(stored=True)`` when the pair was newly stored.
            ``UsedTotpMarkResult(stored=False, rejected_as_replay=True)`` when the pair was
            already recorded (replay). ``UsedTotpMarkResult(stored=False, rejected_as_replay=False)``
            when the store is at ``max_entries`` and no expired entries remain to reclaim
            (fail-closed under capacity pressure; see class docs).
        """
        async with self._lock:
            now = self._clock()
            self._prune(now)
            key = (user_id, counter)
            if key in self._entries:
                return UsedTotpMarkResult(stored=False, rejected_as_replay=True)

            if len(self._entries) >= self.max_entries:
                logger.error(
                    "Rejected in-memory TOTP replay-store insert: capacity %d reached with no "
                    "expired entries to reclaim (fail closed). Use RedisUsedTotpCodeStore or "
                    "increase max_entries for high-volume deployments.",
                    self.max_entries,
                )
                return UsedTotpMarkResult(stored=False, rejected_as_replay=False)

            self._entries[key] = now + ttl_seconds
            return UsedTotpMarkResult(stored=True)

    def _prune(self, now: float) -> None:
        """Drop expired replay-cache entries."""
        expired_keys = [key for key, expires_at in self._entries.items() if expires_at <= now]
        for key in expired_keys:
            del self._entries[key]


class InMemoryTotpEnrollmentStore:
    """Async-safe process-local pending TOTP enrollment store.

    This store is suitable for tests and single-process development. Production
    deployments with multiple workers should use :class:`RedisTotpEnrollmentStore`
    or another shared implementation.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 50_000,
    ) -> None:
        """Initialize an empty enrollment store.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self._clock = clock
        self.max_entries = max_entries
        self._entries: dict[str, _TotpEnrollmentEntry] = {}
        self._lock = asyncio.Lock()

    @property
    def is_shared_across_workers(self) -> bool:
        """In-memory enrollment state is process-local."""
        return False

    async def save(self, *, user_id: str, jti: str, secret: str, ttl_seconds: int) -> bool:
        """Store the latest pending enrollment for ``user_id``.

        Returns:
            ``True`` when stored, or ``False`` when capacity pressure rejects a new user key.
        """
        async with self._lock:
            now = self._clock()
            self._prune(now)
            if user_id not in self._entries and len(self._entries) >= self.max_entries:
                logger.error(
                    "Rejected in-memory TOTP enrollment insert: capacity %d reached with no "
                    "expired entries to reclaim (fail closed). Use RedisTotpEnrollmentStore or "
                    "increase max_entries for high-volume deployments.",
                    self.max_entries,
                    extra={"event": "totp_enrollment_store_capacity"},
                )
                return False

            self._entries[user_id] = _TotpEnrollmentEntry(
                jti=jti,
                secret=secret,
                expires_at=now + max(ttl_seconds, 1),
            )
            return True

    async def consume(self, *, user_id: str, jti: str) -> str | None:
        """Consume the latest pending enrollment for ``user_id`` when ``jti`` matches.

        Returns:
            Stored secret value, or ``None`` if the state is absent, stale, or expired.
        """
        async with self._lock:
            now = self._clock()
            self._prune(now)
            entry = self._entries.get(user_id)
            if entry is None or not hmac.compare_digest(entry.jti, jti):
                return None

            del self._entries[user_id]
            return entry.secret

    async def clear(self, *, user_id: str) -> None:
        """Clear any pending enrollment for ``user_id``."""
        async with self._lock:
            self._entries.pop(user_id, None)

    def _prune(self, now: float) -> None:
        """Drop expired pending-enrollment rows."""
        expired_user_ids = [user_id for user_id, entry in self._entries.items() if entry.expires_at <= now]
        for user_id in expired_user_ids:
            del self._entries[user_id]


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


async def verify_totp_with_store(  # noqa: PLR0913
    secret: str,
    code: str,
    *,
    user_id: Hashable,
    used_tokens_store: UsedTotpCodeStore | None = None,
    algorithm: TotpAlgorithm = TOTP_ALGORITHM,
    require_replay_protection: bool = True,
    unsafe_testing: bool = False,
) -> bool:
    """Validate a TOTP code and optionally reject same-window replays.

    Returns:
        ``True`` when the code is valid and has not already been used for ``user_id``.

    Raises:
        ConfigurationError: If ``require_replay_protection=True`` and no replay store is configured
            outside ``unsafe_testing`` mode.
    """
    counter = _verify_totp_counter(secret, code, algorithm=algorithm)
    if counter is None:
        logger.warning("TOTP verification failed.", extra={"event": "totp_failed", "user_id": str(user_id)})
        return False

    if used_tokens_store is None:
        if require_replay_protection and not unsafe_testing:
            msg = "TOTP replay protection is required in production. Configure a UsedTotpCodeStore."
            raise ConfigurationError(msg)
        warnings.warn(
            "TOTP replay protection is DISABLED because used_tokens_store=None.",
            SecurityWarning,
            stacklevel=2,
        )
        return True

    mark_result = await used_tokens_store.mark_used(user_id, counter, USED_TOTP_CODE_TTL_SECONDS)
    if mark_result.stored:
        return True
    if mark_result.rejected_as_replay:
        logger.warning("TOTP replay detected.", extra={"event": "totp_replay", "user_id": str(user_id)})
    else:
        logger.warning(
            "TOTP used-code store rejected verification under capacity pressure (fail closed).",
            extra={"event": "totp_replay_store_capacity", "user_id": str(user_id)},
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
