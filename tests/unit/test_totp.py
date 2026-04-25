"""Tests for TOTP helpers."""

from __future__ import annotations

import binascii
import importlib
import logging
import warnings
from typing import TYPE_CHECKING, cast
from urllib.parse import parse_qs, urlparse

import pytest

from litestar_auth import totp
from litestar_auth.contrib.redis import RedisAuthClientProtocol, RedisAuthPreset
from litestar_auth.password import PasswordHelper
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
EXPECTED_MIN_SECRET_LENGTH = 32
EXPECTED_COUNTER_AT_91_SECONDS = 3
STORE_CAP = 2
USED_TOTP_TTL_MS = 1_250
PENDING_JTI_TTL_SECONDS = 30
PENDING_JTI_TTL_FLOOR = PENDING_JTI_TTL_SECONDS - 1


def test_totp_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    original_security_warning = totp.SecurityWarning
    original_configuration_error = totp.ConfigurationError
    reloaded_module = importlib.reload(totp)
    reloaded_module.__dict__["SecurityWarning"] = original_security_warning
    reloaded_module.__dict__["ConfigurationError"] = original_configuration_error

    assert reloaded_module.InMemoryUsedTotpCodeStore.__name__ == totp.InMemoryUsedTotpCodeStore.__name__
    assert reloaded_module.InMemoryTotpEnrollmentStore.__name__ == totp.InMemoryTotpEnrollmentStore.__name__
    assert reloaded_module.RedisUsedTotpCodeStore.__name__ == totp.RedisUsedTotpCodeStore.__name__
    assert reloaded_module.RedisTotpEnrollmentStore.__name__ == totp.RedisTotpEnrollmentStore.__name__


def test_generate_totp_secret_returns_base32_secret() -> None:
    """Generated secrets are uppercase base32 strings without padding."""
    secret = totp.generate_totp_secret()

    assert len(secret) >= EXPECTED_MIN_SECRET_LENGTH
    assert secret.isupper()
    assert "=" not in secret
    assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


@pytest.mark.parametrize(
    ("algorithm", "expected_bytes"),
    [("SHA256", 32), ("SHA512", 64)],
)
def test_generate_totp_secret_size_matches_algorithm(algorithm: str, expected_bytes: int) -> None:
    """Secret byte length matches the HMAC output length per RFC 4226 S4."""
    secret = totp.generate_totp_secret(algorithm=algorithm)  # ty: ignore[invalid-argument-type]
    decoded = totp._decode_secret(secret)
    assert len(decoded) == expected_bytes


def test_generate_totp_secret_rejects_unsupported_algorithm() -> None:
    """Unsupported legacy TOTP algorithms fail with an explicit error."""
    with pytest.raises(ValueError, match="Unsupported TOTP algorithm 'SHA1'"):
        totp.generate_totp_secret(algorithm=cast("totp.TotpAlgorithm", "SHA1"))


def test_generate_totp_recovery_codes_returns_distinct_default_codes() -> None:
    """Recovery-code generation returns the configured number of 64-bit hex codes."""
    codes = totp.generate_totp_recovery_codes()

    assert len(codes) == totp.DEFAULT_TOTP_RECOVERY_CODE_COUNT
    assert len(set(codes)) == totp.DEFAULT_TOTP_RECOVERY_CODE_COUNT
    assert all(len(code) == totp.TOTP_RECOVERY_CODE_HEX_BYTES * 2 for code in codes)
    assert all(set(code) <= set("0123456789abcdef") for code in codes)


def test_generate_totp_recovery_codes_rejects_negative_count() -> None:
    """Invalid recovery-code counts fail explicitly."""
    with pytest.raises(ValueError, match="cannot be negative"):
        totp.generate_totp_recovery_codes(count=-1)


def test_hash_totp_recovery_codes_uses_password_helper_verification() -> None:
    """Recovery codes are stored in the same hash format as password secrets."""
    password_helper = PasswordHelper.from_defaults()
    codes = ("0123456789abcdef", "fedcba9876543210")

    hashes = totp.hash_totp_recovery_codes(codes, password_helper=password_helper)

    assert len(hashes) == len(codes)
    assert hashes[0] != codes[0]
    assert password_helper.verify(codes[0], hashes[0]) is True
    assert password_helper.verify("wrong-code", hashes[0]) is False


def test_totp_default_algorithm_is_sha256() -> None:
    """The library default TOTP algorithm is SHA256."""
    assert totp.TOTP_ALGORITHM == "SHA256"


def test_generate_totp_uri_returns_otpauth_uri() -> None:
    """The QR URI contains the expected otpauth fields."""
    uri = totp.generate_totp_uri("ABCDEF123456", "user@example.com", "Litestar Auth")
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "otpauth"
    assert parsed.netloc == "totp"
    assert parsed.path == "/Litestar%20Auth%3Auser%40example.com"
    assert query == {
        "algorithm": ["SHA256"],
        "digits": ["6"],
        "issuer": ["Litestar Auth"],
        "period": ["30"],
        "secret": ["ABCDEF123456"],
    }


def test_generate_totp_uri_includes_algorithm_for_sha256() -> None:
    """Explicit algorithms are encoded into the otpauth URI query string."""
    uri = totp.generate_totp_uri("ABCDEF123456", "user@example.com", "Litestar Auth", algorithm="SHA256")
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    assert query["algorithm"] == ["SHA256"]


@pytest.mark.parametrize("algorithm", ["SHA256", "SHA512"])
def test_generate_totp_uri_preserves_selected_algorithm(algorithm: str) -> None:
    """The otpauth URI query uses the selected TOTP algorithm."""
    uri = totp.generate_totp_uri("ABCDEF123456", "user@example.com", "Litestar Auth", algorithm=algorithm)  # ty: ignore[invalid-argument-type]
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    assert query["algorithm"] == [algorithm]


def test_generate_totp_code_uses_selected_algorithm() -> None:
    """Different algorithms produce different codes for the same inputs."""
    counter = 1
    sha256_code = totp._generate_totp_code(RFC_SECRET, counter, algorithm="SHA256")
    sha512_code = totp._generate_totp_code(RFC_SECRET, counter, algorithm="SHA512")

    assert sha256_code != sha512_code


@pytest.mark.parametrize("algorithm", ["SHA256", "SHA512"])
def test_verify_totp_accepts_current_window_code(monkeypatch: pytest.MonkeyPatch, algorithm: str) -> None:
    """Verification succeeds for the current 30-second time step across algorithms."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    current_code = totp._generate_totp_code(RFC_SECRET, 1, algorithm=algorithm)  # ty: ignore[invalid-argument-type]

    assert totp.verify_totp(RFC_SECRET, current_code, algorithm=algorithm) is True  # ty: ignore[invalid-argument-type]


def test_verify_totp_accepts_previous_window_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codes from the immediately previous time window are accepted."""
    monkeypatch.setattr(totp.time, "time", lambda: 89.0)
    previous_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert totp.verify_totp(RFC_SECRET, previous_code) is True


def test_verify_totp_accepts_next_window_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codes from the immediately next time window are accepted."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    next_counter = 2
    next_code = totp._generate_totp_code(RFC_SECRET, next_counter)

    assert totp.verify_totp(RFC_SECRET, next_code) is True


def test_verify_totp_rejects_outside_drift_window_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Codes more than one time window away are rejected."""
    monkeypatch.setattr(totp.time, "time", lambda: 119.0)
    old_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert totp.verify_totp(RFC_SECRET, old_code) is False


def test_verify_totp_rejects_invalid_codes_and_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed codes or secrets do not verify."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)

    assert totp.verify_totp(RFC_SECRET, "ABC123") is False
    assert totp.verify_totp(RFC_SECRET, "12345") is False
    assert totp.verify_totp("invalid***", "287082") is False


async def test_verify_totp_with_store_rejects_same_window_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay protection rejects the same `(user, counter)` after one success."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    store = totp.InMemoryUsedTotpCodeStore()
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-1",
            used_tokens_store=store,
        )
        is True
    )
    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-1",
            used_tokens_store=store,
        )
        is False
    )


async def test_verify_totp_with_store_warns_when_replay_protection_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Developers get an explicit warning when used-token replay protection is disabled."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with pytest.warns(totp.SecurityWarning, match=r"replay.*used_tokens_store|used_tokens_store.*replay"):
        assert (
            await totp.verify_totp_with_store(
                RFC_SECRET,
                current_code,
                user_id="user-1",
                used_tokens_store=None,
                require_replay_protection=False,
            )
            is True
        )


async def test_verify_totp_with_store_requires_store_outside_testing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production mode rejects missing replay stores when protection is required."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with pytest.raises(totp.ConfigurationError, match="UsedTotpCodeStore"):
        await totp.verify_totp_with_store(RFC_SECRET, current_code, user_id="user-1")


async def test_verify_totp_with_store_warns_in_testing_without_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Testing mode allows missing replay stores but still emits a warning."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with pytest.warns(totp.SecurityWarning, match="used_tokens_store=None"):
        assert (
            await totp.verify_totp_with_store(
                RFC_SECRET,
                current_code,
                user_id="user-1",
                unsafe_testing=True,
            )
            is True
        )


async def test_verify_totp_with_store_does_not_warn_when_store_provided(monkeypatch: pytest.MonkeyPatch) -> None:
    """No warning is emitted when replay protection is enabled via used_tokens_store."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    store = totp.InMemoryUsedTotpCodeStore()
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        assert (
            await totp.verify_totp_with_store(
                RFC_SECRET,
                current_code,
                user_id="user-1",
                used_tokens_store=store,
            )
            is True
        )

    assert not [r for r in records if issubclass(r.category, totp.SecurityWarning)]


async def test_verify_totp_with_store_logs_warning_on_invalid_code(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Log a structured WARNING when the provided TOTP code is invalid."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)

    with caplog.at_level(logging.WARNING, logger=totp.logger.name):
        assert await totp.verify_totp_with_store(RFC_SECRET, "000000", user_id="user-1") is False

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert getattr(record, "event", None) == "totp_failed"
    assert getattr(record, "user_id", None) == "user-1"
    assert "000000" not in record.getMessage()
    assert RFC_SECRET not in record.getMessage()


async def test_verify_totp_with_store_logs_warning_on_replay(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Log a structured WARNING when replay protection rejects a reused code."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    store = totp.InMemoryUsedTotpCodeStore()
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-1",
            used_tokens_store=store,
        )
        is True
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=totp.logger.name):
        assert (
            await totp.verify_totp_with_store(
                RFC_SECRET,
                current_code,
                user_id="user-1",
                used_tokens_store=store,
            )
            is False
        )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert getattr(record, "event", None) == "totp_replay"
    assert getattr(record, "user_id", None) == "user-1"
    assert "287082" not in record.getMessage()
    assert RFC_SECRET not in record.getMessage()


async def test_verify_totp_with_store_logs_capacity_event_when_in_memory_store_full(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Capacity exhaustion logs totp_replay_store_capacity, not totp_replay."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    store = totp.InMemoryUsedTotpCodeStore(max_entries=2)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-1",
            used_tokens_store=store,
        )
        is True
    )
    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-2",
            used_tokens_store=store,
        )
        is True
    )

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=totp.logger.name):
        assert (
            await totp.verify_totp_with_store(
                RFC_SECRET,
                current_code,
                user_id="user-3",
                used_tokens_store=store,
            )
            is False
        )

    capacity_warnings = [r for r in caplog.records if getattr(r, "event", None) == "totp_replay_store_capacity"]
    assert len(capacity_warnings) == 1
    record = capacity_warnings[0]
    assert getattr(record, "user_id", None) == "user-3"
    assert not any(getattr(r, "event", None) == "totp_replay" for r in caplog.records)
    assert RFC_SECRET not in record.getMessage()
    assert current_code not in record.getMessage()


async def test_verify_totp_with_store_keys_replay_on_matched_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay protection keys off the matched counter, not the current counter."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    matched_counter = 2
    code = totp._generate_totp_code(RFC_SECRET, matched_counter)
    seen_counters: list[int] = []

    class RecordingStore:
        async def mark_used(self, user_id: object, counter: int, ttl_seconds: float) -> totp.UsedTotpMarkResult:
            seen_counters.append(counter)
            first = len(seen_counters) == 1
            return totp.UsedTotpMarkResult(stored=first, rejected_as_replay=not first)

    store = RecordingStore()

    assert await totp.verify_totp_with_store(RFC_SECRET, code, user_id="user-1", used_tokens_store=store) is True
    assert await totp.verify_totp_with_store(RFC_SECRET, code, user_id="user-1", used_tokens_store=store) is False
    assert seen_counters == [matched_counter, matched_counter]


async def test_verify_totp_with_store_isolated_per_user_and_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay entries do not collide across users and expire after the used-code TTL elapses."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-1",
            used_tokens_store=store,
        )
        is True
    )
    assert (
        await totp.verify_totp_with_store(
            RFC_SECRET,
            current_code,
            user_id="user-2",
            used_tokens_store=store,
        )
        is True
    )

    clock.current = float(totp.USED_TOTP_CODE_TTL_SECONDS - 1)
    replay_result = await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS)
    assert replay_result.stored is False
    assert replay_result.rejected_as_replay is True

    clock.current = float(totp.USED_TOTP_CODE_TTL_SECONDS)
    ok_result = await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS)
    assert ok_result.stored is True


def test_used_totp_code_ttl_matches_full_drift_validation_window() -> None:
    """TTL tracks drift steps so replay protection spans all accepted counter windows."""
    assert totp.USED_TOTP_CODE_TTL_SECONDS == totp.TIME_STEP_SECONDS * (2 * totp.TOTP_DRIFT_STEPS + 1)


async def test_inmemory_totp_replay_store_covers_full_drift_window() -> None:
    """Mark at t=0 blocks replay until TTL end; after full span the same counter can be stored again."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock)
    ttl = totp.USED_TOTP_CODE_TTL_SECONDS
    counter_t = 42

    assert (await store.mark_used("user-1", counter_t, ttl)).stored is True

    clock.current = float(ttl - 1)
    near_expiry = await store.mark_used("user-1", counter_t, ttl)
    assert near_expiry.stored is False
    assert near_expiry.rejected_as_replay is True

    clock.current = float(ttl)
    after_expiry = await store.mark_used("user-1", counter_t, ttl)
    assert after_expiry.stored is True


async def test_in_memory_used_totp_store_rejects_insert_when_at_capacity_fail_closed() -> None:
    """At capacity with only active entries, new mark_used fails closed (no eviction)."""
    store = totp.InMemoryUsedTotpCodeStore(max_entries=STORE_CAP)

    assert (await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS)).stored is True
    assert (await store.mark_used("user-2", 2, totp.USED_TOTP_CODE_TTL_SECONDS)).stored is True
    assert len(store._entries) == STORE_CAP

    cap_result = await store.mark_used("user-3", 3, totp.USED_TOTP_CODE_TTL_SECONDS)
    assert cap_result.stored is False
    assert cap_result.rejected_as_replay is False
    assert len(store._entries) == STORE_CAP
    assert set(store._entries) == {("user-1", 1), ("user-2", 2)}


async def test_in_memory_used_totp_store_logs_error_when_capacity_blocks_insert(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When full of non-expired entries, mark_used returns False and logs at error level."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock, max_entries=STORE_CAP)

    assert (await store.mark_used("later", 1, 10.0)).stored is True
    assert (await store.mark_used("sooner", 2, 5.0)).stored is True

    with caplog.at_level(logging.ERROR, logger=totp.logger.name):
        cap_block = await store.mark_used("fresh", 3, 15.0)
        assert cap_block.stored is False
        assert cap_block.rejected_as_replay is False

    assert set(store._entries) == {("later", 1), ("sooner", 2)}
    assert "Rejected in-memory TOTP replay-store insert" in caplog.text
    assert "capacity" in caplog.text.lower()


async def test_in_memory_used_totp_store_prunes_expired_entries_before_cap_eviction() -> None:
    """Expired entries are pruned so a new insert can succeed without evicting active rows."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock, max_entries=STORE_CAP)

    assert (await store.mark_used("expired", 1, 1.0)).stored is True
    assert (await store.mark_used("active", 2, 10.0)).stored is True

    clock.current = 2.0
    assert (await store.mark_used("fresh", 3, 10.0)).stored is True

    assert len(store._entries) == STORE_CAP
    assert ("expired", 1) not in store._entries
    assert set(store._entries) == {("active", 2), ("fresh", 3)}


def test_in_memory_used_totp_store_rejects_non_positive_max_entries() -> None:
    """The in-memory replay-store cap must be configured with a positive size."""
    with pytest.raises(ValueError, match="max_entries must be at least 1"):
        totp.InMemoryUsedTotpCodeStore(max_entries=0)


async def test_in_memory_totp_enrollment_store_consumes_only_latest_jti() -> None:
    """Process-local pending enrollment state is latest-only and single-use."""
    store = totp.InMemoryTotpEnrollmentStore()

    assert store.is_shared_across_workers is False
    assert await store.save(user_id="user-1", jti="old", secret="old-secret", ttl_seconds=60) is True
    assert await store.save(user_id="user-1", jti="new", secret="new-secret", ttl_seconds=60) is True
    assert await store.consume(user_id="user-1", jti="old") is None
    assert await store.consume(user_id="user-1", jti="new") == "new-secret"
    assert await store.consume(user_id="user-1", jti="new") is None


async def test_in_memory_totp_enrollment_store_fails_closed_at_capacity(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """At capacity with active entries, new enrollment state is rejected without eviction."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryTotpEnrollmentStore(clock=clock, max_entries=1)

    assert await store.save(user_id="user-1", jti="jti-1", secret="secret-1", ttl_seconds=10) is True
    with caplog.at_level(logging.ERROR, logger=totp.logger.name):
        assert await store.save(user_id="user-2", jti="jti-2", secret="secret-2", ttl_seconds=10) is False

    assert set(store._entries) == {"user-1"}
    assert any(getattr(record, "event", None) == "totp_enrollment_store_capacity" for record in caplog.records)
    clock.current = 11.0
    assert await store.save(user_id="user-2", jti="jti-2", secret="secret-2", ttl_seconds=10) is True
    assert await store.consume(user_id="user-2", jti="jti-2") == "secret-2"


async def test_in_memory_totp_enrollment_store_clear_removes_pending_secret() -> None:
    """Explicit clearing invalidates a pending enrollment token for the user."""
    store = totp.InMemoryTotpEnrollmentStore()

    assert await store.save(user_id="user-1", jti="jti", secret="secret", ttl_seconds=60) is True
    await store.clear(user_id="user-1")

    assert await store.consume(user_id="user-1", jti="jti") is None


def test_in_memory_totp_enrollment_store_rejects_non_positive_max_entries() -> None:
    """The pending-enrollment store cap must be configured with a positive size."""
    with pytest.raises(ValueError, match="max_entries must be at least 1"):
        totp.InMemoryTotpEnrollmentStore(max_entries=0)


async def test_redis_used_totp_code_store_first_call_true_second_false(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """RedisUsedTotpCodeStore: first mark_used for (user_id, counter) returns True, second returns False."""
    ttl_seconds = 60.0
    store = totp.RedisUsedTotpCodeStore(redis=cast_fakeredis(async_fakeredis, totp.RedisUsedTotpCodeStoreClient))
    key = "litestar_auth:totp:used:user-1:42"

    assert (await store.mark_used("user-1", 42, ttl_seconds)).stored is True
    replay = await store.mark_used("user-1", 42, ttl_seconds)
    assert replay.stored is False
    assert replay.rejected_as_replay is True
    assert await async_fakeredis.get(key) == b"1"
    assert 0 < await async_fakeredis.pttl(key) <= int(ttl_seconds * 1000)


def test_redis_used_totp_code_store_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The replay store defers the optional Redis import until construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisUsedTotpCodeStore"
        raise ImportError(msg)

    monkeypatch.setattr(totp, "_load_used_totp_redis_asyncio", fail_load_redis)

    redis_client_sentinel = cast("totp.RedisUsedTotpCodeStoreClient", object())
    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisUsedTotpCodeStore"):
        totp.RedisUsedTotpCodeStore(redis=redis_client_sentinel)


async def test_redis_used_totp_code_store_uses_custom_prefix_and_none_result(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Custom prefixes are applied and Redis NX replays return ``False``."""
    store = totp.RedisUsedTotpCodeStore(
        redis=cast_fakeredis(async_fakeredis, totp.RedisUsedTotpCodeStoreClient),
        key_prefix="custom:",
    )
    key = store._key("user-1", 7)

    assert key == "custom:user-1:7"
    assert await async_fakeredis.set(key, "1") is True
    nx_replay = await store.mark_used("user-1", 7, 1.25)
    assert nx_replay.stored is False
    assert nx_replay.rejected_as_replay is True
    assert await async_fakeredis.get(key) == b"1"


async def test_redis_totp_enrollment_store_replaces_and_consumes_latest_jti(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis enrollment state uses a single latest user key and atomic consume."""
    store = totp.RedisTotpEnrollmentStore(
        redis=cast_fakeredis(async_fakeredis, totp.RedisTotpEnrollmentStoreClient),
        key_prefix="enroll:",
    )
    key = store._key("user-1")

    assert store.is_shared_across_workers is True
    assert key.startswith("enroll:")
    assert await store.save(user_id="user-1", jti="old", secret="old-secret", ttl_seconds=60) is True
    assert await store.save(user_id="user-1", jti="new", secret="new-secret", ttl_seconds=60) is True
    assert await store.consume(user_id="user-1", jti="old") is None
    assert await async_fakeredis.get(key) == b"new:new-secret"
    assert await store.consume(user_id="user-1", jti="new") == "new-secret"
    assert await store.consume(user_id="user-1", jti="new") is None


async def test_redis_totp_enrollment_store_clear_removes_pending_secret(
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """Redis-backed pending enrollment state can be explicitly cleared."""
    store = totp.RedisTotpEnrollmentStore(
        redis=cast_fakeredis(async_fakeredis, totp.RedisTotpEnrollmentStoreClient),
        key_prefix="enroll:",
    )

    assert await store.save(user_id="user-1", jti="jti", secret="secret", ttl_seconds=60) is True
    await store.clear(user_id="user-1")

    assert await store.consume(user_id="user-1", jti="jti") is None


async def test_redis_totp_enrollment_store_coerces_non_bytes_eval_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-redis-py compatible clients that return strings are normalized."""

    class _StringEvalRedisClient:
        async def setex(self, name: str, time: int, value: str) -> object:
            del name, time, value
            return True

        async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> object:
            del script, numkeys, keys_and_args
            return "secret"

        async def delete(self, *names: str) -> int:
            del names
            return 1

    monkeypatch.setattr(totp, "_load_enrollment_redis_asyncio", lambda: None)
    store = totp.RedisTotpEnrollmentStore(
        redis=cast("totp.RedisTotpEnrollmentStoreClient", _StringEvalRedisClient()),
    )

    assert await store.consume(user_id="user-1", jti="jti") == "secret"


def test_redis_totp_enrollment_store_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The enrollment store defers the optional Redis import until construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisTotpEnrollmentStore"
        raise ImportError(msg)

    monkeypatch.setattr(totp, "_load_enrollment_redis_asyncio", fail_load_redis)

    redis_client_sentinel = cast("totp.RedisTotpEnrollmentStoreClient", object())
    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTotpEnrollmentStore"):
        totp.RedisTotpEnrollmentStore(redis=redis_client_sentinel)


async def test_contrib_redis_preset_builds_totp_store_with_prefix_override(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The contrib preset derives TOTP Redis stores and lets per-call prefixes win."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(totp, "_load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp, "_load_enrollment_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.authentication.strategy.jwt._load_redis_asyncio", load_optional_redis)

    preset = RedisAuthPreset(
        redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol),
        totp_used_tokens_key_prefix="preset-used:",
        totp_pending_jti_key_prefix="preset-pending:",
    )
    store = preset.build_totp_used_tokens_store(key_prefix="override-used:")
    enrollment_store = preset.build_totp_enrollment_store(key_prefix="override-enroll:")
    pending_store = preset.build_totp_pending_jti_store(key_prefix="override-pending:")

    assert store._key("user-1", 7) == "override-used:user-1:7"
    assert enrollment_store._key("user-1").startswith("override-enroll:")
    assert pending_store.key_prefix == "override-pending:"
    assert (await store.mark_used("user-1", 7, 1.25)).stored is True
    assert await enrollment_store.save(user_id="user-1", jti="enroll-jti", secret="secret", ttl_seconds=30) is True
    assert await enrollment_store.consume(user_id="user-1", jti="enroll-jti") == "secret"
    await pending_store.deny("pending-jti", ttl_seconds=PENDING_JTI_TTL_SECONDS)
    assert await pending_store.is_denied("pending-jti") is True
    assert await async_fakeredis.get("override-used:user-1:7") == b"1"
    assert await async_fakeredis.get("override-pending:pending-jti") == b"1"
    assert 0 < await async_fakeredis.pttl("override-used:user-1:7") <= USED_TOTP_TTL_MS
    assert PENDING_JTI_TTL_FLOOR <= await async_fakeredis.ttl("override-pending:pending-jti") <= PENDING_JTI_TTL_SECONDS


def test_current_counter_uses_time_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """The RFC counter is derived from the configured 30-second step size."""
    monkeypatch.setattr(totp.time, "time", lambda: 91.0)

    assert totp._current_counter() == EXPECTED_COUNTER_AT_91_SECONDS


def test_decode_secret_restores_padding_and_normalizes_case() -> None:
    """Secret decoding tolerates whitespace, lowercase input, and missing padding."""
    assert totp._decode_secret("  my======  ") == b"f"


def test_decode_secret_rejects_invalid_base32_input() -> None:
    """Malformed base32 secrets raise the decoder error directly."""
    with pytest.raises(binascii.Error):
        totp._decode_secret("invalid***")
