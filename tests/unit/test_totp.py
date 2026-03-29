"""Tests for TOTP helpers."""

from __future__ import annotations

import asyncio
import binascii
import importlib
import logging
import warnings
from urllib.parse import parse_qs, urlparse

import pytest

from litestar_auth import totp

pytestmark = pytest.mark.unit

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
EXPECTED_MIN_SECRET_LENGTH = 32
EXPECTED_COUNTER_AT_91_SECONDS = 3
STORE_CAP = 2


def test_totp_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class execution."""
    original_security_warning = totp.SecurityWarning
    original_configuration_error = totp.ConfigurationError
    reloaded_module = importlib.reload(totp)
    reloaded_module.__dict__["SecurityWarning"] = original_security_warning
    reloaded_module.__dict__["ConfigurationError"] = original_configuration_error

    assert reloaded_module.InMemoryUsedTotpCodeStore.__name__ == totp.InMemoryUsedTotpCodeStore.__name__
    assert reloaded_module.RedisUsedTotpCodeStore.__name__ == totp.RedisUsedTotpCodeStore.__name__


def test_generate_totp_secret_returns_base32_secret() -> None:
    """Generated secrets are uppercase base32 strings without padding."""
    secret = totp.generate_totp_secret()

    assert len(secret) >= EXPECTED_MIN_SECRET_LENGTH
    assert secret.isupper()
    assert "=" not in secret
    assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


@pytest.mark.parametrize(
    ("algorithm", "expected_bytes"),
    [("SHA1", 20), ("SHA256", 32), ("SHA512", 64)],
)
def test_generate_totp_secret_size_matches_algorithm(algorithm: str, expected_bytes: int) -> None:
    """Secret byte length matches the HMAC output length per RFC 4226 S4."""
    secret = totp.generate_totp_secret(algorithm=algorithm)  # ty: ignore[invalid-argument-type]
    decoded = totp._decode_secret(secret)
    assert len(decoded) == expected_bytes


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
    """Non-default algorithms are encoded into the otpauth URI query string."""
    uri = totp.generate_totp_uri("ABCDEF123456", "user@example.com", "Litestar Auth", algorithm="SHA256")
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    assert query["algorithm"] == ["SHA256"]


@pytest.mark.parametrize("algorithm", ["SHA1", "SHA256", "SHA512"])
def test_generate_totp_uri_preserves_selected_algorithm(algorithm: str) -> None:
    """The otpauth URI query uses the selected TOTP algorithm."""
    uri = totp.generate_totp_uri("ABCDEF123456", "user@example.com", "Litestar Auth", algorithm=algorithm)  # ty: ignore[invalid-argument-type]
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)

    assert query["algorithm"] == [algorithm]


def test_generate_totp_code_uses_selected_algorithm() -> None:
    """Different algorithms produce different codes for the same inputs."""
    counter = 1
    sha1_code = totp._generate_totp_code(RFC_SECRET, counter, algorithm="SHA1")
    sha256_code = totp._generate_totp_code(RFC_SECRET, counter, algorithm="SHA256")
    sha512_code = totp._generate_totp_code(RFC_SECRET, counter, algorithm="SHA512")

    assert sha1_code != sha256_code
    assert sha1_code != sha512_code
    assert sha256_code != sha512_code


@pytest.mark.parametrize("algorithm", ["SHA1", "SHA256", "SHA512"])
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
    monkeypatch.setattr(totp, "is_testing", lambda: False)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with pytest.raises(totp.ConfigurationError, match="UsedTotpCodeStore"):
        await totp.verify_totp_with_store(RFC_SECRET, current_code, user_id="user-1")


async def test_verify_totp_with_store_warns_in_testing_without_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Testing mode allows missing replay stores but still emits a warning."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    monkeypatch.setattr(totp, "is_testing", lambda: True)
    current_code = totp._generate_totp_code(RFC_SECRET, 1)

    with pytest.warns(totp.SecurityWarning, match="used_tokens_store=None"):
        assert await totp.verify_totp_with_store(RFC_SECRET, current_code, user_id="user-1") is True


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


async def test_verify_totp_with_store_keys_replay_on_matched_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay protection keys off the matched counter, not the current counter."""
    monkeypatch.setattr(totp.time, "time", lambda: 59.0)
    matched_counter = 2
    code = totp._generate_totp_code(RFC_SECRET, matched_counter)
    seen_counters: list[int] = []

    class RecordingStore:
        async def mark_used(self, user_id: object, counter: int, ttl_seconds: float) -> bool:
            seen_counters.append(counter)
            return len(seen_counters) == 1

    store = RecordingStore()

    assert await totp.verify_totp_with_store(RFC_SECRET, code, user_id="user-1", used_tokens_store=store) is True
    assert await totp.verify_totp_with_store(RFC_SECRET, code, user_id="user-1", used_tokens_store=store) is False
    assert seen_counters == [matched_counter, matched_counter]


async def test_verify_totp_with_store_isolated_per_user_and_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay entries do not collide across users and expire after two time steps."""

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
    assert await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS) is False

    clock.current = float(totp.USED_TOTP_CODE_TTL_SECONDS)
    assert await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS) is True


async def test_in_memory_used_totp_store_caps_entries_with_fifo_eviction() -> None:
    """Cap enforcement should evict the oldest active replay entry before adding a new one."""
    store = totp.InMemoryUsedTotpCodeStore(max_entries=STORE_CAP)

    assert await store.mark_used("user-1", 1, totp.USED_TOTP_CODE_TTL_SECONDS) is True
    assert await store.mark_used("user-2", 2, totp.USED_TOTP_CODE_TTL_SECONDS) is True
    assert await store.mark_used("user-3", 3, totp.USED_TOTP_CODE_TTL_SECONDS) is True

    assert len(store._entries) == STORE_CAP
    assert ("user-1", 1) not in store._entries
    assert set(store._entries) == {("user-2", 2), ("user-3", 3)}


async def test_in_memory_used_totp_store_evicts_soonest_expiring_entry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Cap eviction drops the entry nearest expiry and logs the pressure event."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock, max_entries=STORE_CAP)

    assert await store.mark_used("later", 1, 10.0) is True
    assert await store.mark_used("sooner", 2, 5.0) is True

    with caplog.at_level(logging.WARNING, logger=totp.logger.name):
        assert await store.mark_used("fresh", 3, 15.0) is True

    assert ("sooner", 2) not in store._entries
    assert set(store._entries) == {("later", 1), ("fresh", 3)}
    assert "Evicted TOTP replay entry" in caplog.text


async def test_in_memory_used_totp_store_prunes_expired_entries_before_cap_eviction() -> None:
    """Cap enforcement should full-sweep expired entries before evicting active ones."""

    class Clock:
        def __init__(self) -> None:
            self.current = 0.0

        def __call__(self) -> float:
            return self.current

    clock = Clock()
    store = totp.InMemoryUsedTotpCodeStore(clock=clock, max_entries=STORE_CAP)

    assert await store.mark_used("expired", 1, 1.0) is True
    assert await store.mark_used("active", 2, 10.0) is True

    clock.current = 2.0
    assert await store.mark_used("fresh", 3, 10.0) is True

    assert len(store._entries) == STORE_CAP
    assert ("expired", 1) not in store._entries
    assert set(store._entries) == {("active", 2), ("fresh", 3)}


def test_in_memory_used_totp_store_rejects_non_positive_max_entries() -> None:
    """The in-memory replay-store cap must be configured with a positive size."""
    with pytest.raises(ValueError, match="max_entries must be at least 1"):
        totp.InMemoryUsedTotpCodeStore(max_entries=0)


async def test_redis_used_totp_code_store_first_call_true_second_false() -> None:
    """RedisUsedTotpCodeStore: first mark_used for (user_id, counter) returns True, second returns False."""
    set_results: list[bool] = [True, False]
    ttl_seconds = 60.0
    expected_ttl_ms = int(ttl_seconds * 1000)

    class FakeRedis(totp.RedisUsedTotpCodeStoreClient):
        async def set(
            self,
            name: str,
            value: str,
            *,
            nx: bool = False,
            px: int | None = None,
        ) -> bool | None:
            await asyncio.sleep(0)
            assert name == "litestar_auth:totp:used:user-1:42"
            assert value == "1"
            assert nx is True
            assert px == expected_ttl_ms
            return set_results.pop(0) if set_results else False

    store = totp.RedisUsedTotpCodeStore(redis=FakeRedis())
    assert await store.mark_used("user-1", 42, ttl_seconds) is True
    assert await store.mark_used("user-1", 42, ttl_seconds) is False


async def test_redis_used_totp_code_store_uses_custom_prefix_and_none_result() -> None:
    """Custom prefixes are applied and a missing Redis write is treated as replay."""
    calls: list[tuple[str, str, bool, int | None]] = []

    class FakeRedis(totp.RedisUsedTotpCodeStoreClient):
        async def set(
            self,
            name: str,
            value: str,
            *,
            nx: bool = False,
            px: int | None = None,
        ) -> bool | None:
            calls.append((name, value, nx, px))
            return None

    store = totp.RedisUsedTotpCodeStore(redis=FakeRedis(), key_prefix="custom:")

    assert store._key("user-1", 7) == "custom:user-1:7"
    assert await store.mark_used("user-1", 7, 1.25) is False
    assert calls == [("custom:user-1:7", "1", True, 1250)]


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
