"""Tests for rate-limiting backends."""

from __future__ import annotations

import asyncio
import importlib
import logging
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, call

import pytest
from litestar.connection import Request
from litestar.exceptions import TooManyRequestsException

import litestar_auth.ratelimit as ratelimit_module
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit import (
    DEFAULT_KEY_PREFIX,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RateLimiterBackend,
    RedisRateLimiter,
)
from litestar_auth.ratelimit import (
    logger as ratelimit_logger,
)

pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from types import ModuleType

    from litestar.types import HTTPScope

FULL_RETRY_AFTER = 10
PARTIAL_RETRY_AFTER = 8
REDIS_WINDOW_SECONDS = 5
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
REDIS_RETRY_AFTER = 4
type RedisEvalNumber = str | bytes | bytearray | float | int

KEY_CAP = 2


def _reload_module(module_path: str) -> ModuleType:
    """Import and reload a module so coverage records its module body.

    Returns:
        The reloaded module object.
    """
    return importlib.reload(importlib.import_module(module_path))


def _as_number(value: object, *, name: str) -> RedisEvalNumber:
    """Validate a Redis script argument can be converted to a numeric value.

    Returns:
        The original value narrowed to a number-like Redis eval argument.

    Raises:
        TypeError: If the value is not compatible with ``float()`` / ``int()`` conversion.
    """
    if isinstance(value, str | bytes | bytearray | float | int):
        return value

    msg = f"{name} must be numeric"
    raise TypeError(msg)


@dataclass(slots=True)
class FakeClock:
    """Simple mutable clock for deterministic sliding-window tests."""

    now: float = 0.0

    def __call__(self) -> float:
        """Return the current fake time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Advance the fake time by ``seconds``."""
        self.now += seconds


@dataclass(slots=True)
class ClientStub:
    """Minimal client object carrying a host value."""

    host: str | None


@dataclass(slots=True)
class JsonRequestStub:
    """Minimal request double for JSON body extraction and key building."""

    payload: object
    client: ClientStub | None = None

    async def json(self) -> object:
        """Return the configured JSON payload."""
        return self.payload


async def test_ratelimit_module_reload_preserves_public_api() -> None:
    """Reloading the module preserves the public limiter API under coverage."""
    reloaded_module = importlib.reload(ratelimit_module)
    clock = FakeClock()
    backend = reloaded_module.InMemoryRateLimiter(max_attempts=2, window_seconds=10, clock=clock)
    request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={"email": "Reloaded@Example.com"},
            client=ClientStub(host="127.0.0.1"),
        ),
    )
    limiter = reloaded_module.EndpointRateLimit(
        backend=backend,
        scope="ip_email",
        namespace="login",
    )
    config = reloaded_module.AuthRateLimitConfig(login=limiter)
    orchestrator = reloaded_module.TotpRateLimitOrchestrator(verify=limiter)

    assert reloaded_module.DEFAULT_KEY_PREFIX == DEFAULT_KEY_PREFIX
    assert reloaded_module.InMemoryRateLimiter.__name__ == "InMemoryRateLimiter"
    assert isinstance(backend, reloaded_module.RateLimiterBackend)
    assert config.login is limiter
    assert orchestrator._limiters == {"verify": limiter}

    await backend.increment("127.0.0.1")
    assert await backend.check("127.0.0.1") is True
    assert await limiter.build_key(request) == (
        f"login:{reloaded_module._safe_key_part('127.0.0.1')}:{reloaded_module._safe_key_part('reloaded@example.com')}"
    )
    assert await reloaded_module._extract_email(request) == "Reloaded@Example.com"
    await orchestrator.on_success("verify", request)


@pytest.mark.parametrize(
    ("module_path", "expected_symbols"),
    [
        pytest.param(
            "litestar_auth.ratelimit._helpers",
            ("DEFAULT_KEY_PREFIX", "RedisScriptResult", "_extract_email", "_safe_key_part", "logger"),
            id="_helpers",
        ),
        pytest.param(
            "litestar_auth.ratelimit._protocol",
            ("RateLimiterBackend", "RedisClientProtocol", "RedisPipelineProtocol"),
            id="_protocol",
        ),
        pytest.param(
            "litestar_auth.ratelimit._memory",
            ("InMemoryRateLimiter",),
            id="_memory",
        ),
        pytest.param(
            "litestar_auth.ratelimit._redis",
            ("RedisRateLimiter", "_load_package_redis_asyncio"),
            id="_redis",
        ),
        pytest.param(
            "litestar_auth.ratelimit._config",
            ("AuthRateLimitConfig", "EndpointRateLimit", "RateLimitScope"),
            id="_config",
        ),
        pytest.param(
            "litestar_auth.ratelimit._orchestrator",
            ("TotpRateLimitOrchestrator", "TotpSensitiveEndpoint"),
            id="_orchestrator",
        ),
        pytest.param(
            "litestar_auth.ratelimit",
            (
                "AuthRateLimitConfig",
                "EndpointRateLimit",
                "InMemoryRateLimiter",
                "RedisRateLimiter",
                "TotpRateLimitOrchestrator",
                "_safe_key_part",
                "logger",
            ),
            id="__init__",
        ),
    ],
)
def test_ratelimit_submodules_expose_stable_import_paths(
    module_path: str,
    expected_symbols: tuple[str, ...],
) -> None:
    """Each ratelimit submodule remains directly importable after decomposition."""
    module = _reload_module(module_path)

    assert module.__name__ == module_path
    missing_symbols = [symbol for symbol in expected_symbols if not hasattr(module, symbol)]
    assert missing_symbols == []


async def test_ratelimit_protocol_stubs_behave_as_type_contracts() -> None:
    """Protocol stubs remain directly callable without adding runtime behavior."""
    protocol_module = _reload_module("litestar_auth.ratelimit._protocol")
    pipeline_protocol = protocol_module.RedisPipelineProtocol
    client_protocol = protocol_module.RedisClientProtocol
    backend_protocol = protocol_module.RateLimiterBackend
    dummy = object()
    property_getter = backend_protocol.is_shared_across_workers.fget
    enter = pipeline_protocol.__dict__["__aenter__"]
    exit_ = pipeline_protocol.__dict__["__aexit__"]

    assert await enter(dummy) is None
    assert await exit_(dummy, None, None, None) is None
    assert pipeline_protocol.incr(dummy, "counter") is None
    assert pipeline_protocol.expire(dummy, "counter", 60) is None
    assert await pipeline_protocol.execute(dummy) is None
    assert await client_protocol.delete(dummy, "key") is None
    assert await client_protocol.eval(dummy, "return 1", 1, "key") is None
    assert property_getter is not None
    assert property_getter(dummy) is None
    assert await backend_protocol.check(dummy, "key") is None
    assert await backend_protocol.increment(dummy, "key") is None
    assert await backend_protocol.reset(dummy, "key") is None
    assert await backend_protocol.retry_after(dummy, "key") is None


async def test_memory_rate_limiter_blocks_after_max_attempts_within_window() -> None:
    """The memory limiter rejects attempts once the sliding window is full."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=10, clock=clock)

    assert isinstance(limiter, RateLimiterBackend)
    assert await limiter.check("127.0.0.1") is True

    await limiter.increment("127.0.0.1")
    assert await limiter.check("127.0.0.1") is True

    await limiter.increment("127.0.0.1")
    assert await limiter.check("127.0.0.1") is False


async def test_memory_rate_limiter_cleans_expired_counters_after_window() -> None:
    """The memory limiter drops expired timestamps and clears empty buckets."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=5, clock=clock)

    await limiter.increment("127.0.0.1:user@example.com")
    await limiter.increment("127.0.0.1:user@example.com")
    assert await limiter.check("127.0.0.1:user@example.com") is False

    clock.advance(5.1)

    assert await limiter.check("127.0.0.1:user@example.com") is True
    assert await limiter.retry_after("127.0.0.1:user@example.com") == 0


async def test_memory_rate_limiter_uses_configurable_limits_per_key() -> None:
    """The memory limiter honors custom limits and isolates keys."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(max_attempts=1, window_seconds=2, clock=clock)

    await limiter.increment("10.0.0.1")

    assert await limiter.check("10.0.0.1") is False
    assert await limiter.check("10.0.0.2") is True

    clock.advance(2.1)

    assert await limiter.check("10.0.0.1") is True


def test_memory_rate_limiter_rejects_invalid_rate_limit_configuration() -> None:
    """The shared limiter validation rejects invalid attempt and window values."""
    with pytest.raises(ValueError, match="max_attempts"):
        InMemoryRateLimiter(max_attempts=0, window_seconds=10)
    with pytest.raises(ValueError, match="window_seconds"):
        InMemoryRateLimiter(max_attempts=1, window_seconds=0)


async def test_memory_rate_limiter_reports_retry_after_and_supports_reset() -> None:
    """The memory limiter exposes remaining TTL and can clear counters."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=FULL_RETRY_AFTER, clock=clock)

    await limiter.increment("127.0.0.1")
    await limiter.increment("127.0.0.1")

    assert await limiter.retry_after("127.0.0.1") == FULL_RETRY_AFTER

    clock.advance(2.2)
    assert await limiter.retry_after("127.0.0.1") == PARTIAL_RETRY_AFTER

    await limiter.reset("127.0.0.1")
    assert await limiter.check("127.0.0.1") is True
    assert await limiter.retry_after("127.0.0.1") == 0


async def test_memory_rate_limiter_is_async_safe_under_concurrent_increments() -> None:
    """Concurrent increments do not lose updates under asyncio scheduling."""
    limiter = InMemoryRateLimiter(max_attempts=20, window_seconds=30)
    key = "127.0.0.1"

    async with asyncio.TaskGroup() as task_group:
        for _ in range(20):
            task_group.create_task(limiter.increment(key))

    assert await limiter.check(key) is False
    assert limiter.is_shared_across_workers is False


@dataclass(slots=True)
class FakeRedisClient:
    """Minimal async Redis client test double with sliding-window state."""

    delete_mock: AsyncMock
    eval_mock: AsyncMock
    windows: dict[str, list[tuple[str, float]]]
    deleted_keys: list[str]

    async def delete(self, *names: str) -> int:
        """Delete the configured keys.

        Returns:
            Number of deleted keys.
        """
        self.deleted_keys.extend(names)
        for name in names:
            self.windows.pop(name, None)
        return await self.delete_mock(*names)

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> ratelimit_module.RedisScriptResult:
        """Emulate the Redis Lua scripts used by ``RedisRateLimiter``.

        Returns:
            The scalar result produced by the emulated script.

        Raises:
            AssertionError: If the script uses an unsupported key count or script body.
            TypeError: If the Redis key is not a string.
        """
        if numkeys != 1:
            msg = "FakeRedisClient only supports single-key scripts"
            raise AssertionError(msg)

        await self.eval_mock(script, numkeys, *keys_and_args)
        key = keys_and_args[0]
        if not isinstance(key, str):
            msg = "Redis keys must be strings"
            raise TypeError(msg)

        if script == RedisRateLimiter._CHECK_SCRIPT:
            return self._check(
                key,
                _as_number(keys_and_args[1], name="now"),
                _as_number(keys_and_args[2], name="window_seconds"),
                _as_number(keys_and_args[3], name="max_attempts"),
            )
        if script == RedisRateLimiter._INCREMENT_SCRIPT:
            return self._increment(
                key,
                _as_number(keys_and_args[1], name="now"),
                _as_number(keys_and_args[2], name="window_seconds"),
                keys_and_args[3],
                _as_number(keys_and_args[4], name="ttl"),
            )
        if script == RedisRateLimiter._RETRY_AFTER_SCRIPT:
            return self._retry_after(
                key,
                _as_number(keys_and_args[1], name="now"),
                _as_number(keys_and_args[2], name="window_seconds"),
                _as_number(keys_and_args[3], name="max_attempts"),
            )

        msg = "Unexpected Lua script"
        raise AssertionError(msg)

    def _prune(self, key: str, *, now: float, window_seconds: float) -> list[tuple[str, float]]:
        """Remove expired entries from a sorted-set window.

        Returns:
            The active entries that remain after pruning.
        """
        cutoff = now - window_seconds
        entries = [(member, score) for member, score in self.windows.get(key, []) if score > cutoff]
        if entries:
            self.windows[key] = entries
            return entries

        self.windows.pop(key, None)
        self.deleted_keys.append(key)
        return []

    def _check(
        self,
        key: str,
        now: RedisEvalNumber,
        window_seconds: RedisEvalNumber,
        max_attempts: RedisEvalNumber,
    ) -> int:
        """Emulate the check Lua script.

        Returns:
            The number of active attempts in the sliding window.
        """
        del max_attempts
        entries = self._prune(key, now=float(now), window_seconds=float(window_seconds))
        return len(entries)

    def _increment(
        self,
        key: str,
        now: RedisEvalNumber,
        window_seconds: RedisEvalNumber,
        member: object,
        ttl: RedisEvalNumber,
    ) -> int:
        """Emulate the increment Lua script.

        Returns:
            The number of active attempts after recording the new one.
        """
        del ttl
        entries = self._prune(key, now=float(now), window_seconds=float(window_seconds))
        entries.append((str(member), float(now)))
        self.windows[key] = entries
        return len(entries)

    def _retry_after(
        self,
        key: str,
        now: RedisEvalNumber,
        window_seconds: RedisEvalNumber,
        max_attempts: RedisEvalNumber,
    ) -> int:
        """Emulate the retry-after Lua script.

        Returns:
            Whole seconds until the oldest active attempt leaves the window.
        """
        entries = self._prune(key, now=float(now), window_seconds=float(window_seconds))
        if len(entries) < int(max_attempts):
            return 0

        oldest_score = min(score for _, score in entries)
        remaining = float(window_seconds) - (float(now) - oldest_score)
        return max(int(-(-remaining // 1)), 0)


def make_fake_redis() -> FakeRedisClient:
    """Build a fake Redis client with in-memory sliding-window behavior.

    Returns:
        A fake Redis client for unit tests.
    """
    delete_mock = AsyncMock(return_value=1)
    eval_mock = AsyncMock(return_value=0)
    return FakeRedisClient(
        delete_mock=delete_mock,
        eval_mock=eval_mock,
        windows={},
        deleted_keys=[],
    )


@pytest.fixture
def patch_redis_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the Redis loader to return a dummy client for RedisRateLimiter tests."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_redis)


def _build_request(
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] | None = ("127.0.0.1", 12345),
) -> Request:
    """Create a minimal request object for endpoint rate-limit tests.

    Returns:
        Minimal request carrying the provided headers.
    """
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/login",
            "raw_path": b"/auth/login",
            "root_path": "",
            "query_string": b"",
            "headers": headers or [],
            "client": client,
            "server": ("testserver", 80),
            "path_params": {},
            "app": object(),
        },
    )
    return Request(scope=scope)


def test_endpoint_rate_limit_trusted_proxy_defaults_to_false() -> None:
    """Rate-limit config remains safe-by-default for proxy headers."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip",
        namespace="login",
    )
    assert limiter.trusted_proxy is False


def test_client_host_ignores_proxy_headers_by_default() -> None:
    """When trusted_proxy=False, only request.client.host is used."""
    request = _build_request(headers=[(b"x-forwarded-for", b"203.0.113.1")])
    assert ratelimit_module._client_host(request) == "127.0.0.1"


def test_client_host_returns_unknown_without_client() -> None:
    """Requests without a client address fall back to a stable placeholder."""
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/login",
            "raw_path": b"/auth/login",
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": None,
            "server": ("testserver", 80),
            "path_params": {},
        },
    )
    request = Request(scope=scope)

    assert ratelimit_module._client_host(request) == "unknown"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([(b"x-forwarded-for", b"203.0.113.12, 10.0.0.1")], "203.0.113.12"),
        ([(b"x-forwarded-for", b" , 10.0.0.1")], "127.0.0.1"),
        ([], "127.0.0.1"),
    ],
)
def test_client_host_uses_default_trusted_headers(headers: list[tuple[bytes, bytes]], expected: str) -> None:
    """Default trusted_headers only reads X-Forwarded-For."""
    request = _build_request(headers=headers)
    assert ratelimit_module._client_host(request, trusted_proxy=True) == expected


def test_client_host_rejects_non_boolean_trusted_proxy_configuration() -> None:
    """trusted_proxy must be a boolean to avoid silent config misuse."""
    request = _build_request(headers=[(b"x-forwarded-for", b"203.0.113.5")])

    with pytest.raises(ConfigurationError, match="trusted_proxy must be a boolean"):
        ratelimit_module._client_host(request, trusted_proxy=cast("Any", "true"))


@pytest.mark.parametrize(
    ("headers", "trusted_headers", "expected"),
    [
        (
            [(b"cf-connecting-ip", b"203.0.113.10")],
            ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"),
            "203.0.113.10",
        ),
        (
            [(b"x-real-ip", b"203.0.113.11")],
            ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"),
            "203.0.113.11",
        ),
        (
            [(b"x-real-ip", b"   ")],
            ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"),
            "127.0.0.1",
        ),
    ],
)
def test_client_host_uses_custom_trusted_headers(
    headers: list[tuple[bytes, bytes]],
    trusted_headers: tuple[str, ...],
    expected: str,
) -> None:
    """Explicit trusted_headers opt-in reads additional proxy headers."""
    request = _build_request(headers=headers)
    assert ratelimit_module._client_host(request, trusted_proxy=True, trusted_headers=trusted_headers) == expected


def test_memory_rate_limiter_rejects_invalid_storage_configuration() -> None:
    """The in-memory limiter validates the key-cap and sweep settings."""
    with pytest.raises(ValueError, match="max_keys"):
        InMemoryRateLimiter(max_attempts=1, window_seconds=10, max_keys=0)
    with pytest.raises(ValueError, match="sweep_interval"):
        InMemoryRateLimiter(max_attempts=1, window_seconds=10, sweep_interval=0)


async def test_memory_rate_limiter_global_sweep_prunes_expired_idle_keys() -> None:
    """Periodic sweeping removes expired keys even if they are never touched again."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=5, clock=clock, sweep_interval=2)

    await limiter.increment("stale")
    clock.advance(5.1)
    await limiter.check("fresh")

    assert "stale" not in limiter._windows


def test_memory_rate_limiter_maybe_sweep_waits_for_configured_interval() -> None:
    """Sweeping only runs when the operation counter reaches the interval."""
    limiter = InMemoryRateLimiter(max_attempts=2, window_seconds=5, sweep_interval=3)
    limiter._windows["stale"] = deque([0.0])

    limiter._maybe_sweep(6.0)
    limiter._maybe_sweep(6.0)
    assert "stale" in limiter._windows

    limiter._maybe_sweep(6.0)
    assert "stale" not in limiter._windows


async def test_memory_rate_limiter_evicts_least_recently_active_key_at_capacity() -> None:
    """Adding a new key evicts the least-recently-active survivor when capped."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_attempts=2,
        window_seconds=60,
        clock=clock,
        max_keys=KEY_CAP,
        sweep_interval=100,
    )

    await limiter.increment("first")
    clock.advance(0.1)
    await limiter.increment("second")
    clock.advance(0.1)
    await limiter.increment("first")
    clock.advance(0.1)
    await limiter.increment("third")

    assert len(limiter._windows) == KEY_CAP
    assert list(limiter._windows) == ["first", "third"]
    assert await limiter.check("second") is True
    assert await limiter.check("first") is False


def test_redis_rate_limiter_implements_shared_backend_protocol(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter matches the shared backend interface."""
    limiter = RedisRateLimiter(redis=make_fake_redis(), max_attempts=2, window_seconds=10)

    assert isinstance(limiter, RateLimiterBackend)


async def test_redis_rate_limiter_blocks_after_max_attempts(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter rejects requests after the sliding window fills."""
    clock = FakeClock()
    redis_client = make_fake_redis()
    limiter = RedisRateLimiter(redis=redis_client, max_attempts=2, window_seconds=30, clock=clock)

    await limiter.increment("127.0.0.1")
    await limiter.increment("127.0.0.1")

    assert await limiter.check("127.0.0.1") is False
    redis_client.eval_mock.assert_awaited()


async def test_redis_rate_limiter_check_and_retry_after_use_lua_scripts(
    patch_redis_loader: None,
) -> None:
    """Check and retry-after delegate to their Lua scripts and decode bytes."""
    clock = FakeClock(now=12.5)
    redis_client = AsyncMock()
    redis_client.eval = AsyncMock(side_effect=[b"1", str(REDIS_RETRY_AFTER).encode()])
    redis_client.delete = AsyncMock(return_value=1)
    limiter = RedisRateLimiter(
        redis=cast("ratelimit_module.RedisClientProtocol", redis_client),
        max_attempts=3,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )

    assert limiter.is_shared_across_workers is True
    assert await limiter.check("127.0.0.1") is True
    assert await limiter.retry_after("127.0.0.1") == REDIS_RETRY_AFTER

    expected_key = f"{DEFAULT_KEY_PREFIX}127.0.0.1"
    assert redis_client.eval.await_args_list[0].args == (
        RedisRateLimiter._CHECK_SCRIPT,
        1,
        expected_key,
        clock.now,
        REDIS_WINDOW_SECONDS,
        3,
    )
    assert redis_client.eval.await_args_list[1].args == (
        RedisRateLimiter._RETRY_AFTER_SCRIPT,
        1,
        expected_key,
        clock.now,
        REDIS_WINDOW_SECONDS,
        3,
    )


async def test_redis_rate_limiter_increments_with_atomic_pipeline(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter records attempts with a single Lua script."""
    clock = FakeClock(now=12.5)
    redis_client = make_fake_redis()
    limiter = RedisRateLimiter(
        redis=redis_client,
        max_attempts=3,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )

    await limiter.increment("127.0.0.1:user@example.com")

    redis_client.eval_mock.assert_awaited_once()
    script, numkeys, redis_key, score, window_seconds, member, ttl = redis_client.eval_mock.await_args.args
    assert script == RedisRateLimiter._INCREMENT_SCRIPT
    assert numkeys == 1
    assert redis_key == f"{DEFAULT_KEY_PREFIX}127.0.0.1:user@example.com"
    assert score == clock.now
    assert window_seconds == REDIS_WINDOW_SECONDS
    assert isinstance(member, str)
    assert ttl == REDIS_WINDOW_SECONDS


async def test_redis_rate_limiter_retry_after_and_reset_delegate_to_redis(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter reports retry-after from the oldest active attempt."""
    clock = FakeClock()
    redis_client = make_fake_redis()
    limiter = RedisRateLimiter(redis=redis_client, max_attempts=2, window_seconds=10, clock=clock)

    await limiter.increment("127.0.0.1")
    clock.advance(2.2)
    await limiter.increment("127.0.0.1")

    assert await limiter.retry_after("127.0.0.1") == PARTIAL_RETRY_AFTER
    await limiter.reset("127.0.0.1")

    redis_client.delete_mock.assert_awaited_once_with(f"{DEFAULT_KEY_PREFIX}127.0.0.1")
    assert await limiter.check("127.0.0.1") is True


async def test_redis_rate_limiter_prunes_expired_entries_like_in_memory_backend(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter drops expired attempts instead of waiting for a fixed-window reset."""
    clock = FakeClock()
    redis_client = make_fake_redis()
    limiter = RedisRateLimiter(
        redis=redis_client,
        max_attempts=2,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )

    await limiter.increment("127.0.0.1:user@example.com")
    clock.advance(4.9)
    await limiter.increment("127.0.0.1:user@example.com")
    assert await limiter.check("127.0.0.1:user@example.com") is False

    clock.advance(0.2)
    assert await limiter.check("127.0.0.1:user@example.com") is True


async def test_redis_rate_limiter_blocks_fixed_window_boundary_burst(
    patch_redis_loader: None,
) -> None:
    """The Redis limiter prevents a burst split across a fixed-window boundary."""
    clock = FakeClock()
    redis_client = make_fake_redis()
    limiter = RedisRateLimiter(redis=redis_client, max_attempts=2, window_seconds=10, clock=clock)

    await limiter.increment("127.0.0.1")
    clock.advance(9.9)
    await limiter.increment("127.0.0.1")
    assert await limiter.check("127.0.0.1") is False

    clock.advance(0.2)
    assert await limiter.check("127.0.0.1") is True
    await limiter.increment("127.0.0.1")
    assert await limiter.check("127.0.0.1") is False

    clock.advance(9.9)
    assert await limiter.check("127.0.0.1") is True


def test_redis_rate_limiter_lazy_import_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Redis limiter explains how to install the optional dependency."""

    def fail_import(name: str) -> None:
        raise ImportError(name)

    monkeypatch.setattr(importlib, "import_module", fail_import)

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisRateLimiter"):
        ratelimit_module._load_redis_asyncio()


@dataclass(slots=True)
class RedisClientWithConnectionError:
    """Redis client that always fails with ConnectionError."""

    async def delete(self, *names: str) -> int:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        raise ConnectionError

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> ratelimit_module.RedisScriptResult:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        raise ConnectionError


@dataclass(slots=True)
class RedisTokenClientWithConnectionError:
    """Redis token client that always fails with ConnectionError."""

    async def get(self, name: str, /) -> bytes | str | None:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        raise ConnectionError

    async def setex(self, name: str, time: int, value: str, /) -> object:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        raise ConnectionError

    async def delete(self, *names: str) -> int:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        raise ConnectionError

    async def sadd(self, name: str, *values: str) -> int:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        del name, values
        raise ConnectionError

    async def srem(self, name: str, *values: str) -> int:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        del name, values
        raise ConnectionError

    async def smembers(self, name: str) -> set[bytes]:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        del name
        raise ConnectionError

    async def expire(self, name: str, time: int) -> bool:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        del name, time
        raise ConnectionError

    def scan_iter(
        self,
        match: object | None = None,
        count: int | None = None,
        _type: str | None = None,
        **kwargs: object,
    ) -> AsyncIterator[str]:
        """Always fail to simulate a dropped Redis connection.

        Raises:
            ConnectionError: Always raised.
        """
        del match
        del count
        del _type
        del kwargs
        raise ConnectionError


async def test_redis_rate_limiter_propagates_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """RedisRateLimiter does not swallow connection errors from Redis."""
    limiter = RedisRateLimiter(redis=RedisClientWithConnectionError(), max_attempts=2, window_seconds=10)

    with pytest.raises(ConnectionError):
        await limiter.check("127.0.0.1")


async def test_redis_token_strategy_propagates_connection_error() -> None:
    """RedisTokenStrategy does not swallow connection errors from Redis."""
    user_manager = AsyncMock()
    user_manager.get = AsyncMock()

    strategy = RedisTokenStrategy(
        redis=RedisTokenClientWithConnectionError(),
        token_hash_secret=REDIS_TOKEN_HASH_SECRET,
    )

    with pytest.raises(ConnectionError):
        await strategy.read_token("token", user_manager)


async def test_endpoint_rate_limit_before_request_raises_with_retry_after_header() -> None:
    """Blocked requests surface a Retry-After header derived from backend state."""
    clock = FakeClock()
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=FULL_RETRY_AFTER, clock=clock),
        scope="ip",
        namespace="login",
    )
    request = _build_request()
    await limiter.increment(request)

    with pytest.raises(TooManyRequestsException) as exc_info:
        await limiter.before_request(request)

    assert exc_info.value.headers == {"Retry-After": str(FULL_RETRY_AFTER)}


async def test_endpoint_rate_limit_before_request_allows_under_limit_request() -> None:
    """Allowed requests short-circuit before retry-after lookup or logging."""
    backend = AsyncMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock(return_value=None)
    backend.reset = AsyncMock(return_value=None)
    backend.retry_after = AsyncMock(return_value=FULL_RETRY_AFTER)
    limiter = EndpointRateLimit(
        backend=cast("RateLimiterBackend", backend),
        scope="ip",
        namespace="login",
    )

    await limiter.before_request(_build_request())

    backend.check.assert_awaited_once()
    backend.retry_after.assert_not_called()


async def test_endpoint_rate_limit_build_key_ip_email_normalizes_identifier() -> None:
    """IP-email scoped keys append a normalized identifier hash when present."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip_email",
        namespace="login",
    )
    request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={"identifier": " User@Example.COM "},
            client=ClientStub(host="10.0.0.1"),
        ),
    )

    key = await limiter.build_key(request)

    assert key == (
        f"login:{ratelimit_module._safe_key_part('10.0.0.1')}:{ratelimit_module._safe_key_part('user@example.com')}"
    )


async def test_endpoint_rate_limit_reset_uses_key_without_email_when_body_has_no_identifier() -> None:
    """Reset delegates to the backend using only the host hash when identity is absent."""
    backend = AsyncMock()
    backend.check = AsyncMock(return_value=True)
    backend.increment = AsyncMock(return_value=None)
    backend.reset = AsyncMock(return_value=None)
    backend.retry_after = AsyncMock(return_value=0)
    limiter = EndpointRateLimit(
        backend=cast("RateLimiterBackend", backend),
        scope="ip_email",
        namespace="register",
    )
    request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(payload={}, client=ClientStub(host="192.168.1.1")),
    )

    await limiter.reset(request)

    backend.reset.assert_awaited_once_with(f"register:{ratelimit_module._safe_key_part('192.168.1.1')}")


async def test_extract_email_prefers_identity_fields_and_ignores_invalid_payloads() -> None:
    """Email extraction respects field priority and ignores non-dict bodies."""
    prioritized_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={
                "identifier": "",
                "username": "user@example.com",
                "email": "other@example.com",
            },
        ),
    )

    assert await ratelimit_module._extract_email(prioritized_request) == "user@example.com"
    assert (
        await ratelimit_module._extract_email(
            cast("Request[Any, Any, Any]", JsonRequestStub(payload={"email": "user@example.com"})),
        )
        == "user@example.com"
    )
    assert (
        await ratelimit_module._extract_email(
            cast("Request[Any, Any, Any]", JsonRequestStub(payload=["not-a-dict"])),
        )
        is None
    )

    class BadJsonRequest:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.client = None

        async def json(self) -> object:
            raise TypeError

    assert await ratelimit_module._extract_email(cast("Request[Any, Any, Any]", BadJsonRequest())) is None


async def test_extract_email_skips_blank_identifier_username_and_email_values() -> None:
    """Blank identity values are ignored in priority order before falling back."""
    identifier_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={
                "identifier": "id@example.com",
                "username": "user@example.com",
                "email": "other@example.com",
            },
        ),
    )
    email_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(payload={"username": "", "email": "other@example.com"}),
    )
    blank_email_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(payload={"email": ""}),
    )

    assert await ratelimit_module._extract_email(identifier_request) == "id@example.com"
    assert await ratelimit_module._extract_email(email_request) == "other@example.com"
    assert await ratelimit_module._extract_email(blank_email_request) is None


async def test_endpoint_rate_limit_build_key_ip_uses_namespace_and_host() -> None:
    """IP-scoped keys include only the namespace and client host."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip",
        namespace="login",
    )
    request = _build_request()

    assert await limiter.build_key(request) == f"login:{ratelimit_module._safe_key_part('127.0.0.1')}"


async def test_endpoint_rate_limit_build_key_ip_email_without_email_uses_host_only() -> None:
    """IP-email scoped keys omit the identity suffix when no email-like field exists."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip_email",
        namespace="register",
    )
    request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(payload={}, client=ClientStub(host="192.168.1.1")),
    )

    assert await limiter.build_key(request) == f"register:{ratelimit_module._safe_key_part('192.168.1.1')}"


async def test_endpoint_rate_limit_logs_trigger(caplog: pytest.LogCaptureFixture) -> None:
    """Blocked requests emit a warning log with namespace and scope."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip",
        namespace="login",
    )
    request = _build_request()
    await limiter.increment(request)

    with caplog.at_level(logging.WARNING, logger=ratelimit_logger.name), pytest.raises(TooManyRequestsException):
        await limiter.before_request(request)

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["rate_limit_triggered"]
    assert getattr(caplog.records[0], "namespace", None) == "login"
    assert getattr(caplog.records[0], "scope", None) == "ip"


async def test_totp_rate_limit_orchestrator_routes_actions_to_configured_limiters() -> None:
    """Configured TOTP limiters receive the expected endpoint-specific callbacks."""
    request = cast("Request[Any, Any, Any]", object())
    enable_limiter = AsyncMock()
    verify_limiter = AsyncMock()
    orchestrator = ratelimit_module.TotpRateLimitOrchestrator(
        enable=cast("EndpointRateLimit", enable_limiter),
        verify=cast("EndpointRateLimit", verify_limiter),
    )
    empty_orchestrator = ratelimit_module.TotpRateLimitOrchestrator()

    assert orchestrator._limiters == {"enable": enable_limiter, "verify": verify_limiter}

    await orchestrator.before_request("enable", request)
    await orchestrator.before_request("confirm_enable", request)
    await orchestrator.on_invalid_attempt("verify", request)
    await orchestrator.on_invalid_attempt("disable", request)
    await orchestrator.on_account_state_failure("verify", request)
    await orchestrator.on_account_state_failure("enable", request)
    await empty_orchestrator.on_account_state_failure("verify", request)
    await orchestrator.on_success("verify", request)
    await orchestrator.on_success("confirm_enable", request)

    enable_limiter.before_request.assert_awaited_once_with(request)
    verify_limiter.increment.assert_awaited_once_with(request)
    assert verify_limiter.reset.await_args_list == [call(request), call(request)]
