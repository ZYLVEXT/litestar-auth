"""Tests for rate-limiting backends."""

from __future__ import annotations

import asyncio
import importlib
import logging
import runpy
import sys
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from types import ModuleType as RuntimeModuleType
from typing import TYPE_CHECKING, Any, cast, get_args, get_origin, get_type_hints
from unittest.mock import AsyncMock, call

import pytest
from litestar.connection import Request
from litestar.exceptions import TooManyRequestsException
from redis.exceptions import ConnectionError as RedisConnectionError

import litestar_auth.ratelimit as ratelimit_module
import litestar_auth.ratelimit._config as ratelimit_config_module
import litestar_auth.ratelimit._endpoint as ratelimit_endpoint_module
import litestar_auth.ratelimit._helpers as ratelimit_helpers_module
import litestar_auth.ratelimit._slot_catalog as ratelimit_slot_catalog_module
from litestar_auth.authentication.strategy.redis import RedisClientProtocol as RedisTokenClientProtocol
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy, RedisTokenStrategyConfig
from litestar_auth.contrib.redis import (
    RedisAuthClientProtocol,
    RedisAuthPreset,
    RedisAuthRateLimitConfigOptions,
    RedisAuthRateLimitTier,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit import (
    DEFAULT_KEY_PREFIX,
    AuthRateLimitConfig,
    AuthRateLimitEndpointGroup,
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
    RateLimiterBackend,
    RedisClientProtocol,
    RedisRateLimiter,
    SharedRateLimitConfigOptions,
)
from tests._helpers import cast_fakeredis

pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from types import ModuleType

    import fakeredis
    from litestar.types import HTTPScope

    from tests._helpers import AsyncFakeRedis

FULL_RETRY_AFTER = 10
PARTIAL_RETRY_AFTER = 8
REDIS_WINDOW_SECONDS = 5
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
REDIS_RETRY_AFTER = 4
SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300
USED_TOTP_TTL_MS = 1_250
PENDING_JTI_TTL_SECONDS = 30
PENDING_JTI_TTL_FLOOR = PENDING_JTI_TTL_SECONDS - 1
UUID4_HEX_LENGTH = 32
LENIENT_STRICT_MAX_ATTEMPTS = 5
LENIENT_MEMORY_WINDOW_SECONDS = 300
LENIENT_REDIS_WINDOW_SECONDS = 120

AUTH_RATE_LIMIT_SLOT_IDENTIFIERS: tuple[AuthRateLimitSlot, ...] = (
    AuthRateLimitSlot.LOGIN,
    AuthRateLimitSlot.CHANGE_PASSWORD,
    AuthRateLimitSlot.REFRESH,
    AuthRateLimitSlot.REGISTER,
    AuthRateLimitSlot.FORGOT_PASSWORD,
    AuthRateLimitSlot.RESET_PASSWORD,
    AuthRateLimitSlot.TOTP_ENABLE,
    AuthRateLimitSlot.TOTP_CONFIRM_ENABLE,
    AuthRateLimitSlot.TOTP_VERIFY,
    AuthRateLimitSlot.TOTP_DISABLE,
    AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES,
    AuthRateLimitSlot.VERIFY_TOKEN,
    AuthRateLimitSlot.REQUEST_VERIFY_TOKEN,
)
AUTH_RATE_LIMIT_SLOT_VALUES = tuple(slot.value for slot in AUTH_RATE_LIMIT_SLOT_IDENTIFIERS)
AUTH_RATE_LIMIT_GROUP_IDENTIFIERS: tuple[AuthRateLimitEndpointGroup, ...] = (
    "login",
    "password_reset",
    "refresh",
    "register",
    "totp",
    "verification",
)
AUTH_RATE_LIMIT_SLOT_IDENTIFIERS_BY_GROUP: dict[
    AuthRateLimitEndpointGroup,
    frozenset[AuthRateLimitSlot],
] = {
    "login": frozenset({AuthRateLimitSlot.LOGIN, AuthRateLimitSlot.CHANGE_PASSWORD}),
    "password_reset": frozenset({AuthRateLimitSlot.FORGOT_PASSWORD, AuthRateLimitSlot.RESET_PASSWORD}),
    "refresh": frozenset({AuthRateLimitSlot.REFRESH}),
    "register": frozenset({AuthRateLimitSlot.REGISTER}),
    "totp": frozenset(
        {
            AuthRateLimitSlot.TOTP_ENABLE,
            AuthRateLimitSlot.TOTP_CONFIRM_ENABLE,
            AuthRateLimitSlot.TOTP_VERIFY,
            AuthRateLimitSlot.TOTP_DISABLE,
            AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES,
        },
    ),
    "verification": frozenset({AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}),
}
AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS = AUTH_RATE_LIMIT_SLOT_IDENTIFIERS_BY_GROUP["verification"]

KEY_CAP = 2


def _reload_module(module_path: str) -> ModuleType:
    """Import and reload a module so coverage records its module body.

    Returns:
        The reloaded module object.
    """
    return importlib.reload(importlib.import_module(module_path))


def _unwrap_optional(annotation: object) -> object:
    """Return the non-``None`` member of an optional annotation."""
    args = get_args(annotation)
    if type(None) not in args:
        return annotation

    non_none_args = tuple(arg for arg in args if arg is not type(None))
    assert len(non_none_args) == 1
    return non_none_args[0]


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
    headers: dict[str, str] = field(default_factory=dict)

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
        "login:"
        f"{ratelimit_helpers_module._safe_key_part('127.0.0.1')}:"
        f"{ratelimit_helpers_module._safe_key_part('reloaded@example.com')}"
    )
    assert await ratelimit_helpers_module._extract_email(request) == "Reloaded@Example.com"
    await orchestrator.on_success("verify", request)


def test_auth_rate_limit_config_exposes_stable_endpoint_slots() -> None:
    """AuthRateLimitConfig keeps the current per-endpoint field inventory."""
    assert tuple(field.name for field in fields(ratelimit_module.AuthRateLimitConfig)) == AUTH_RATE_LIMIT_SLOT_VALUES
    assert all(field.default is None for field in fields(ratelimit_module.AuthRateLimitConfig))


def test_auth_rate_limit_identifier_helpers_stay_aligned_with_public_builder_contract() -> None:
    """Default recipe metadata stays aligned with the public enum builder contract."""
    group_identifiers = get_args(ratelimit_module.AuthRateLimitEndpointGroup.__value__)

    assert tuple(field.name for field in fields(AuthRateLimitConfig)) == AUTH_RATE_LIMIT_SLOT_VALUES
    assert AUTH_RATE_LIMIT_SLOT_IDENTIFIERS == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_SLOTS
    assert group_identifiers == AUTH_RATE_LIMIT_GROUP_IDENTIFIERS
    assert frozenset(group_identifiers) == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_GROUPS
    assert (
        ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP
        == AUTH_RATE_LIMIT_SLOT_IDENTIFIERS_BY_GROUP
    )


def test_auth_rate_limit_slot_enum_stays_aligned_with_public_inventory() -> None:
    """The slot enum defines the public values in stable order."""
    slot_enum = ratelimit_config_module.AuthRateLimitSlot

    assert tuple(slot_enum) == AUTH_RATE_LIMIT_SLOT_IDENTIFIERS
    assert tuple(member.value for member in slot_enum) == AUTH_RATE_LIMIT_SLOT_VALUES
    assert tuple(member.name for member in slot_enum) == (
        "LOGIN",
        "CHANGE_PASSWORD",
        "REFRESH",
        "REGISTER",
        "FORGOT_PASSWORD",
        "RESET_PASSWORD",
        "TOTP_ENABLE",
        "TOTP_CONFIRM_ENABLE",
        "TOTP_VERIFY",
        "TOTP_DISABLE",
        "TOTP_REGENERATE_RECOVERY_CODES",
        "VERIFY_TOKEN",
        "REQUEST_VERIFY_TOKEN",
    )


def test_auth_rate_limit_change_password_slot_is_distinct_from_login() -> None:
    """Password rotation has an independently tunable slot instead of reusing login."""
    assert AuthRateLimitSlot.CHANGE_PASSWORD.value == "change_password"
    assert AuthRateLimitSlot.CHANGE_PASSWORD is not AuthRateLimitSlot.LOGIN


def test_auth_rate_limit_slot_enum_iteration_feeds_shared_builder_inputs() -> None:
    """The public slot enum remains valid input for the shared-backend builder."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(
            enabled=tuple(AuthRateLimitSlot),
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS,
        ),
    )
    assert config.login == EndpointRateLimit(backend=shared_backend, scope="ip_email", namespace="login")
    assert config.forgot_password == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="forgot-password",
    )
    assert config.verify_token is None
    assert config.request_verify_token is None


def test_auth_rate_limit_slot_enum_threads_through_builder_type_hints() -> None:
    """The shared-backend builder keys its public slot inputs with the exported enum."""
    builder_type_hints = get_type_hints(AuthRateLimitConfig.from_shared_backend, include_extras=True)

    options_annotation = _unwrap_optional(builder_type_hints["options"])
    option_hints = get_type_hints(options_annotation, include_extras=True)
    enabled_annotation = _unwrap_optional(option_hints["enabled"])
    disabled_annotation = option_hints["disabled"]
    group_backends_annotation = _unwrap_optional(option_hints["group_backends"])
    endpoint_overrides_annotation = _unwrap_optional(option_hints["endpoint_overrides"])

    assert get_origin(enabled_annotation) is Iterable
    assert get_args(enabled_annotation) == (ratelimit_module.AuthRateLimitSlot,)
    assert get_origin(disabled_annotation) is Iterable
    assert get_args(disabled_annotation) == (ratelimit_module.AuthRateLimitSlot,)

    assert get_origin(group_backends_annotation) is Mapping
    assert get_args(group_backends_annotation) == (
        ratelimit_module.AuthRateLimitEndpointGroup,
        RateLimiterBackend,
    )
    assert get_origin(endpoint_overrides_annotation) is Mapping
    assert get_args(endpoint_overrides_annotation)[0] is ratelimit_module.AuthRateLimitSlot
    assert set(get_args(get_args(endpoint_overrides_annotation)[1])) == {EndpointRateLimit, type(None)}


def test_auth_rate_limit_config_from_shared_backend_accepts_slot_enum_override_keys() -> None:
    """Endpoint override maps accept slot enums while keeping runtime behavior unchanged."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    forgot_password_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip",
        namespace="forgot_password",
    )
    verification_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="verify-request",
    )
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(
            enabled=(AuthRateLimitSlot.FORGOT_PASSWORD, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN),
            endpoint_overrides={
                AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
                AuthRateLimitSlot.REQUEST_VERIFY_TOKEN: verification_override,
            },
        ),
    )

    assert config.forgot_password is forgot_password_override
    assert config.request_verify_token is verification_override


def test_endpoint_rate_limit_annotations_are_runtime_resolvable() -> None:
    """The public endpoint limiter surface keeps runtime-resolvable annotations."""
    endpoint_hints = get_type_hints(EndpointRateLimit)
    before_request_hints = get_type_hints(EndpointRateLimit.before_request)
    build_key_hints = get_type_hints(EndpointRateLimit.build_key)

    assert endpoint_hints["backend"] is RateLimiterBackend
    assert get_origin(before_request_hints["request"]) is Request
    assert get_args(before_request_hints["request"]) == (Any, Any, Any)
    assert before_request_hints["return"] is type(None)
    assert get_origin(build_key_hints["request"]) is Request
    assert get_args(build_key_hints["request"]) == (Any, Any, Any)
    assert build_key_hints["return"] is str
    assert ratelimit_config_module.EndpointRateLimit is ratelimit_endpoint_module.EndpointRateLimit


def test_auth_rate_limit_default_recipes_cover_supported_slots_scopes_groups_and_namespaces() -> None:
    """Default auth rate-limit recipes cover the supported slot inventory."""
    recipes = ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_RECIPES
    catalog = ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_CATALOG

    assert tuple(recipe.slot for recipe in recipes) == tuple(field.name for field in fields(AuthRateLimitConfig))
    assert tuple(ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT) == tuple(
        field.name for field in fields(AuthRateLimitConfig)
    )
    assert catalog.recipes == recipes
    assert catalog.recipes_by_slot == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT
    assert catalog.slots == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_SLOTS
    assert catalog.slot_set == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET
    assert catalog.slots_by_group == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP
    assert catalog.groups == ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_GROUPS
    assert {recipe.slot: recipe.default_scope for recipe in recipes} == {
        "login": "ip_email",
        "change_password": "ip_email",
        "refresh": "ip",
        "register": "ip",
        "forgot_password": "ip_email",
        "reset_password": "ip",
        "totp_enable": "ip",
        "totp_confirm_enable": "ip",
        "totp_verify": "ip",
        "totp_disable": "ip",
        "totp_regenerate_recovery_codes": "ip",
        "verify_token": "ip",
        "request_verify_token": "ip_email",
    }
    assert {recipe.slot: recipe.default_namespace for recipe in recipes} == {
        "login": "login",
        "change_password": "change-password",
        "refresh": "refresh",
        "register": "register",
        "forgot_password": "forgot-password",
        "reset_password": "reset-password",
        "totp_enable": "totp-enable",
        "totp_confirm_enable": "totp-confirm-enable",
        "totp_verify": "totp-verify",
        "totp_disable": "totp-disable",
        "totp_regenerate_recovery_codes": "totp-regenerate-recovery-codes",
        "verify_token": "verify-token",
        "request_verify_token": "request-verify-token",
    }
    assert {recipe.slot: recipe.group for recipe in recipes} == {
        "login": "login",
        "change_password": "login",
        "refresh": "refresh",
        "register": "register",
        "forgot_password": "password_reset",
        "reset_password": "password_reset",
        "totp_enable": "totp",
        "totp_confirm_enable": "totp",
        "totp_verify": "totp",
        "totp_disable": "totp",
        "totp_regenerate_recovery_codes": "totp",
        "verify_token": "verification",
        "request_verify_token": "verification",
    }
    assert catalog.slots_by_group == AUTH_RATE_LIMIT_SLOT_IDENTIFIERS_BY_GROUP


def test_auth_rate_limit_slot_catalog_module_executes_standalone() -> None:
    """The extracted slot catalog can initialize without importing the config module."""
    module_globals = runpy.run_path(str(Path(ratelimit_slot_catalog_module.__file__).resolve()))
    catalog = module_globals["_AUTH_RATE_LIMIT_ENDPOINT_CATALOG"]
    slots = module_globals["_AUTH_RATE_LIMIT_ENDPOINT_SLOTS"]

    assert tuple(slot.value for slot in slots) == AUTH_RATE_LIMIT_SLOT_VALUES
    assert catalog.slots == slots


def test_auth_rate_limit_catalog_query_helpers_respect_slot_order_and_disablement() -> None:
    """Builder slot selection stays ordered and respects disablement."""
    catalog = ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_CATALOG
    enabled_slots = catalog.resolve_enabled_slots(
        (AuthRateLimitSlot.LOGIN, AuthRateLimitSlot.REFRESH, AuthRateLimitSlot.TOTP_VERIFY),
    )
    selected_recipes = tuple(
        catalog.iter_enabled_recipes(
            enabled_slots=enabled_slots,
            disabled_slots=frozenset({AuthRateLimitSlot.REFRESH}),
        ),
    )

    assert enabled_slots == frozenset(
        {AuthRateLimitSlot.LOGIN, AuthRateLimitSlot.REFRESH, AuthRateLimitSlot.TOTP_VERIFY},
    )
    assert tuple(recipe.slot for recipe in selected_recipes) == (AuthRateLimitSlot.LOGIN, AuthRateLimitSlot.TOTP_VERIFY)


def test_auth_rate_limit_config_from_shared_backend_accepts_all_supported_group_identifiers() -> None:
    """Every documented group identifier maps to the expected public slot inventory."""
    default_backend = InMemoryRateLimiter(max_attempts=1, window_seconds=10)
    login_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    password_reset_backend = InMemoryRateLimiter(max_attempts=3, window_seconds=10)
    refresh_backend = InMemoryRateLimiter(max_attempts=4, window_seconds=10)
    register_backend = InMemoryRateLimiter(max_attempts=5, window_seconds=10)
    totp_backend = InMemoryRateLimiter(max_attempts=6, window_seconds=10)
    verification_backend = InMemoryRateLimiter(max_attempts=7, window_seconds=10)
    group_backends: dict[AuthRateLimitEndpointGroup, InMemoryRateLimiter] = {
        "login": login_backend,
        "password_reset": password_reset_backend,
        "refresh": refresh_backend,
        "register": register_backend,
        "totp": totp_backend,
        "verification": verification_backend,
    }

    config = AuthRateLimitConfig.from_shared_backend(
        default_backend,
        options=SharedRateLimitConfigOptions(
            enabled=AUTH_RATE_LIMIT_SLOT_IDENTIFIERS,
            group_backends=group_backends,
        ),
    )

    expected_backends = {
        "login": login_backend,
        "change_password": login_backend,
        "refresh": refresh_backend,
        "register": register_backend,
        "forgot_password": password_reset_backend,
        "reset_password": password_reset_backend,
        "totp_enable": totp_backend,
        "totp_confirm_enable": totp_backend,
        "totp_verify": totp_backend,
        "totp_disable": totp_backend,
        "totp_regenerate_recovery_codes": totp_backend,
        "verify_token": verification_backend,
        "request_verify_token": verification_backend,
    }

    for slot, expected_backend in expected_backends.items():
        limiter = getattr(config, slot)

        assert limiter is not None
        assert limiter.backend is expected_backend


def test_auth_rate_limit_config_manual_construction_remains_plain_dataclass() -> None:
    """Direct AuthRateLimitConfig construction remains unchanged after catalog extraction."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    login_rate_limit = EndpointRateLimit(backend=shared_backend, scope="ip_email", namespace="login")
    verify_rate_limit = EndpointRateLimit(backend=shared_backend, scope="ip", namespace="verify-token")
    config = AuthRateLimitConfig(login=login_rate_limit, verify_token=verify_rate_limit)

    assert config == AuthRateLimitConfig(login=login_rate_limit, verify_token=verify_rate_limit)
    assert config.login is login_rate_limit
    assert config.verify_token is verify_rate_limit
    assert config.request_verify_token is None


def test_auth_rate_limit_config_from_shared_backend_uses_supported_slot_defaults() -> None:
    """The shared-backend builder materializes every supported slot by default."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(trusted_proxy=True),
    )

    for recipe in ratelimit_slot_catalog_module._AUTH_RATE_LIMIT_ENDPOINT_RECIPES:
        limiter = getattr(config, recipe.slot)

        assert limiter is not None
        assert limiter.backend is shared_backend
        assert limiter.scope == recipe.default_scope
        assert limiter.namespace == recipe.default_namespace
        assert limiter.trusted_proxy is True
        assert limiter.identity_fields == ("identifier", "username", "email")
        assert limiter.trusted_headers == ratelimit_config_module._DEFAULT_TRUSTED_HEADERS


def test_auth_rate_limit_config_strict_preset_enables_only_public_sign_in_slots() -> None:
    """The strict preset limits only the shared sign-in attack surfaces."""
    strict_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=60)
    config = AuthRateLimitConfig.strict(backend=strict_backend)

    assert config.login == EndpointRateLimit(
        backend=strict_backend,
        scope="ip_email",
        namespace="login",
    )
    assert config.change_password == EndpointRateLimit(
        backend=strict_backend,
        scope="ip_email",
        namespace="change-password",
    )
    assert config.register == EndpointRateLimit(
        backend=strict_backend,
        scope="ip",
        namespace="register",
    )
    assert config.totp_verify == EndpointRateLimit(
        backend=strict_backend,
        scope="ip",
        namespace="totp-verify",
    )
    assert config.totp_regenerate_recovery_codes == EndpointRateLimit(
        backend=strict_backend,
        scope="ip",
        namespace="totp-regenerate-recovery-codes",
    )
    assert config.refresh is None
    assert config.forgot_password is None
    assert config.reset_password is None
    assert config.totp_enable is None
    assert config.totp_confirm_enable is None
    assert config.totp_disable is None
    assert config.totp_regenerate_recovery_codes is not None
    assert config.verify_token is None
    assert config.request_verify_token is None


def test_auth_rate_limit_config_disabled_preset_turns_off_every_endpoint() -> None:
    """The disabled preset leaves every auth endpoint slot unset."""
    config = AuthRateLimitConfig.disabled()

    assert all(getattr(config, field.name) is None for field in fields(AuthRateLimitConfig))


def test_auth_rate_limit_config_lenient_preset_keeps_sensitive_routes_stricter() -> None:
    """The lenient preset caps token and secret routes below the shared budget."""
    lenient_backend = InMemoryRateLimiter(max_attempts=12, window_seconds=LENIENT_MEMORY_WINDOW_SECONDS)
    config = AuthRateLimitConfig.lenient(backend=lenient_backend)
    sensitive_backend = config.forgot_password

    assert config.login == EndpointRateLimit(
        backend=lenient_backend,
        scope="ip_email",
        namespace="login",
    )
    assert config.change_password == EndpointRateLimit(
        backend=lenient_backend,
        scope="ip_email",
        namespace="change-password",
    )
    assert config.refresh == EndpointRateLimit(
        backend=lenient_backend,
        scope="ip",
        namespace="refresh",
    )
    assert config.register == EndpointRateLimit(
        backend=lenient_backend,
        scope="ip",
        namespace="register",
    )
    assert sensitive_backend is not None
    assert isinstance(sensitive_backend.backend, InMemoryRateLimiter)
    assert sensitive_backend.backend is not lenient_backend
    assert sensitive_backend.backend.max_attempts == LENIENT_STRICT_MAX_ATTEMPTS
    assert sensitive_backend.backend.window_seconds == LENIENT_MEMORY_WINDOW_SECONDS
    assert config.reset_password == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="reset-password",
    )
    assert config.totp_enable == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="totp-enable",
    )
    assert config.totp_confirm_enable == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="totp-confirm-enable",
    )
    assert config.totp_verify == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="totp-verify",
    )
    assert config.totp_disable == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="totp-disable",
    )
    assert config.totp_regenerate_recovery_codes == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="totp-regenerate-recovery-codes",
    )
    assert config.verify_token == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip",
        namespace="verify-token",
    )
    assert config.request_verify_token == EndpointRateLimit(
        backend=sensitive_backend.backend,
        scope="ip_email",
        namespace="request-verify-token",
    )


def test_auth_rate_limit_config_lenient_preset_clones_redis_backend_for_sensitive_routes() -> None:
    """The lenient preset preserves Redis wiring while capping sensitive attempts."""
    redis_client = cast("Any", object())
    lenient_backend = RedisRateLimiter(
        redis=redis_client,
        max_attempts=9,
        window_seconds=LENIENT_REDIS_WINDOW_SECONDS,
        key_prefix="auth:",
    )

    config = AuthRateLimitConfig.lenient(backend=lenient_backend)
    sensitive_backend = config.verify_token

    assert config.login is not None
    assert config.login.backend is lenient_backend
    assert sensitive_backend is not None
    assert isinstance(sensitive_backend.backend, RedisRateLimiter)
    assert sensitive_backend.backend is not lenient_backend
    assert sensitive_backend.backend.redis is redis_client
    assert sensitive_backend.backend.max_attempts == LENIENT_STRICT_MAX_ATTEMPTS
    assert sensitive_backend.backend.window_seconds == LENIENT_REDIS_WINDOW_SECONDS
    assert sensitive_backend.backend.key_prefix == "auth:"


def test_auth_rate_limit_config_lenient_preset_rejects_unknown_backend_types() -> None:
    """The lenient preset fails fast when it cannot safely clone the backend."""

    class CustomRateLimiter:
        @property
        def is_shared_across_workers(self) -> bool:
            return False

        async def check(self, key: str) -> bool:
            return True

        async def increment(self, key: str) -> None:
            del key

        async def reset(self, key: str) -> None:
            del key

        async def retry_after(self, key: str) -> int:
            del key
            return 0

    with pytest.raises(TypeError, match="built-in InMemoryRateLimiter or RedisRateLimiter"):
        AuthRateLimitConfig.lenient(backend=CustomRateLimiter())


def test_auth_rate_limit_config_from_shared_backend_supports_partial_enablement_and_disabled_slots() -> None:
    """The shared-backend builder can leave individual slots unset."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(
            enabled=(AuthRateLimitSlot.LOGIN, AuthRateLimitSlot.REFRESH, AuthRateLimitSlot.TOTP_VERIFY),
            disabled=(AuthRateLimitSlot.REFRESH,),
        ),
    )

    assert config.login is not None
    assert config.totp_verify is not None
    assert config.refresh is None
    assert config.register is None
    assert config.forgot_password is None
    assert config.reset_password is None
    assert config.totp_enable is None
    assert config.totp_confirm_enable is None
    assert config.totp_disable is None
    assert config.totp_regenerate_recovery_codes is None
    assert config.verify_token is None
    assert config.request_verify_token is None


def test_auth_rate_limit_config_from_shared_backend_applies_group_backends_and_endpoint_overrides() -> None:
    """The builder applies group backends before canonical endpoint overrides."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    totp_backend = InMemoryRateLimiter(max_attempts=5, window_seconds=30)
    forgot_password_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip",
        namespace="forgot_password",
        trusted_proxy=True,
    )
    confirm_enable_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="totp-confirm-shared",
    )
    request_verify_override = EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="verify-request",
        trusted_proxy=True,
    )
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(
            enabled=(
                AuthRateLimitSlot.FORGOT_PASSWORD,
                AuthRateLimitSlot.TOTP_ENABLE,
                AuthRateLimitSlot.TOTP_CONFIRM_ENABLE,
                AuthRateLimitSlot.TOTP_VERIFY,
                AuthRateLimitSlot.REQUEST_VERIFY_TOKEN,
            ),
            group_backends={"totp": totp_backend},
            endpoint_overrides={
                AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
                AuthRateLimitSlot.TOTP_ENABLE: None,
                AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: confirm_enable_override,
                AuthRateLimitSlot.REQUEST_VERIFY_TOKEN: request_verify_override,
            },
            trusted_proxy=True,
        ),
    )

    assert config.totp_enable is None
    assert config.totp_confirm_enable is confirm_enable_override
    assert config.forgot_password is forgot_password_override
    assert config.totp_verify is not None
    assert config.totp_verify.backend is totp_backend
    assert config.totp_verify.scope == "ip"
    assert config.totp_verify.namespace == "totp-verify"
    assert config.totp_verify.trusted_proxy is True
    assert config.request_verify_token is request_verify_override


async def test_auth_rate_limit_config_from_shared_backend_applies_explicit_slot_overrides_and_group_backends() -> None:
    """Explicit slot overrides and group backends drive the final namespace and backend layout."""
    credential_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    refresh_backend = InMemoryRateLimiter(max_attempts=3, window_seconds=15)
    totp_backend = InMemoryRateLimiter(max_attempts=4, window_seconds=20)
    group_backends: dict[AuthRateLimitEndpointGroup, InMemoryRateLimiter] = {
        "totp": totp_backend,
        "refresh": refresh_backend,
    }
    disabled_slots = AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS
    endpoint_overrides: dict[AuthRateLimitSlot, EndpointRateLimit] = {
        AuthRateLimitSlot.FORGOT_PASSWORD: EndpointRateLimit(
            backend=credential_backend,
            scope="ip_email",
            namespace="forgot_password",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.RESET_PASSWORD: EndpointRateLimit(
            backend=credential_backend,
            scope="ip",
            namespace="reset_password",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.TOTP_ENABLE: EndpointRateLimit(
            backend=totp_backend,
            scope="ip",
            namespace="totp_enable",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: EndpointRateLimit(
            backend=totp_backend,
            scope="ip",
            namespace="totp_confirm_enable",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
            backend=totp_backend,
            scope="ip",
            namespace="totp_verify",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.TOTP_DISABLE: EndpointRateLimit(
            backend=totp_backend,
            scope="ip",
            namespace="totp_disable",
            trusted_proxy=True,
        ),
        AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES: EndpointRateLimit(
            backend=totp_backend,
            scope="ip",
            namespace="totp_regenerate_recovery_codes",
            trusted_proxy=True,
        ),
    }
    config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        options=SharedRateLimitConfigOptions(
            group_backends=group_backends,
            disabled=disabled_slots,
            endpoint_overrides=endpoint_overrides,
            trusted_proxy=True,
        ),
    )
    credential_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={"identifier": "User@Example.com", "email": "User@Example.com"},
            client=ClientStub(host="10.0.0.1"),
        ),
    )
    ip_only_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(payload={"token": "ignored"}, client=ClientStub(host="10.0.0.1")),
    )
    expected_limiters = {
        "login": (credential_backend, "ip_email", "login"),
        "change_password": (credential_backend, "ip_email", "change-password"),
        "refresh": (refresh_backend, "ip", "refresh"),
        "register": (credential_backend, "ip", "register"),
        "forgot_password": (credential_backend, "ip_email", "forgot_password"),
        "reset_password": (credential_backend, "ip", "reset_password"),
        "totp_enable": (totp_backend, "ip", "totp_enable"),
        "totp_confirm_enable": (totp_backend, "ip", "totp_confirm_enable"),
        "totp_verify": (totp_backend, "ip", "totp_verify"),
        "totp_disable": (totp_backend, "ip", "totp_disable"),
        "totp_regenerate_recovery_codes": (totp_backend, "ip", "totp_regenerate_recovery_codes"),
    }

    for slot, (backend, scope, namespace) in expected_limiters.items():
        limiter = getattr(config, slot)

        assert limiter is not None
        assert limiter.backend is backend
        assert limiter.scope == scope
        assert limiter.namespace == namespace
        assert limiter.trusted_proxy is True

    assert config.verify_token is None
    assert config.request_verify_token is None
    key_requests = {
        "login": credential_request,
        "change_password": credential_request,
        "forgot_password": credential_request,
        "refresh": ip_only_request,
        "totp_verify": ip_only_request,
        "totp_disable": ip_only_request,
        "totp_regenerate_recovery_codes": ip_only_request,
    }
    expected_keys = {
        "login": (
            f"login:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
            f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
        ),
        "change_password": (
            f"change-password:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
            f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
        ),
        "forgot_password": (
            f"forgot_password:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
            f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
        ),
        "refresh": f"refresh:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}",
        "totp_verify": f"totp_verify:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}",
        "totp_disable": f"totp_disable:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}",
        "totp_regenerate_recovery_codes": (
            f"totp_regenerate_recovery_codes:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}"
        ),
    }

    for slot, expected_key in expected_keys.items():
        limiter = getattr(config, slot)

        assert limiter is not None
        assert await limiter.build_key(key_requests[slot]) == expected_key


def test_auth_rate_limit_config_from_shared_backend_supports_documented_redis_override_recipe(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The documented Redis override recipe stays expressible through the shared builder."""
    redis_client = cast_fakeredis(async_fakeredis, RedisClientProtocol)
    credential_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60)
    refresh_backend = RedisRateLimiter(redis=redis_client, max_attempts=10, window_seconds=300)
    totp_backend = RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=300)

    config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        options=SharedRateLimitConfigOptions(
            group_backends={"refresh": refresh_backend, "totp": totp_backend},
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS,
            endpoint_overrides={
                AuthRateLimitSlot.FORGOT_PASSWORD: EndpointRateLimit(
                    backend=credential_backend,
                    scope="ip_email",
                    namespace="forgot_password",
                ),
                AuthRateLimitSlot.RESET_PASSWORD: EndpointRateLimit(
                    backend=credential_backend,
                    scope="ip",
                    namespace="reset_password",
                ),
                AuthRateLimitSlot.TOTP_ENABLE: EndpointRateLimit(
                    backend=totp_backend,
                    scope="ip",
                    namespace="totp_enable",
                ),
                AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: EndpointRateLimit(
                    backend=totp_backend,
                    scope="ip",
                    namespace="totp_confirm_enable",
                ),
                AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
                    backend=totp_backend,
                    scope="ip",
                    namespace="totp_verify",
                ),
                AuthRateLimitSlot.TOTP_DISABLE: EndpointRateLimit(
                    backend=totp_backend,
                    scope="ip",
                    namespace="totp_disable",
                ),
                AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES: EndpointRateLimit(
                    backend=totp_backend,
                    scope="ip",
                    namespace="totp_regenerate_recovery_codes",
                ),
            },
        ),
    )
    assert config.login == EndpointRateLimit(backend=credential_backend, scope="ip_email", namespace="login")
    assert config.change_password == EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="change-password",
    )
    assert config.refresh == EndpointRateLimit(backend=refresh_backend, scope="ip", namespace="refresh")
    assert config.register == EndpointRateLimit(backend=credential_backend, scope="ip", namespace="register")
    assert config.forgot_password == EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot_password",
    )
    assert config.reset_password == EndpointRateLimit(
        backend=credential_backend,
        scope="ip",
        namespace="reset_password",
    )
    assert config.totp_enable == EndpointRateLimit(backend=totp_backend, scope="ip", namespace="totp_enable")
    assert config.totp_confirm_enable == EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_confirm_enable",
    )
    assert config.totp_verify == EndpointRateLimit(backend=totp_backend, scope="ip", namespace="totp_verify")
    assert config.totp_disable == EndpointRateLimit(backend=totp_backend, scope="ip", namespace="totp_disable")
    assert config.verify_token is None
    assert config.request_verify_token is None


async def test_contrib_redis_preset_builds_rate_limit_config_with_shared_client_tiers(
    async_fakeredis: AsyncFakeRedis,
    monkeypatch: pytest.MonkeyPatch,
    patch_redis_loader: None,
) -> None:
    """The contrib preset preserves group tiers, overrides, and the TOTP Redis store builders."""
    del patch_redis_loader

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth._totp_stores._load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth._totp_stores._load_enrollment_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist._load_redis_asyncio", load_optional_redis)
    redis_client = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    assert isinstance(redis_client, RedisAuthClientProtocol)
    preset = RedisAuthPreset(
        redis=redis_client,
        rate_limit_tier=RedisAuthRateLimitTier(
            max_attempts=SHARED_MAX_ATTEMPTS,
            window_seconds=SHARED_WINDOW_SECONDS,
        ),
        group_rate_limit_tiers={
            "refresh": RedisAuthRateLimitTier(
                max_attempts=REFRESH_MAX_ATTEMPTS,
                window_seconds=REFRESH_WINDOW_SECONDS,
                key_prefix="refresh:",
            ),
            "totp": RedisAuthRateLimitTier(
                max_attempts=TOTP_MAX_ATTEMPTS,
                window_seconds=TOTP_WINDOW_SECONDS,
                key_prefix="totp:",
            ),
        },
    )
    explicit_totp_backend = InMemoryRateLimiter(max_attempts=9, window_seconds=90)
    credential_request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={"identifier": "User@Example.com", "email": "User@Example.com"},
            client=ClientStub(host="10.0.0.1"),
        ),
    )

    config = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS,
            group_backends={"totp": explicit_totp_backend},
        ),
    )
    store = preset.build_totp_used_tokens_store(key_prefix="used:")
    enrollment_store = preset.build_totp_enrollment_store(key_prefix="enroll:")
    pending_store = preset.build_totp_pending_jti_store(key_prefix="pending:")

    assert config.login is not None
    assert isinstance(config.login.backend, RedisRateLimiter)
    assert config.login.backend.redis is redis_client
    assert config.login.backend.max_attempts == SHARED_MAX_ATTEMPTS
    assert config.login.backend.window_seconds == SHARED_WINDOW_SECONDS
    assert config.login.backend.key_prefix == DEFAULT_KEY_PREFIX
    assert config.refresh is not None
    assert isinstance(config.refresh.backend, RedisRateLimiter)
    assert config.refresh.backend.redis is redis_client
    assert config.refresh.backend.max_attempts == REFRESH_MAX_ATTEMPTS
    assert config.refresh.backend.window_seconds == REFRESH_WINDOW_SECONDS
    assert config.refresh.backend.key_prefix == "refresh:"
    assert config.refresh.namespace == "refresh"
    assert config.forgot_password is not None
    assert config.forgot_password.namespace == "forgot-password"
    assert await config.forgot_password.build_key(credential_request) == (
        f"forgot-password:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
        f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
    )
    assert config.totp_verify is not None
    assert config.totp_verify.backend is explicit_totp_backend
    assert config.totp_disable is not None
    assert config.totp_disable.backend is explicit_totp_backend
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert store._redis is redis_client
    assert enrollment_store._redis is redis_client
    assert pending_store.redis is redis_client
    assert enrollment_store._key("user-1").startswith("enroll:")
    assert pending_store.key_prefix == "pending:"
    assert (await store.mark_used("user-1", 7, 1.25)).stored is True
    await pending_store.deny("pending-jti", ttl_seconds=PENDING_JTI_TTL_SECONDS)
    assert await pending_store.is_denied("pending-jti") is True
    assert await async_fakeredis.get("used:user-1:7") == b"1"
    assert await async_fakeredis.get("pending:pending-jti") == b"1"
    assert 0 < await async_fakeredis.pttl("used:user-1:7") <= USED_TOTP_TTL_MS
    assert PENDING_JTI_TTL_FLOOR <= await async_fakeredis.ttl("pending:pending-jti") <= PENDING_JTI_TTL_SECONDS


def test_auth_rate_limit_config_from_shared_backend_uses_default_route_namespaces() -> None:
    """The shared-backend builder uses the default route-style namespaces."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(enabled=(AuthRateLimitSlot.FORGOT_PASSWORD,)),
    )

    assert config.forgot_password == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="forgot-password",
    )


def test_auth_rate_limit_config_from_shared_backend_rejects_unknown_endpoint_override_slot() -> None:
    """The shared-backend builder validates endpoint override slot names."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)

    with pytest.raises(
        TypeError,
        match="endpoint_overrides must contain AuthRateLimitSlot values: bogus-slot",
    ):
        AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            options=SharedRateLimitConfigOptions(endpoint_overrides=cast("Any", {"bogus-slot": None})),
        )


def test_auth_rate_limit_config_from_shared_backend_rejects_string_endpoint_override_slot() -> None:
    """The shared-backend builder requires enum slot keys, not raw strings."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)

    with pytest.raises(
        TypeError,
        match="endpoint_overrides must contain AuthRateLimitSlot values: login",
    ):
        AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            options=SharedRateLimitConfigOptions(endpoint_overrides=cast("Any", {"login": None})),
        )


def test_auth_rate_limit_config_from_shared_backend_rejects_unknown_enabled_slot() -> None:
    """The shared-backend builder validates enabled slot names."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)

    with pytest.raises(TypeError, match="enabled must contain AuthRateLimitSlot values: bogus-slot"):
        AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            options=SharedRateLimitConfigOptions(enabled=cast("Any", (AuthRateLimitSlot.LOGIN, "bogus-slot"))),
        )


def test_auth_rate_limit_config_from_shared_backend_rejects_string_disabled_slot() -> None:
    """The shared-backend builder requires enum disabled values, not raw strings."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)

    with pytest.raises(TypeError, match="disabled must contain AuthRateLimitSlot values: verify_token"):
        AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            options=SharedRateLimitConfigOptions(disabled=cast("Any", {"verify_token"})),
        )


def test_auth_rate_limit_config_from_shared_backend_rejects_unknown_group_name() -> None:
    """The shared-backend builder validates group override names."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)

    with pytest.raises(ValueError, match="group_backends contains unsupported auth rate-limit groups: bogus-group"):
        AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            options=SharedRateLimitConfigOptions(
                group_backends=cast("Any", {"bogus-group": InMemoryRateLimiter(max_attempts=1, window_seconds=10)}),
            ),
        )


def test_auth_rate_limit_config_from_shared_backend_builds_default_route_namespaces() -> None:
    """The default shared-builder output uses the hyphenated route namespaces."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig.from_shared_backend(
        shared_backend,
        options=SharedRateLimitConfigOptions(
            enabled=(
                AuthRateLimitSlot.FORGOT_PASSWORD,
                AuthRateLimitSlot.TOTP_VERIFY,
                AuthRateLimitSlot.REQUEST_VERIFY_TOKEN,
            ),
        ),
    )

    assert config.forgot_password == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="forgot-password",
    )
    assert config.totp_verify == EndpointRateLimit(
        backend=shared_backend,
        scope="ip",
        namespace="totp-verify",
    )
    assert config.request_verify_token == EndpointRateLimit(
        backend=shared_backend,
        scope="ip_email",
        namespace="request-verify-token",
    )


def test_auth_rate_limit_recipe_index_rejects_duplicate_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    """Duplicate slot definitions are rejected when building the recipe index."""
    duplicate_recipe = ratelimit_slot_catalog_module._AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.LOGIN,
        default_scope="ip_email",
        default_namespace="login",
        group="login",
    )
    monkeypatch.setattr(
        ratelimit_slot_catalog_module,
        "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES",
        (
            duplicate_recipe,
            ratelimit_slot_catalog_module._AuthRateLimitEndpointRecipe(
                slot=AuthRateLimitSlot.LOGIN,
                default_scope="ip",
                default_namespace="login-second-copy",
                group="login",
            ),
        ),
    )

    with pytest.raises(RuntimeError, match="must not contain duplicate slots"):
        ratelimit_slot_catalog_module._build_auth_rate_limit_recipe_index()


def test_auth_rate_limit_config_import_check_rejects_slot_alignment_drift() -> None:
    """Reloading `_config` fails fast when dataclass fields drift from the supported slot defaults."""
    field_stub = type("FieldStub", (), {"name": "unexpected_slot"})()
    module_name = "litestar_auth.ratelimit._config_alignment_guard_test"
    source_path = Path(ratelimit_config_module.__file__).resolve()
    source = source_path.read_text()
    patched_source = source.replace(
        "from dataclasses import dataclass, fields",
        "from dataclasses import dataclass; fields = _mismatched_fields",
        1,
    )

    def _mismatched_fields(_cls: type[object]) -> tuple[object, ...]:
        return (field_stub,)

    module = RuntimeModuleType(module_name)
    module.__file__ = str(source_path)
    module.__package__ = "litestar_auth.ratelimit"
    module.__dict__["_mismatched_fields"] = _mismatched_fields
    sys.modules[module_name] = module

    try:
        with pytest.raises(
            RuntimeError,
            match="fields must stay aligned",
        ):
            exec(compile(patched_source, str(source_path), "exec"), module.__dict__)
    finally:
        sys.modules.pop(module_name, None)


def test_auth_rate_limit_default_recipe_helpers_are_not_reexported_from_public_module() -> None:
    """Default recipe helpers are not re-exported from the public module."""
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_CATALOG")
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert hasattr(ratelimit_slot_catalog_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT")
    assert "_AUTH_RATE_LIMIT_ENDPOINT_CATALOG" not in ratelimit_module.__all__
    assert "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES" not in ratelimit_module.__all__
    assert "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT" not in ratelimit_module.__all__
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_CATALOG")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES")
    assert not hasattr(ratelimit_module, "_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT")


async def test_endpoint_rate_limit_shared_backend_preserves_namespace_and_scope_per_slot() -> None:
    """Shared backends stay endpoint-specific through namespace and scope choices."""
    shared_backend = InMemoryRateLimiter(max_attempts=2, window_seconds=10)
    config = AuthRateLimitConfig(
        login=EndpointRateLimit(backend=shared_backend, scope="ip_email", namespace="login"),
        refresh=EndpointRateLimit(backend=shared_backend, scope="ip_email", namespace="refresh"),
        totp_confirm_enable=EndpointRateLimit(
            backend=shared_backend,
            scope="ip",
            namespace="totp-confirm-enable",
        ),
        totp_verify=EndpointRateLimit(backend=shared_backend, scope="ip", namespace="totp-verify"),
    )
    request = cast(
        "Request[Any, Any, Any]",
        JsonRequestStub(
            payload={"identifier": "User@Example.com"},
            client=ClientStub(host="10.0.0.1"),
        ),
    )
    login_rate_limit = config.login
    refresh_rate_limit = config.refresh
    confirm_enable_rate_limit = config.totp_confirm_enable
    verify_rate_limit = config.totp_verify

    assert login_rate_limit is not None
    assert refresh_rate_limit is not None
    assert confirm_enable_rate_limit is not None
    assert verify_rate_limit is not None
    assert login_rate_limit.backend is shared_backend
    assert refresh_rate_limit.backend is shared_backend
    assert confirm_enable_rate_limit.backend is shared_backend
    assert verify_rate_limit.backend is shared_backend
    assert await login_rate_limit.build_key(request) == (
        "login:"
        f"{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
        f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
    )
    assert await refresh_rate_limit.build_key(request) == (
        "refresh:"
        f"{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
        f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
    )
    assert await confirm_enable_rate_limit.build_key(request) == (
        f"totp-confirm-enable:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}"
    )
    assert await verify_rate_limit.build_key(request) == (
        f"totp-verify:{ratelimit_helpers_module._safe_key_part('10.0.0.1')}"
    )


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
            "litestar_auth.ratelimit._endpoint",
            ("EndpointRateLimit", "RateLimitScope"),
            id="_endpoint",
        ),
        pytest.param(
            "litestar_auth.ratelimit._config",
            (
                "AuthRateLimitConfig",
                "AuthRateLimitEndpointGroup",
                "AuthRateLimitSlot",
                "EndpointRateLimit",
            ),
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
                "AuthRateLimitEndpointGroup",
                "AuthRateLimitSlot",
                "EndpointRateLimit",
                "InMemoryRateLimiter",
                "RateLimitScope",
                "RedisRateLimiter",
                "TotpRateLimitOrchestrator",
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


def test_public_ratelimit_all_lists_only_documented_exports() -> None:
    """The public ratelimit module keeps non-public helpers out of ``__all__``."""
    assert all(not symbol.startswith("_") for symbol in ratelimit_module.__all__)
    for symbol in (
        "_DEFAULT_TRUSTED_HEADERS",
        "_client_host",
        "_extract_email",
        "_load_redis_asyncio",
        "_safe_key_part",
        "_validate_configuration",
        "importlib",
        "logger",
    ):
        assert symbol not in ratelimit_module.__all__
        assert not hasattr(ratelimit_module, symbol)


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


@pytest.fixture
def patch_redis_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the Redis loader to return a dummy client for RedisRateLimiter tests."""

    def load_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_helpers_module, "_load_redis_asyncio", load_redis)


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
    assert ratelimit_helpers_module._client_host(request) == "127.0.0.1"


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

    assert ratelimit_helpers_module._client_host(request) == "unknown"


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
    assert ratelimit_helpers_module._client_host(request, trusted_proxy=True) == expected


def test_client_host_rejects_non_boolean_trusted_proxy_configuration() -> None:
    """trusted_proxy must be a boolean to avoid silent config misuse."""
    request = _build_request(headers=[(b"x-forwarded-for", b"203.0.113.5")])

    with pytest.raises(ConfigurationError, match="trusted_proxy must be a boolean"):
        ratelimit_helpers_module._client_host(request, trusted_proxy=cast("Any", "true"))


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
    assert (
        ratelimit_helpers_module._client_host(
            request,
            trusted_proxy=True,
            trusted_headers=trusted_headers,
        )
        == expected
    )


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


async def test_memory_rate_limiter_fails_closed_for_new_keys_at_capacity(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Capacity pressure rejects new keys instead of evicting active counters by default."""
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
    with caplog.at_level(logging.WARNING, logger=ratelimit_helpers_module.logger.name):
        assert await limiter.check("third") is False
        await limiter.increment("third")

    assert len(limiter._windows) == KEY_CAP
    assert list(limiter._windows) == ["first", "second"]
    assert "third" not in limiter._windows
    assert await limiter.check("first") is False
    assert any(getattr(record, "event", None) == "rate_limit_memory_capacity" for record in caplog.records)


async def test_memory_rate_limiter_reclaims_expired_keys_before_capacity_rejection() -> None:
    """Capacity checks prune expired idle counters before rejecting a new key."""
    clock = FakeClock()
    limiter = InMemoryRateLimiter(
        max_attempts=2,
        window_seconds=1,
        clock=clock,
        max_keys=1,
        sweep_interval=100,
    )

    await limiter.increment("expired")
    clock.advance(1.1)

    assert await limiter.check("fresh") is True
    await limiter.increment("fresh")
    assert set(limiter._windows) == {"fresh"}


def test_redis_rate_limiter_implements_shared_backend_protocol(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter matches the shared backend interface."""
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=10,
    )

    assert isinstance(limiter, RateLimiterBackend)


async def test_redis_rate_limiter_blocks_after_max_attempts(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter rejects requests after the sliding window fills."""
    clock = FakeClock()
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=30,
        clock=clock,
    )

    await limiter.increment("127.0.0.1")
    await limiter.increment("127.0.0.1")

    assert await limiter.check("127.0.0.1") is False
    assert await async_fakeredis.zcard(f"{DEFAULT_KEY_PREFIX}127.0.0.1") == limiter.max_attempts


async def test_redis_rate_limiter_check_and_retry_after_use_lua_scripts(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """Check and retry-after delegate to the shipped Lua scripts through fakeredis."""
    clock = FakeClock(now=12.5)
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=3,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )
    check_key = "127.0.0.1"
    retry_after_key = "127.0.0.2"

    await limiter.increment(check_key)
    clock.now = 11.0
    await limiter.increment(retry_after_key)
    clock.now = 12.0
    await limiter.increment(retry_after_key)
    clock.now = 12.5
    await limiter.increment(retry_after_key)

    assert limiter.is_shared_across_workers is True
    assert await limiter.check(check_key) is True
    assert await limiter.retry_after(retry_after_key) == REDIS_RETRY_AFTER


def test_redis_rate_limiter_decode_integer_accepts_bytes() -> None:
    """Redis script results may arrive as bytes and still decode cleanly."""
    assert RedisRateLimiter._decode_integer(str(REDIS_RETRY_AFTER).encode()) == REDIS_RETRY_AFTER


async def test_redis_rate_limiter_increments_with_atomic_pipeline(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter records attempts by running its increment Lua script."""
    clock = FakeClock(now=12.5)
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=3,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )

    await limiter.increment("127.0.0.1:user@example.com")

    redis_key = f"{DEFAULT_KEY_PREFIX}127.0.0.1:user@example.com"
    entries = await async_fakeredis.zrange(redis_key, 0, -1, withscores=True)
    assert len(entries) == 1
    stored_member, stored_score = entries[0]
    assert stored_member.decode().startswith(f"{clock.now:.9f}:")
    assert len(stored_member.decode().split(":")[1]) == UUID4_HEX_LENGTH
    assert stored_score == clock.now
    ttl_seconds = await async_fakeredis.ttl(redis_key)
    assert 0 < ttl_seconds <= REDIS_WINDOW_SECONDS


async def test_redis_rate_limiter_retry_after_and_reset_delegate_to_redis(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter reports retry-after from the oldest active attempt."""
    clock = FakeClock()
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=10,
        clock=clock,
    )

    await limiter.increment("127.0.0.1")
    clock.advance(2.2)
    await limiter.increment("127.0.0.1")

    assert await limiter.retry_after("127.0.0.1") == PARTIAL_RETRY_AFTER
    await limiter.reset("127.0.0.1")

    assert await async_fakeredis.exists(f"{DEFAULT_KEY_PREFIX}127.0.0.1") == 0
    assert await limiter.check("127.0.0.1") is True


async def test_redis_rate_limiter_prunes_expired_entries_like_in_memory_backend(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter drops expired attempts instead of waiting for a fixed-window reset."""
    clock = FakeClock()
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=REDIS_WINDOW_SECONDS,
        clock=clock,
    )

    await limiter.increment("127.0.0.1:user@example.com")
    clock.advance(4.9)
    second_attempt_at = clock.now
    await limiter.increment("127.0.0.1:user@example.com")
    assert await limiter.check("127.0.0.1:user@example.com") is False

    clock.advance(0.2)
    assert await limiter.check("127.0.0.1:user@example.com") is True

    entries = await async_fakeredis.zrange(
        f"{DEFAULT_KEY_PREFIX}127.0.0.1:user@example.com",
        0,
        -1,
        withscores=True,
    )
    assert len(entries) == 1
    assert entries[0][0].decode().startswith(f"{second_attempt_at:.9f}:")
    assert entries[0][1] == pytest.approx(second_attempt_at)


async def test_redis_rate_limiter_blocks_fixed_window_boundary_burst(
    async_fakeredis: AsyncFakeRedis,
    patch_redis_loader: None,
) -> None:
    """The Redis limiter prevents a burst split across a fixed-window boundary."""
    clock = FakeClock()
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=10,
        clock=clock,
    )

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
        ratelimit_helpers_module._load_redis_asyncio()


async def test_redis_rate_limiter_propagates_connection_error(
    async_fakeredis: AsyncFakeRedis,
    fakeredis_server: fakeredis.FakeServer,
    patch_redis_loader: None,
) -> None:
    """RedisRateLimiter does not swallow connection errors from Redis."""
    limiter = RedisRateLimiter(
        redis=cast_fakeredis(async_fakeredis, RedisClientProtocol),
        max_attempts=2,
        window_seconds=10,
    )
    fakeredis_server.connected = False

    with pytest.raises(RedisConnectionError):
        await limiter.check("127.0.0.1")


async def test_redis_token_strategy_propagates_connection_error(
    async_fakeredis: AsyncFakeRedis,
    fakeredis_server: fakeredis.FakeServer,
) -> None:
    """RedisTokenStrategy does not swallow connection errors from Redis."""
    user_manager = AsyncMock()
    user_manager.get = AsyncMock()
    fakeredis_server.connected = False

    strategy = RedisTokenStrategy(
        config=RedisTokenStrategyConfig(
            redis=cast_fakeredis(async_fakeredis, RedisTokenClientProtocol),
            token_hash_secret=REDIS_TOKEN_HASH_SECRET,
        ),
    )

    with pytest.raises(RedisConnectionError):
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
        "login:"
        f"{ratelimit_helpers_module._safe_key_part('10.0.0.1')}:"
        f"{ratelimit_helpers_module._safe_key_part('user@example.com')}"
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

    backend.reset.assert_awaited_once_with(
        f"register:{ratelimit_helpers_module._safe_key_part('192.168.1.1')}",
    )


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

    assert await ratelimit_helpers_module._extract_email(prioritized_request) == "user@example.com"
    assert (
        await ratelimit_helpers_module._extract_email(
            cast("Request[Any, Any, Any]", JsonRequestStub(payload={"email": "user@example.com"})),
        )
        == "user@example.com"
    )
    assert (
        await ratelimit_helpers_module._extract_email(
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

    assert await ratelimit_helpers_module._extract_email(cast("Request[Any, Any, Any]", BadJsonRequest())) is None


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

    assert await ratelimit_helpers_module._extract_email(identifier_request) == "id@example.com"
    assert await ratelimit_helpers_module._extract_email(email_request) == "other@example.com"
    assert await ratelimit_helpers_module._extract_email(blank_email_request) is None


async def test_endpoint_rate_limit_build_key_ip_uses_namespace_and_host() -> None:
    """IP-scoped keys include only the namespace and client host."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip",
        namespace="login",
    )
    request = _build_request()

    assert await limiter.build_key(request) == f"login:{ratelimit_helpers_module._safe_key_part('127.0.0.1')}"


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

    assert await limiter.build_key(request) == (f"register:{ratelimit_helpers_module._safe_key_part('192.168.1.1')}")


async def test_endpoint_rate_limit_logs_trigger(caplog: pytest.LogCaptureFixture) -> None:
    """Blocked requests emit a warning log with namespace and scope."""
    limiter = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=1, window_seconds=10),
        scope="ip",
        namespace="login",
    )
    request = _build_request()
    await limiter.increment(request)

    with (
        caplog.at_level(
            logging.WARNING,
            logger=ratelimit_helpers_module.logger.name,
        ),
        pytest.raises(TooManyRequestsException),
    ):
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
    regenerate_limiter = AsyncMock()
    orchestrator = ratelimit_module.TotpRateLimitOrchestrator(
        enable=cast("EndpointRateLimit", enable_limiter),
        verify=cast("EndpointRateLimit", verify_limiter),
        regenerate_recovery_codes=cast("EndpointRateLimit", regenerate_limiter),
    )
    empty_orchestrator = ratelimit_module.TotpRateLimitOrchestrator()

    assert orchestrator._limiters == {
        "enable": enable_limiter,
        "verify": verify_limiter,
        "regenerate_recovery_codes": regenerate_limiter,
    }

    await orchestrator.before_request("enable", request)
    await orchestrator.before_request("confirm_enable", request)
    await orchestrator.on_invalid_attempt("verify", request)
    await orchestrator.on_invalid_attempt("regenerate_recovery_codes", request)
    await orchestrator.on_invalid_attempt("disable", request)
    await orchestrator.on_account_state_failure("verify", request)
    await orchestrator.on_account_state_failure("enable", request)
    await empty_orchestrator.on_account_state_failure("verify", request)
    await orchestrator.on_success("verify", request)
    await orchestrator.on_success("confirm_enable", request)

    enable_limiter.before_request.assert_awaited_once_with(request)
    verify_limiter.increment.assert_awaited_once_with(request)
    regenerate_limiter.increment.assert_awaited_once_with(request)
    assert verify_limiter.reset.await_args_list == [call(request), call(request)]
