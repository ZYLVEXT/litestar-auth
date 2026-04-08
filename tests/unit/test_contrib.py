"""Tests for contrib package re-exports."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, cast, get_type_hints
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

import litestar_auth.contrib.redis as redis_module
import litestar_auth.contrib.redis._surface as redis_surface_module
import litestar_auth.ratelimit as ratelimit_module
from litestar_auth._redis_protocols import RedisSharedAuthClient
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy as BaseRedisTokenStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.oauth import __all__ as oauth_all
from litestar_auth.contrib.oauth import create_provider_oauth_controller
from litestar_auth.contrib.redis import (
    RedisAuthPreset,
    RedisAuthRateLimitTier,
    RedisTokenStrategy,
    RedisUsedTotpCodeStore,
)
from litestar_auth.contrib.redis import __all__ as redis_all
from litestar_auth.controllers.oauth import OAuthControllerUserManagerProtocol
from litestar_auth.oauth.router import create_provider_oauth_controller as base_create_provider_oauth_controller
from litestar_auth.ratelimit import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitEndpointGroup,
    RedisRateLimiter,
)
from litestar_auth.totp import RedisUsedTotpCodeStore as BaseRedisUsedTotpCodeStore
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit
REDIS_TOKEN_HASH_SECRET = "redis-token-hash-secret-1234567890"
SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300


class ExampleStrategy:
    """Minimal strategy implementation for backend construction."""

    async def read_token(self, token: str | None, user_manager: object) -> ExampleUser | None:
        """Return no user because this test never authenticates."""
        del token, user_manager
        return None

    async def write_token(self, user: ExampleUser) -> str:
        """Return a deterministic token string."""
        return str(user.id)

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """No-op token invalidation for tests."""
        del token, user


class ExampleUserManager(OAuthControllerUserManagerProtocol[ExampleUser, str]):
    """Minimal typed user manager for lazy-import tests."""

    user_db: object = object()

    async def create(
        self,
        user_create: object,
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> ExampleUser:
        """Return a placeholder user because this path is never reached."""
        del user_create, safe, allow_privileged
        return ExampleUser(id=uuid4())

    async def update(self, user_update: object, user: ExampleUser) -> ExampleUser:
        """Return the provided user because this path is never reached."""
        del user_update
        return user

    async def on_after_login(self, user: ExampleUser) -> None:
        """No-op login hook for protocol conformance."""
        del user


class PresetRedisClient:
    """Minimal async Redis double for contrib preset coverage."""

    def __init__(self) -> None:
        """Initialize recorded TOTP replay-store calls."""
        self.set_calls: list[tuple[str, str, bool, int | None]] = []

    async def delete(self, *names: str) -> int:
        """Return a successful delete count for protocol compatibility."""
        del names
        return 1

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> int:
        """Return a neutral Lua result for constructor-only coverage."""
        del script, numkeys, keys_and_args
        return 0

    async def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool = False,
        px: int | None = None,
    ) -> bool | None:
        """Record a TOTP replay-store write and simulate success.

        Returns:
            ``True`` to simulate a successful first-write reservation.
        """
        self.set_calls.append((name, value, nx, px))
        return True


def test_contrib_packages_reexport_public_symbols() -> None:
    """Contrib packages expose the documented convenience imports."""
    assert RedisTokenStrategy is BaseRedisTokenStrategy
    assert RedisUsedTotpCodeStore is BaseRedisUsedTotpCodeStore
    assert create_provider_oauth_controller is base_create_provider_oauth_controller


def test_contrib_packages_define_all() -> None:
    """Contrib packages publish only their intended public symbols."""
    assert redis_all == ("RedisAuthPreset", "RedisAuthRateLimitTier", "RedisTokenStrategy", "RedisUsedTotpCodeStore")
    assert oauth_all == ("create_provider_oauth_controller",)


@pytest.mark.imports
def test_contrib_redis_public_boundary_tracks_internal_surface() -> None:
    """The public Redis contrib package re-exports the dedicated internal surface."""
    assert redis_module.RedisAuthPreset is redis_surface_module.RedisAuthPreset
    assert redis_module.RedisAuthRateLimitTier is redis_surface_module.RedisAuthRateLimitTier
    assert redis_module.RedisTokenStrategy is redis_surface_module.RedisTokenStrategy
    assert redis_module.RedisUsedTotpCodeStore is redis_surface_module.RedisUsedTotpCodeStore
    assert redis_module.__all__ == redis_surface_module.__all__


def test_contrib_redis_preset_exposes_shared_client_protocol() -> None:
    """The preset's public client annotation matches the shared low-level Redis contract."""
    preset_hints = get_type_hints(RedisAuthPreset, include_extras=True)

    assert preset_hints["redis"] is RedisSharedAuthClient
    assert isinstance(PresetRedisClient(), RedisSharedAuthClient)


def test_contrib_redis_preset_snapshots_group_rate_limit_tiers_as_read_only_mapping() -> None:
    """The preset stores group tiers as a read-only snapshot detached from caller-owned mappings."""
    source_tiers: dict[AuthRateLimitEndpointGroup, RedisAuthRateLimitTier] = {
        "refresh": RedisAuthRateLimitTier(
            max_attempts=REFRESH_MAX_ATTEMPTS,
            window_seconds=REFRESH_WINDOW_SECONDS,
        ),
    }

    preset = RedisAuthPreset(
        redis=PresetRedisClient(),
        group_rate_limit_tiers=source_tiers,
    )
    source_tiers["totp"] = RedisAuthRateLimitTier(
        max_attempts=TOTP_MAX_ATTEMPTS,
        window_seconds=TOTP_WINDOW_SECONDS,
    )

    assert isinstance(preset.group_rate_limit_tiers, MappingProxyType)
    assert tuple(preset.group_rate_limit_tiers) == ("refresh",)
    with pytest.raises(TypeError, match="mappingproxy"):
        cast("Any", preset.group_rate_limit_tiers)["totp"] = RedisAuthRateLimitTier(
            max_attempts=TOTP_MAX_ATTEMPTS,
            window_seconds=TOTP_WINDOW_SECONDS,
        )


async def test_contrib_redis_preset_builds_shared_client_auth_components(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib preset derives both auth rate limiting and TOTP replay protection."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.totp._load_redis_asyncio", load_optional_redis)
    redis_client: RedisSharedAuthClient = PresetRedisClient()
    assert isinstance(redis_client, RedisSharedAuthClient)
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
        totp_used_tokens_key_prefix="used:",
    )

    config = preset.build_rate_limit_config(
        disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
        namespace_style="snake_case",
        identity_fields=("username", "email"),
        trusted_headers=("X-Real-IP",),
    )
    store = preset.build_totp_used_tokens_store()

    assert config.login is not None
    assert isinstance(config.login.backend, RedisRateLimiter)
    assert config.login.backend.redis is redis_client
    assert config.login.backend.max_attempts == SHARED_MAX_ATTEMPTS
    assert config.login.backend.window_seconds == SHARED_WINDOW_SECONDS
    assert config.login.backend.key_prefix == ratelimit_module.DEFAULT_KEY_PREFIX
    assert config.login.identity_fields == ("username", "email")
    assert config.login.trusted_headers == ("X-Real-IP",)
    assert config.refresh is not None
    assert isinstance(config.refresh.backend, RedisRateLimiter)
    assert config.refresh.backend.redis is redis_client
    assert config.refresh.backend.max_attempts == REFRESH_MAX_ATTEMPTS
    assert config.refresh.backend.window_seconds == REFRESH_WINDOW_SECONDS
    assert config.refresh.backend.key_prefix == "refresh:"
    assert config.refresh.identity_fields == ("username", "email")
    assert config.refresh.trusted_headers == ("X-Real-IP",)
    assert config.totp_verify is not None
    assert isinstance(config.totp_verify.backend, RedisRateLimiter)
    assert config.totp_verify.backend.redis is redis_client
    assert config.totp_verify.backend.max_attempts == TOTP_MAX_ATTEMPTS
    assert config.totp_verify.backend.window_seconds == TOTP_WINDOW_SECONDS
    assert config.totp_verify.backend.key_prefix == "totp:"
    assert AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP["verification"] == AUTH_RATE_LIMIT_VERIFICATION_SLOTS
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert store._redis is redis_client
    assert await store.mark_used("user-1", 7, 1.25) is True
    assert redis_client.set_calls == [("used:user-1:7", "1", True, 1250)]


def test_contrib_redis_preset_covers_optional_identity_and_proxy_header_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The preset forwards either optional builder input independently."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", load_optional_redis)
    preset = RedisAuthPreset(redis=PresetRedisClient())

    config_with_headers = preset.build_rate_limit_config(trusted_headers=("X-Real-IP",))
    config_with_identity_fields = preset.build_rate_limit_config(identity_fields=("email",))

    assert config_with_headers.login is not None
    assert config_with_headers.login.identity_fields == ("identifier", "username", "email")
    assert config_with_headers.login.trusted_headers == ("X-Real-IP",)
    assert config_with_identity_fields.login is not None
    assert config_with_identity_fields.login.identity_fields == ("email",)
    assert config_with_identity_fields.login.trusted_headers == ("X-Forwarded-For",)


def test_contrib_redis_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib Redis alias preserves the strategy's optional dependency guard."""

    def fail_import(name: str) -> None:
        raise ImportError(name)

    monkeypatch.setattr("litestar_auth.authentication.strategy.redis.importlib.import_module", fail_import)

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisTokenStrategy"):
        RedisTokenStrategy(redis=AsyncMock(), token_hash_secret=REDIS_TOKEN_HASH_SECRET)


def test_contrib_redis_preset_preserves_rate_limit_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib preset defers Redis rate-limit imports until config construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisRateLimiter"
        raise ImportError(msg)

    monkeypatch.setattr(ratelimit_module, "_load_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=PresetRedisClient())

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisRateLimiter"):
        preset.build_rate_limit_config()


def test_contrib_redis_preset_preserves_totp_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib preset defers TOTP Redis imports until replay-store construction."""

    def fail_load_redis() -> object:
        msg = "Install litestar-auth[redis] to use RedisUsedTotpCodeStore"
        raise ImportError(msg)

    monkeypatch.setattr("litestar_auth.totp._load_redis_asyncio", fail_load_redis)
    preset = RedisAuthPreset(redis=PresetRedisClient())

    with pytest.raises(ImportError, match="Install litestar-auth\\[redis\\] to use RedisUsedTotpCodeStore"):
        preset.build_totp_used_tokens_store()


def test_contrib_oauth_preserves_lazy_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """The contrib OAuth alias preserves the router's optional dependency guard."""

    def fail_import(module_name: str) -> None:
        message = f"No module named {module_name!r}"
        raise ModuleNotFoundError(
            message,
            name="httpx_oauth.clients.github",
        )

    monkeypatch.setattr("litestar_auth.oauth.router.import_module", fail_import)
    backend = AuthenticationBackend[ExampleUser, str](
        name="oauth",
        transport=BearerTransport(),
        strategy=ExampleStrategy(),
    )
    user_manager = ExampleUserManager()

    with pytest.raises(ImportError, match=r"Install litestar-auth\[oauth\] to use OAuth controllers\."):
        create_provider_oauth_controller(
            provider_name="github",
            backend=backend,
            user_manager=user_manager,
            oauth_client_class="httpx_oauth.clients.github.GitHubOAuth2",
            redirect_base_url="http://testserver.local/auth/oauth",
        )
