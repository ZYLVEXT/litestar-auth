"""Focused Redis contrib tests for the canonical auth rate-limit preset surface."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, cast

import pytest

import litestar_auth.ratelimit as ratelimit_module
from litestar_auth.contrib.redis import (
    RedisAuthClientProtocol,
    RedisAuthPreset,
    RedisAuthRateLimitConfigOptions,
    RedisAuthRateLimitTier,
)
from litestar_auth.ratelimit import (
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
)
from tests._helpers import cast_fakeredis

if TYPE_CHECKING:
    from tests._helpers import AsyncFakeRedis

pytestmark = pytest.mark.unit


def test_redis_auth_preset_build_rate_limit_config_signature_tracks_canonical_builder_surface() -> None:
    """The Redis preset exposes only the supported shared-builder keyword surface."""
    parameter_names = tuple(inspect.signature(RedisAuthPreset.build_rate_limit_config).parameters)

    assert parameter_names == (
        "self",
        "options",
    )


def test_redis_auth_preset_build_rate_limit_config_uses_endpoint_overrides(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The Redis preset mirrors the canonical shared-backend builder inputs."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._helpers._load_redis_asyncio", load_optional_redis)
    redis_client = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    refresh_backend = InMemoryRateLimiter(max_attempts=9, window_seconds=90)
    forgot_password_override = EndpointRateLimit(
        backend=InMemoryRateLimiter(max_attempts=4, window_seconds=45),
        scope="ip",
        namespace="forgot_password",
    )
    endpoint_overrides: dict[AuthRateLimitSlot, EndpointRateLimit | None] = {
        AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
        AuthRateLimitSlot.REQUEST_VERIFY_TOKEN: None,
    }
    preset = RedisAuthPreset(
        redis=redis_client,
        rate_limit_tier=RedisAuthRateLimitTier(max_attempts=5, window_seconds=60),
        group_rate_limit_tiers={
            "refresh": RedisAuthRateLimitTier(max_attempts=10, window_seconds=300, key_prefix="refresh:"),
        },
    )

    config = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(
            group_backends={"refresh": refresh_backend},
            endpoint_overrides=endpoint_overrides,
            trusted_proxy=True,
            identity_fields=("email",),
            trusted_headers=("X-Real-IP",),
        ),
    )

    assert config.login is not None
    assert config.login.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert config.login.backend.redis is redis_client
    assert config.login.trusted_proxy is True
    assert config.login.identity_fields == ("email",)
    assert config.login.trusted_headers == ("X-Real-IP",)
    assert config.refresh is not None
    assert config.refresh.backend is refresh_backend
    assert config.forgot_password is forgot_password_override
    assert config.request_verify_token is None


@pytest.mark.parametrize(
    ("legacy_kwargs", "legacy_parameter"),
    [
        ({"namespace_style": "snake_case"}, "namespace_style"),
        ({"scope_overrides": {AuthRateLimitSlot.FORGOT_PASSWORD: "ip"}}, "scope_overrides"),
        (
            {"namespace_overrides": {AuthRateLimitSlot.FORGOT_PASSWORD: "forgot_password"}},
            "namespace_overrides",
        ),
    ],
)
def test_redis_auth_preset_build_rate_limit_config_rejects_removed_legacy_keywords(
    async_fakeredis: AsyncFakeRedis,
    legacy_kwargs: dict[str, object],
    legacy_parameter: str,
) -> None:
    """The Redis preset no longer accepts removed compatibility keyword arguments."""
    preset = RedisAuthPreset(redis=cast_fakeredis(async_fakeredis, RedisAuthClientProtocol))

    with pytest.raises(TypeError, match=rf"unexpected keyword argument '{legacy_parameter}'"):
        preset.build_rate_limit_config(**cast("Any", legacy_kwargs))
