"""Internal Redis contrib surface.

This module centralizes the documented Redis-backed auth helpers plus the
shared-client preset wiring so the public ``litestar_auth.contrib.redis``
package can stay small and stable while Redis-specific convenience helpers grow
behind the same boundary.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol, runtime_checkable

import litestar_auth._redis_protocols as redis_protocols_module
import litestar_auth.ratelimit as ratelimit_module
from litestar_auth.authentication.strategy.jwt import RedisJWTDenylistStore
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitNamespaceStyle,
    EndpointRateLimit,
    RateLimiterBackend,
    RateLimitScope,
)
from litestar_auth.totp import DEFAULT_TOTP_USED_KEY_PREFIX, RedisUsedTotpCodeStore


@dataclass(slots=True, frozen=True)
class RedisAuthRateLimitTier:
    """Rate-limit settings used by :class:`RedisAuthPreset`.

    Args:
        max_attempts: Maximum attempts allowed inside the window.
        window_seconds: Sliding-window duration in seconds.
        key_prefix: Optional Redis key prefix passed to ``RedisRateLimiter``.
            ``None`` preserves the current ``RedisRateLimiter`` default.
    """

    max_attempts: int
    window_seconds: float
    key_prefix: str | None = None


def _default_rate_limit_tier() -> RedisAuthRateLimitTier:
    """Return the preset's default shared rate-limit tier."""
    return RedisAuthRateLimitTier(max_attempts=5, window_seconds=60)


def _empty_group_rate_limit_tiers() -> MappingProxyType[AuthRateLimitEndpointGroup, RedisAuthRateLimitTier]:
    """Return an empty read-only group-tier mapping for the preset default."""
    return MappingProxyType({})


@runtime_checkable
class RedisAuthClientProtocol(redis_protocols_module.RedisSharedAuthClient, Protocol):
    """Public async Redis client contract shared by Redis auth contrib helpers."""


@dataclass(slots=True)
class RedisAuthPreset:
    """Shared-client Redis preset for auth rate limiting and TOTP replay protection.

    Keep the low-level ``RedisRateLimiter``, ``RedisUsedTotpCodeStore``,
    ``RedisJWTDenylistStore``, and ``AuthRateLimitConfig.from_shared_backend()``
    APIs for advanced cases that need fully custom backends. This preset is the
    higher-level path when one async Redis client should back the auth
    rate-limit config plus the TOTP replay and pending-token replay stores.

    Args:
        redis: Async Redis client compatible with ``redis.asyncio.Redis`` and
            satisfying :class:`RedisAuthClientProtocol`:
            ``eval(...)``, ``delete(...)``,
            ``set(name, value, nx=True, px=ttl_ms)``, ``get(...)``, and
            ``setex(...)``.
        rate_limit_tier: Default rate-limit settings used for every supported
            auth slot unless a group-specific override is configured.
        group_rate_limit_tiers: Optional per-group rate-limit settings keyed by
            ``AuthRateLimitEndpointGroup`` names such as ``"refresh"`` or
            ``"totp"``.
        totp_used_tokens_key_prefix: Optional default Redis key prefix for the
            TOTP replay store. ``None`` preserves the current
            ``RedisUsedTotpCodeStore`` default.
        totp_pending_jti_key_prefix: Optional default Redis key prefix for the
            pending-login-token JTI denylist store. ``None`` preserves the
            current ``RedisJWTDenylistStore`` default.
    """

    redis: RedisAuthClientProtocol
    rate_limit_tier: RedisAuthRateLimitTier = field(default_factory=_default_rate_limit_tier)
    group_rate_limit_tiers: typing.Mapping[AuthRateLimitEndpointGroup, RedisAuthRateLimitTier] = field(
        default_factory=_empty_group_rate_limit_tiers,
    )
    totp_used_tokens_key_prefix: str | None = None
    totp_pending_jti_key_prefix: str | None = None

    def __post_init__(self) -> None:
        """Snapshot group-specific rate-limit tiers into a read-only mapping."""
        self.group_rate_limit_tiers = MappingProxyType(dict(self.group_rate_limit_tiers))

    def _build_rate_limit_backend(self, tier: RedisAuthRateLimitTier) -> RateLimiterBackend:
        """Return a ``RedisRateLimiter`` for ``tier`` using the preset's client."""
        key_prefix = ratelimit_module.DEFAULT_KEY_PREFIX if tier.key_prefix is None else tier.key_prefix
        return ratelimit_module.RedisRateLimiter(
            redis=self.redis,
            max_attempts=tier.max_attempts,
            window_seconds=tier.window_seconds,
            key_prefix=key_prefix,
        )

    def build_rate_limit_config(  # noqa: PLR0913
        self,
        *,
        enabled: typing.Iterable[AuthRateLimitEndpointSlot] | None = None,
        disabled: typing.Iterable[AuthRateLimitEndpointSlot] = (),
        group_backends: typing.Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend] | None = None,
        scope_overrides: typing.Mapping[AuthRateLimitEndpointSlot, RateLimitScope] | None = None,
        namespace_style: AuthRateLimitNamespaceStyle = "route",
        namespace_overrides: typing.Mapping[AuthRateLimitEndpointSlot, str] | None = None,
        endpoint_overrides: typing.Mapping[AuthRateLimitEndpointSlot, EndpointRateLimit | None] | None = None,
        trusted_proxy: bool = False,
        identity_fields: tuple[str, ...] | None = None,
        trusted_headers: tuple[str, ...] | None = None,
    ) -> AuthRateLimitConfig:
        """Build ``AuthRateLimitConfig`` from the preset's shared Redis client.

        Args:
            enabled: Optional auth slot names to build.
            disabled: Auth slot names to leave unset.
            group_backends: Optional explicit backend overrides keyed by auth
                slot group. These win over ``group_rate_limit_tiers``.
            scope_overrides: Optional per-slot scope overrides.
            namespace_style: Namespace family for generated limiters.
            namespace_overrides: Optional per-slot namespace overrides.
            endpoint_overrides: Optional full per-slot replacements or explicit
                ``None`` disablement.
            trusted_proxy: Shared trusted-proxy setting applied to generated
                limiters.
            identity_fields: Optional shared request body identity fields. When
                omitted, ``AuthRateLimitConfig.from_shared_backend()`` keeps its
                current default.
            trusted_headers: Optional shared trusted proxy header names. When
                omitted, ``AuthRateLimitConfig.from_shared_backend()`` keeps its
                current default.

        Returns:
            The auth rate-limit config built from the preset's shared client and
            tier settings.
        """
        derived_group_backends: dict[AuthRateLimitEndpointGroup, RateLimiterBackend] = {
            group: self._build_rate_limit_backend(tier) for group, tier in self.group_rate_limit_tiers.items()
        }
        if group_backends is not None:
            derived_group_backends.update(group_backends)
        shared_backend: RateLimiterBackend = self._build_rate_limit_backend(self.rate_limit_tier)
        resolved_group_backends = derived_group_backends or None

        if identity_fields is None:
            if trusted_headers is None:
                return AuthRateLimitConfig.from_shared_backend(
                    shared_backend,
                    enabled=enabled,
                    disabled=disabled,
                    group_backends=resolved_group_backends,
                    scope_overrides=scope_overrides,
                    namespace_style=namespace_style,
                    namespace_overrides=namespace_overrides,
                    endpoint_overrides=endpoint_overrides,
                    trusted_proxy=trusted_proxy,
                )
            return AuthRateLimitConfig.from_shared_backend(
                shared_backend,
                enabled=enabled,
                disabled=disabled,
                group_backends=resolved_group_backends,
                scope_overrides=scope_overrides,
                namespace_style=namespace_style,
                namespace_overrides=namespace_overrides,
                endpoint_overrides=endpoint_overrides,
                trusted_proxy=trusted_proxy,
                trusted_headers=trusted_headers,
            )

        if trusted_headers is None:
            return AuthRateLimitConfig.from_shared_backend(
                shared_backend,
                enabled=enabled,
                disabled=disabled,
                group_backends=resolved_group_backends,
                scope_overrides=scope_overrides,
                namespace_style=namespace_style,
                namespace_overrides=namespace_overrides,
                endpoint_overrides=endpoint_overrides,
                trusted_proxy=trusted_proxy,
                identity_fields=identity_fields,
            )

        return AuthRateLimitConfig.from_shared_backend(
            shared_backend,
            enabled=enabled,
            disabled=disabled,
            group_backends=resolved_group_backends,
            scope_overrides=scope_overrides,
            namespace_style=namespace_style,
            namespace_overrides=namespace_overrides,
            endpoint_overrides=endpoint_overrides,
            trusted_proxy=trusted_proxy,
            identity_fields=identity_fields,
            trusted_headers=trusted_headers,
        )

    def build_totp_used_tokens_store(self, *, key_prefix: str | None = None) -> RedisUsedTotpCodeStore:
        """Build ``RedisUsedTotpCodeStore`` from the preset's shared Redis client.

        Args:
            key_prefix: Optional per-call Redis key prefix override. When
                omitted, the preset uses ``totp_used_tokens_key_prefix`` and
                finally falls back to the current ``RedisUsedTotpCodeStore``
                default.

        Returns:
            Redis-backed TOTP replay store sharing the preset's client.
        """
        resolved_key_prefix = self.totp_used_tokens_key_prefix if key_prefix is None else key_prefix
        if resolved_key_prefix is None:
            resolved_key_prefix = DEFAULT_TOTP_USED_KEY_PREFIX
        return RedisUsedTotpCodeStore(redis=self.redis, key_prefix=resolved_key_prefix)

    def build_totp_pending_jti_store(self, *, key_prefix: str | None = None) -> RedisJWTDenylistStore:
        """Build ``RedisJWTDenylistStore`` from the preset's shared Redis client.

        Args:
            key_prefix: Optional per-call Redis key prefix override. When
                omitted, the preset uses ``totp_pending_jti_key_prefix`` and
                finally falls back to the current ``RedisJWTDenylistStore``
                default.

        Returns:
            Redis-backed pending-token JTI denylist sharing the preset's
            client.
        """
        resolved_key_prefix = self.totp_pending_jti_key_prefix if key_prefix is None else key_prefix
        if resolved_key_prefix is None:
            return RedisJWTDenylistStore(redis=self.redis)
        return RedisJWTDenylistStore(redis=self.redis, key_prefix=resolved_key_prefix)


__all__ = (
    "RedisAuthClientProtocol",
    "RedisAuthPreset",
    "RedisAuthRateLimitTier",
    "RedisTokenStrategy",
    "RedisUsedTotpCodeStore",
)
