"""Configuration types and private endpoint metadata for auth rate limiting."""

from __future__ import annotations

from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from litestar.exceptions import TooManyRequestsException

from ._helpers import _DEFAULT_TRUSTED_HEADERS, _client_host, _extract_email, _safe_key_part, logger

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from litestar.connection import Request

    from ._protocol import RateLimiterBackend

type RateLimitScope = Literal["ip", "ip_email"]
type _AuthRateLimitEndpointSlot = Literal[
    "login",
    "refresh",
    "register",
    "forgot_password",
    "reset_password",
    "totp_enable",
    "totp_confirm_enable",
    "totp_verify",
    "totp_disable",
    "verify_token",
    "request_verify_token",
]
type _AuthRateLimitEndpointGroup = Literal["login", "password_reset", "refresh", "register", "totp", "verification"]

_DEFAULT_IDENTITY_FIELDS = ("identifier", "username", "email")
_MISSING_OVERRIDE = object()


@dataclass(slots=True, frozen=True)
class _AuthRateLimitEndpointRecipe:
    """Package-owned metadata for a supported auth rate-limit slot."""

    slot: _AuthRateLimitEndpointSlot
    default_scope: RateLimitScope
    default_namespace: str
    group: _AuthRateLimitEndpointGroup


_AUTH_RATE_LIMIT_ENDPOINT_RECIPES: tuple[_AuthRateLimitEndpointRecipe, ...] = (
    _AuthRateLimitEndpointRecipe(slot="login", default_scope="ip_email", default_namespace="login", group="login"),
    _AuthRateLimitEndpointRecipe(slot="refresh", default_scope="ip", default_namespace="refresh", group="refresh"),
    _AuthRateLimitEndpointRecipe(slot="register", default_scope="ip", default_namespace="register", group="register"),
    _AuthRateLimitEndpointRecipe(
        slot="forgot_password",
        default_scope="ip_email",
        default_namespace="forgot-password",
        group="password_reset",
    ),
    _AuthRateLimitEndpointRecipe(
        slot="reset_password",
        default_scope="ip",
        default_namespace="reset-password",
        group="password_reset",
    ),
    _AuthRateLimitEndpointRecipe(slot="totp_enable", default_scope="ip", default_namespace="totp-enable", group="totp"),
    _AuthRateLimitEndpointRecipe(
        slot="totp_confirm_enable",
        default_scope="ip",
        default_namespace="totp-confirm-enable",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(slot="totp_verify", default_scope="ip", default_namespace="totp-verify", group="totp"),
    _AuthRateLimitEndpointRecipe(
        slot="totp_disable",
        default_scope="ip",
        default_namespace="totp-disable",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot="verify_token",
        default_scope="ip",
        default_namespace="verify-token",
        group="verification",
    ),
    _AuthRateLimitEndpointRecipe(
        slot="request_verify_token",
        default_scope="ip_email",
        default_namespace="request-verify-token",
        group="verification",
    ),
)


def _build_auth_rate_limit_recipe_index() -> MappingProxyType[str, _AuthRateLimitEndpointRecipe]:
    """Build a read-only lookup table for the private auth endpoint recipes.

    Returns:
        Immutable mapping keyed by ``AuthRateLimitConfig`` slot name.

    Raises:
        RuntimeError: If the private catalog accidentally defines duplicate slots.
    """
    recipe_index = {recipe.slot: recipe for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES}
    if len(recipe_index) == len(_AUTH_RATE_LIMIT_ENDPOINT_RECIPES):
        return MappingProxyType(recipe_index)

    msg = "Auth rate-limit endpoint recipes must not contain duplicate slots."
    raise RuntimeError(msg)


_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT = _build_auth_rate_limit_recipe_index()
_AUTH_RATE_LIMIT_ENDPOINT_SLOTS = tuple(_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT)
_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET = frozenset(_AUTH_RATE_LIMIT_ENDPOINT_SLOTS)
_AUTH_RATE_LIMIT_ENDPOINT_GROUPS = frozenset(recipe.group for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES)


def _validate_builder_names(
    names: Iterable[str],
    *,
    allowed: frozenset[str],
    parameter_name: str,
    item_name: str,
) -> None:
    """Reject unsupported builder slot or group names.

    Raises:
        ValueError: If ``names`` includes an unsupported slot or group identifier.
    """
    unknown_names = sorted(set(names) - allowed)
    if not unknown_names:
        return

    msg = f"{parameter_name} contains unsupported {item_name}: {', '.join(unknown_names)}"
    raise ValueError(msg)


@dataclass(slots=True, frozen=True)
class EndpointRateLimit:
    """Per-endpoint rate-limit settings and request hook."""

    backend: RateLimiterBackend
    scope: RateLimitScope
    namespace: str
    trusted_proxy: bool = False
    identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS

    async def before_request(self, request: Request[Any, Any, Any]) -> None:
        """Reject the request with 429 when its key is over the configured limit.

        Security:
            Only set ``trusted_proxy=True`` when this service is behind a trusted
            proxy or load balancer that overwrites client IP headers. Otherwise,
            attackers can spoof headers like ``X-Forwarded-For`` and evade or
            poison rate-limiting keys.

        Raises:
            TooManyRequestsException: If the request exceeded the configured limit.
        """
        key = await self.build_key(request)
        if await self.backend.check(key):
            return

        retry_after = await self.backend.retry_after(key)
        logger.warning(
            "Rate limit exceeded",
            extra={
                "event": "rate_limit_triggered",
                "namespace": self.namespace,
                "scope": self.scope,
                "trusted_proxy": self.trusted_proxy,
            },
        )
        msg = "Too many requests."
        raise TooManyRequestsException(
            detail=msg,
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    async def increment(self, request: Request[Any, Any, Any]) -> None:
        """Record a failed or rate-limited attempt for the current request."""
        await self.backend.increment(await self.build_key(request))

    async def reset(self, request: Request[Any, Any, Any]) -> None:
        """Clear stored attempts for the current request key."""
        await self.backend.reset(await self.build_key(request))

    async def build_key(self, request: Request[Any, Any, Any]) -> str:
        """Build the backend key for the given request.

        Returns:
            Namespaced rate-limit key for the request.
        """
        host = _client_host(request, trusted_proxy=self.trusted_proxy, trusted_headers=self.trusted_headers)
        parts = [self.namespace, _safe_key_part(host)]
        if self.scope == "ip_email":
            email = await _extract_email(request, identity_fields=self.identity_fields)
            if email:
                parts.append(_safe_key_part(email.strip().casefold()))

        return ":".join(parts)


@dataclass(slots=True, frozen=True)
class AuthRateLimitConfig:
    """Optional rate-limit rules for auth-related endpoints."""

    login: EndpointRateLimit | None = None
    refresh: EndpointRateLimit | None = None
    register: EndpointRateLimit | None = None
    forgot_password: EndpointRateLimit | None = None
    reset_password: EndpointRateLimit | None = None
    totp_enable: EndpointRateLimit | None = None
    totp_confirm_enable: EndpointRateLimit | None = None
    totp_verify: EndpointRateLimit | None = None
    totp_disable: EndpointRateLimit | None = None
    verify_token: EndpointRateLimit | None = None
    request_verify_token: EndpointRateLimit | None = None

    @classmethod
    def from_shared_backend(  # noqa: PLR0913
        cls,
        backend: RateLimiterBackend,
        *,
        enabled: Iterable[str] | None = None,
        disabled: Iterable[str] = (),
        group_backends: Mapping[str, RateLimiterBackend] | None = None,
        scope_overrides: Mapping[str, RateLimitScope] | None = None,
        namespace_overrides: Mapping[str, str] | None = None,
        endpoint_overrides: Mapping[str, EndpointRateLimit | None] | None = None,
        trusted_proxy: bool = False,
        identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS,
        trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
    ) -> Self:
        """Build endpoint-specific limiters from the package-owned shared-backend recipe.

        The builder uses the private endpoint catalog for default scopes and namespace
        tokens, then applies override precedence in this order:

        1. ``backend`` for every enabled slot
        2. ``group_backends`` for slot groups such as ``totp`` or ``verification``
        3. ``scope_overrides`` / ``namespace_overrides`` for slot-specific tweaks
        4. ``endpoint_overrides`` for full slot replacement or explicit ``None`` disablement

        Args:
            backend: Default limiter backend for enabled auth slots.
            enabled: Optional auth slot names to build. Defaults to all supported slots.
            disabled: Auth slot names to leave unset, even when they would otherwise be enabled.
            group_backends: Optional backend overrides keyed by auth slot group:
                ``login``, ``refresh``, ``register``, ``password_reset``, ``totp``, or
                ``verification``.
            scope_overrides: Optional per-slot scope overrides to preserve existing key behavior.
            namespace_overrides: Optional per-slot namespace tokens to preserve existing key names.
            endpoint_overrides: Optional full per-slot replacements. ``None`` disables a slot.
            trusted_proxy: Shared trusted-proxy setting applied to generated limiters.
            identity_fields: Shared request body identity fields applied to generated limiters.
            trusted_headers: Shared trusted proxy header names applied to generated limiters.

        Returns:
            New config populated from the shared-backend builder inputs.
        """
        group_backend_map = dict(group_backends or {})
        scope_override_map = dict(scope_overrides or {})
        namespace_override_map = dict(namespace_overrides or {})
        endpoint_override_map = dict(endpoint_overrides or {})
        enabled_slots = _AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET if enabled is None else frozenset(enabled)
        disabled_slots = frozenset(disabled)

        _validate_builder_names(
            enabled_slots,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET,
            parameter_name="enabled",
            item_name="auth rate-limit slots",
        )
        _validate_builder_names(
            disabled_slots,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET,
            parameter_name="disabled",
            item_name="auth rate-limit slots",
        )
        _validate_builder_names(
            group_backend_map,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_GROUPS,
            parameter_name="group_backends",
            item_name="auth rate-limit groups",
        )
        _validate_builder_names(
            scope_override_map,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET,
            parameter_name="scope_overrides",
            item_name="auth rate-limit slots",
        )
        _validate_builder_names(
            namespace_override_map,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET,
            parameter_name="namespace_overrides",
            item_name="auth rate-limit slots",
        )
        _validate_builder_names(
            endpoint_override_map,
            allowed=_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET,
            parameter_name="endpoint_overrides",
            item_name="auth rate-limit slots",
        )

        config_kwargs: dict[str, EndpointRateLimit | None] = {}

        for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES:
            slot_override = endpoint_override_map.get(recipe.slot, _MISSING_OVERRIDE)
            if slot_override is not _MISSING_OVERRIDE:
                config_kwargs[recipe.slot] = cast("EndpointRateLimit | None", slot_override)
                continue

            if recipe.slot not in enabled_slots or recipe.slot in disabled_slots:
                continue

            config_kwargs[recipe.slot] = EndpointRateLimit(
                backend=group_backend_map.get(recipe.group, backend),
                scope=scope_override_map.get(recipe.slot, recipe.default_scope),
                namespace=namespace_override_map.get(recipe.slot, recipe.default_namespace),
                trusted_proxy=trusted_proxy,
                identity_fields=identity_fields,
                trusted_headers=trusted_headers,
            )

        return cls(**cast("Any", config_kwargs))


if tuple(field.name for field in fields(AuthRateLimitConfig)) != _AUTH_RATE_LIMIT_ENDPOINT_SLOTS:
    msg = "AuthRateLimitConfig fields must stay aligned with the private auth rate-limit endpoint catalog."
    raise RuntimeError(msg)
