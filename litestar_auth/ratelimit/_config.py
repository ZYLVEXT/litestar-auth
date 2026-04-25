"""Configuration types and private endpoint metadata for auth rate limiting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping  # noqa: TC003
from dataclasses import dataclass, fields
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Self, cast

from litestar.connection import Request  # noqa: TC002
from litestar.exceptions import TooManyRequestsException

from ._helpers import _DEFAULT_TRUSTED_HEADERS, _client_host, _extract_email, _safe_key_part, logger
from ._memory import InMemoryRateLimiter
from ._protocol import RateLimiterBackend  # noqa: TC001
from ._redis import RedisRateLimiter

type RateLimitScope = Literal["ip", "ip_email"]
type AuthRateLimitEndpointGroup = Literal["login", "password_reset", "refresh", "register", "totp", "verification"]

_DEFAULT_IDENTITY_FIELDS = ("identifier", "username", "email")
_AUTH_RATE_LIMIT_NAMESPACE_STYLES = frozenset({"route", "snake_case"})
_MISSING_OVERRIDE = object()


class AuthRateLimitSlot(StrEnum):
    """IDE-friendly enum of supported auth rate-limit endpoint slots."""

    LOGIN = "login"
    # Dedicated credential-rotation slot so operators can tune stolen-session re-verification separately from login.
    CHANGE_PASSWORD = "change_password"  # noqa: S105
    REFRESH = "refresh"
    REGISTER = "register"
    FORGOT_PASSWORD = "forgot_password"  # noqa: S105
    RESET_PASSWORD = "reset_password"  # noqa: S105
    TOTP_ENABLE = "totp_enable"
    TOTP_CONFIRM_ENABLE = "totp_confirm_enable"
    TOTP_VERIFY = "totp_verify"
    TOTP_DISABLE = "totp_disable"
    TOTP_REGENERATE_RECOVERY_CODES = "totp_regenerate_recovery_codes"
    VERIFY_TOKEN = "verify_token"  # noqa: S105
    REQUEST_VERIFY_TOKEN = "request_verify_token"  # noqa: S105


@dataclass(slots=True, frozen=True)
class _AuthRateLimitEndpointRecipe:
    """Package-owned metadata for a supported auth rate-limit slot."""

    slot: AuthRateLimitSlot
    default_scope: RateLimitScope
    default_namespace: str
    group: AuthRateLimitEndpointGroup


_AUTH_RATE_LIMIT_ENDPOINT_RECIPES: tuple[_AuthRateLimitEndpointRecipe, ...] = (
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.LOGIN,
        default_scope="ip_email",
        default_namespace="login",
        group="login",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.CHANGE_PASSWORD,
        default_scope="ip_email",
        default_namespace="change-password",
        group="login",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.REFRESH,
        default_scope="ip",
        default_namespace="refresh",
        group="refresh",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.REGISTER,
        default_scope="ip",
        default_namespace="register",
        group="register",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.FORGOT_PASSWORD,
        default_scope="ip_email",
        default_namespace="forgot-password",
        group="password_reset",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.RESET_PASSWORD,
        default_scope="ip",
        default_namespace="reset-password",
        group="password_reset",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.TOTP_ENABLE,
        default_scope="ip",
        default_namespace="totp-enable",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.TOTP_CONFIRM_ENABLE,
        default_scope="ip",
        default_namespace="totp-confirm-enable",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.TOTP_VERIFY,
        default_scope="ip",
        default_namespace="totp-verify",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.TOTP_DISABLE,
        default_scope="ip",
        default_namespace="totp-disable",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES,
        default_scope="ip",
        default_namespace="totp-regenerate-recovery-codes",
        group="totp",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.VERIFY_TOKEN,
        default_scope="ip",
        default_namespace="verify-token",
        group="verification",
    ),
    _AuthRateLimitEndpointRecipe(
        slot=AuthRateLimitSlot.REQUEST_VERIFY_TOKEN,
        default_scope="ip_email",
        default_namespace="request-verify-token",
        group="verification",
    ),
)


def _build_auth_rate_limit_recipe_index() -> MappingProxyType[AuthRateLimitSlot, _AuthRateLimitEndpointRecipe]:
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


@dataclass(slots=True, frozen=True)
class _AuthRateLimitEndpointCatalog:
    """Read-only query surface for the private auth endpoint recipe catalog."""

    recipes: tuple[_AuthRateLimitEndpointRecipe, ...]
    recipes_by_slot: MappingProxyType[AuthRateLimitSlot, _AuthRateLimitEndpointRecipe]
    slots: tuple[AuthRateLimitSlot, ...]
    slot_set: frozenset[AuthRateLimitSlot]
    slots_by_group: MappingProxyType[AuthRateLimitEndpointGroup, frozenset[AuthRateLimitSlot]]
    groups: frozenset[AuthRateLimitEndpointGroup]

    def resolve_enabled_slots(
        self,
        enabled: Iterable[AuthRateLimitSlot] | None,
    ) -> frozenset[AuthRateLimitSlot]:
        """Return the enabled slot set, defaulting to the full supported catalog."""
        return self.slot_set if enabled is None else frozenset(enabled)

    def iter_enabled_recipes(
        self,
        *,
        enabled_slots: frozenset[AuthRateLimitSlot],
        disabled_slots: frozenset[AuthRateLimitSlot],
    ) -> Iterable[_AuthRateLimitEndpointRecipe]:
        """Yield catalog entries that remain enabled after disablement is applied."""
        for recipe in self.recipes:
            if recipe.slot in enabled_slots and recipe.slot not in disabled_slots:
                yield recipe

    def validate_slot_names(self, names: Iterable[AuthRateLimitSlot], *, parameter_name: str) -> None:
        """Validate slot-keyed builder inputs against the private catalog."""
        _validate_builder_names(
            names,
            allowed=self.slot_set,
            parameter_name=parameter_name,
            item_name="auth rate-limit slots",
        )

    def validate_group_names(self, names: Iterable[str], *, parameter_name: str) -> None:
        """Validate group-keyed builder inputs against the private catalog."""
        _validate_builder_names(
            names,
            allowed=self.groups,
            parameter_name=parameter_name,
            item_name="auth rate-limit groups",
        )


def _build_auth_rate_limit_endpoint_catalog() -> _AuthRateLimitEndpointCatalog:
    """Build the private auth rate-limit catalog query surface.

    Returns:
        Read-only catalog metadata keyed by the supported auth endpoint slots.
    """
    recipes_by_slot = _build_auth_rate_limit_recipe_index()
    slots = tuple(recipes_by_slot)
    slots_by_group: dict[AuthRateLimitEndpointGroup, set[AuthRateLimitSlot]] = {}
    for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES:
        slots_by_group.setdefault(recipe.group, set()).add(recipe.slot)

    return _AuthRateLimitEndpointCatalog(
        recipes=_AUTH_RATE_LIMIT_ENDPOINT_RECIPES,
        recipes_by_slot=recipes_by_slot,
        slots=slots,
        slot_set=frozenset(slots),
        slots_by_group=MappingProxyType(
            {group: frozenset(group_slots) for group, group_slots in slots_by_group.items()},
        ),
        groups=frozenset(recipe.group for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES),
    )


_AUTH_RATE_LIMIT_ENDPOINT_CATALOG = _build_auth_rate_limit_endpoint_catalog()
_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT: MappingProxyType[AuthRateLimitSlot, _AuthRateLimitEndpointRecipe] = (
    _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.recipes_by_slot
)
_AUTH_RATE_LIMIT_ENDPOINT_SLOTS: tuple[AuthRateLimitSlot, ...] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slots
_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET: frozenset[AuthRateLimitSlot] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slot_set
_AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP: MappingProxyType[
    AuthRateLimitEndpointGroup,
    frozenset[AuthRateLimitSlot],
] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slots_by_group
_AUTH_RATE_LIMIT_ENDPOINT_GROUPS: frozenset[AuthRateLimitEndpointGroup] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.groups
_STRICT_AUTH_RATE_LIMIT_PRESET_SLOTS: frozenset[AuthRateLimitSlot] = frozenset(
    {
        AuthRateLimitSlot.LOGIN,
        AuthRateLimitSlot.CHANGE_PASSWORD,
        AuthRateLimitSlot.REGISTER,
        AuthRateLimitSlot.TOTP_VERIFY,
        AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES,
    },
)
_LENIENT_AUTH_RATE_LIMIT_SHARED_SLOTS: frozenset[AuthRateLimitSlot] = frozenset(
    {
        AuthRateLimitSlot.LOGIN,
        AuthRateLimitSlot.CHANGE_PASSWORD,
        AuthRateLimitSlot.REFRESH,
        AuthRateLimitSlot.REGISTER,
    },
)
_LENIENT_AUTH_RATE_LIMIT_STRICT_SLOTS: frozenset[AuthRateLimitSlot] = frozenset(
    slot for slot in _AUTH_RATE_LIMIT_ENDPOINT_SLOTS if slot not in _LENIENT_AUTH_RATE_LIMIT_SHARED_SLOTS
)
_LENIENT_STRICT_MAX_ATTEMPTS_CAP = 5


def _validate_builder_names[NameT: str](
    names: Iterable[NameT],
    *,
    allowed: frozenset[NameT],
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


def _validate_auth_rate_limit_slots(names: Iterable[object], *, parameter_name: str) -> None:
    """Reject slot-keyed builder inputs that are not ``AuthRateLimitSlot`` values.

    Raises:
        TypeError: If any provided slot value is not an ``AuthRateLimitSlot``.
    """
    supported_slot_values = {slot.value for slot in AuthRateLimitSlot}
    invalid_names = sorted(
        {
            str(name)
            for name in names
            if not isinstance(name, AuthRateLimitSlot)
            and not (
                isinstance(name, StrEnum)
                and name.__class__.__name__ == AuthRateLimitSlot.__name__
                and str(name) in supported_slot_values
            )
        },
    )
    if not invalid_names:
        return

    msg = f"{parameter_name} must contain AuthRateLimitSlot values: {', '.join(invalid_names)}"
    raise TypeError(msg)


def _clone_backend_with_capped_attempts(backend: RateLimiterBackend, *, max_attempts_cap: int) -> RateLimiterBackend:
    """Clone built-in backends while capping the attempt budget.

    Args:
        backend: Built-in rate-limiter backend to clone.
        max_attempts_cap: Maximum attempts allowed on the cloned backend.

    Returns:
        New backend instance with the same storage configuration and a capped
        ``max_attempts`` value.

    Raises:
        TypeError: If ``backend`` is not a built-in limiter that the preset can
            safely clone.
    """
    if isinstance(backend, InMemoryRateLimiter):
        return InMemoryRateLimiter(
            max_attempts=min(backend.max_attempts, max_attempts_cap),
            window_seconds=backend.window_seconds,
            max_keys=backend.max_keys,
            sweep_interval=backend.sweep_interval,
        )
    if isinstance(backend, RedisRateLimiter):
        return RedisRateLimiter(
            redis=backend.redis,
            max_attempts=min(backend.max_attempts, max_attempts_cap),
            window_seconds=backend.window_seconds,
            key_prefix=backend.key_prefix,
        )

    msg = "AuthRateLimitConfig.lenient() only supports built-in InMemoryRateLimiter or RedisRateLimiter backends."
    raise TypeError(msg)


def _build_auth_rate_limit_endpoint(  # noqa: PLR0913
    recipe: _AuthRateLimitEndpointRecipe,
    *,
    backend: RateLimiterBackend,
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend],
    trusted_proxy: bool,
    identity_fields: tuple[str, ...],
    trusted_headers: tuple[str, ...],
) -> EndpointRateLimit:
    """Materialize one endpoint limiter from catalog metadata plus builder overrides.

    Returns:
        Endpoint limiter with the resolved backend, scope, and namespace.
    """
    return EndpointRateLimit(
        backend=group_backends.get(recipe.group, backend),
        scope=recipe.default_scope,
        namespace=recipe.default_namespace,
        trusted_proxy=trusted_proxy,
        identity_fields=identity_fields,
        trusted_headers=trusted_headers,
    )


def _iter_auth_rate_limit_config_items(  # noqa: PLR0913
    *,
    catalog: _AuthRateLimitEndpointCatalog,
    backend: RateLimiterBackend,
    enabled: Iterable[AuthRateLimitSlot] | None,
    disabled: Iterable[AuthRateLimitSlot],
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend],
    endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None],
    trusted_proxy: bool,
    identity_fields: tuple[str, ...],
    trusted_headers: tuple[str, ...],
) -> Iterable[tuple[str, EndpointRateLimit | None]]:
    """Yield dataclass kwargs for the shared-backend builder in stable slot order."""
    enabled_values = None if enabled is None else tuple(enabled)
    disabled_values = tuple(disabled)
    endpoint_override_slots = tuple(endpoint_overrides)

    if enabled_values is not None:
        _validate_auth_rate_limit_slots(enabled_values, parameter_name="enabled")
    _validate_auth_rate_limit_slots(disabled_values, parameter_name="disabled")
    _validate_auth_rate_limit_slots(endpoint_override_slots, parameter_name="endpoint_overrides")

    enabled_slots = catalog.resolve_enabled_slots(cast("Iterable[AuthRateLimitSlot] | None", enabled_values))
    disabled_slots = frozenset(cast("Iterable[AuthRateLimitSlot]", disabled_values))

    catalog.validate_slot_names(enabled_slots, parameter_name="enabled")
    catalog.validate_slot_names(disabled_slots, parameter_name="disabled")
    catalog.validate_group_names(group_backends, parameter_name="group_backends")
    catalog.validate_slot_names(endpoint_overrides, parameter_name="endpoint_overrides")

    for recipe in catalog.recipes:
        slot_override = endpoint_overrides.get(recipe.slot, _MISSING_OVERRIDE)
        if slot_override is not _MISSING_OVERRIDE:
            yield recipe.slot.value, cast("EndpointRateLimit | None", slot_override)
            continue

        if recipe.slot not in enabled_slots or recipe.slot in disabled_slots:
            continue

        yield (
            recipe.slot.value,
            _build_auth_rate_limit_endpoint(
                recipe,
                backend=backend,
                group_backends=group_backends,
                trusted_proxy=trusted_proxy,
                identity_fields=identity_fields,
                trusted_headers=trusted_headers,
            ),
        )


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
    change_password: EndpointRateLimit | None = None
    refresh: EndpointRateLimit | None = None
    register: EndpointRateLimit | None = None
    forgot_password: EndpointRateLimit | None = None
    reset_password: EndpointRateLimit | None = None
    totp_enable: EndpointRateLimit | None = None
    totp_confirm_enable: EndpointRateLimit | None = None
    totp_verify: EndpointRateLimit | None = None
    totp_disable: EndpointRateLimit | None = None
    totp_regenerate_recovery_codes: EndpointRateLimit | None = None
    verify_token: EndpointRateLimit | None = None
    request_verify_token: EndpointRateLimit | None = None

    @classmethod
    def disabled(cls) -> Self:
        """Build a preset that disables rate limiting for every auth endpoint.

        Returns:
            New config with every supported auth slot left unset.
        """
        return cls()

    @classmethod
    def strict(cls, *, backend: RateLimiterBackend) -> Self:
        """Build a strict preset for public-facing sign-in surfaces.

        The provided backend should already be configured with the lower attempt
        budget you want to enforce. This preset wires that shared backend to the
        highest-risk credential entry points: login, change-password, register,
        and TOTP verify.

        Args:
            backend: Shared backend instance for the strict preset slots.

        Returns:
            New config with only the strict preset slots enabled.
        """
        config_kwargs = {
            recipe.slot.value: EndpointRateLimit(
                backend=backend,
                scope=recipe.default_scope,
                namespace=recipe.default_namespace,
            )
            for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES
            if recipe.slot in _STRICT_AUTH_RATE_LIMIT_PRESET_SLOTS
        }
        return cls(**cast("Any", config_kwargs))

    @classmethod
    def lenient(cls, *, backend: RateLimiterBackend) -> Self:
        """Build a lenient preset for internal or low-risk deployments.

        The supplied backend sets the broader budget used for the lower-risk
        login, change-password, refresh, and registration surfaces. Token- and secret-bearing
        flows still receive a stricter built-in limiter clone capped at five
        attempts per window so reset, verification, and TOTP endpoints do not
        inherit an overly permissive budget.

        Args:
            backend: Built-in shared backend instance for the lenient preset.

        Returns:
            New config with route-style namespaces for every supported auth slot.
        """
        strict_backend = _clone_backend_with_capped_attempts(
            backend,
            max_attempts_cap=_LENIENT_STRICT_MAX_ATTEMPTS_CAP,
        )
        config_kwargs = {
            recipe.slot.value: EndpointRateLimit(
                backend=backend if recipe.slot in _LENIENT_AUTH_RATE_LIMIT_SHARED_SLOTS else strict_backend,
                scope=recipe.default_scope,
                namespace=recipe.default_namespace,
            )
            for recipe in _AUTH_RATE_LIMIT_ENDPOINT_RECIPES
        }
        return cls(**cast("Any", config_kwargs))

    @classmethod
    def from_shared_backend(  # noqa: PLR0913
        cls,
        backend: RateLimiterBackend,
        *,
        enabled: Iterable[AuthRateLimitSlot] | None = None,
        disabled: Iterable[AuthRateLimitSlot] = (),
        group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend] | None = None,
        endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None] | None = None,
        trusted_proxy: bool = False,
        identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS,
        trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
    ) -> Self:
        """Build endpoint-specific limiters from the package-owned shared-backend recipe.

        The builder uses the private endpoint catalog for default scopes and namespace
        tokens, then applies override precedence in this order:

        1. ``backend`` for every enabled slot
        2. ``group_backends`` for slot groups such as ``totp`` or ``verification``
        3. ``endpoint_overrides`` for full slot replacement or explicit ``None`` disablement

        Args:
            backend: Default limiter backend for enabled auth slots.
            enabled: Optional auth slot enum values to build. Defaults to all supported slots. Use
                ``tuple(AuthRateLimitSlot)`` for the ordered full inventory.
            disabled: Auth slot enum values to leave unset, even when they would otherwise be enabled.
                Use ``{AuthRateLimitSlot.VERIFY_TOKEN, AuthRateLimitSlot.REQUEST_VERIFY_TOKEN}`` to leave
                the built-in verification routes disabled.
            group_backends: Optional backend overrides keyed by auth slot group:
                ``login``, ``refresh``, ``register``, ``password_reset``, ``totp``, or
                ``verification``.
            endpoint_overrides: Optional full per-slot replacements. ``None`` disables a slot.
            trusted_proxy: Shared trusted-proxy setting applied to generated limiters.
            identity_fields: Shared request body identity fields applied to generated limiters.
            trusted_headers: Shared trusted proxy header names applied to generated limiters.

        Returns:
            New config populated from the shared-backend builder inputs.
        """
        group_backend_map: dict[AuthRateLimitEndpointGroup, RateLimiterBackend] = dict(group_backends or {})
        endpoint_override_map = dict(endpoint_overrides or {})
        config_kwargs = dict(
            _iter_auth_rate_limit_config_items(
                catalog=_AUTH_RATE_LIMIT_ENDPOINT_CATALOG,
                backend=backend,
                enabled=enabled,
                disabled=disabled,
                group_backends=group_backend_map,
                endpoint_overrides=endpoint_override_map,
                trusted_proxy=trusted_proxy,
                identity_fields=identity_fields,
                trusted_headers=trusted_headers,
            ),
        )
        return cls(**cast("Any", config_kwargs))


if tuple(field.name for field in fields(AuthRateLimitConfig)) != tuple(
    slot.value for slot in _AUTH_RATE_LIMIT_ENDPOINT_SLOTS
):
    msg = "AuthRateLimitConfig fields must stay aligned with the private auth rate-limit endpoint catalog."
    raise RuntimeError(msg)
