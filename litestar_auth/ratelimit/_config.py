"""Configuration types and private endpoint metadata for auth rate limiting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping  # noqa: TC003
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any, ClassVar, Self, cast

from ._endpoint import _DEFAULT_IDENTITY_FIELDS, EndpointRateLimit
from ._helpers import _DEFAULT_TRUSTED_HEADERS
from ._memory import InMemoryRateLimiter
from ._protocol import RateLimiterBackend  # noqa: TC001
from ._redis import RedisRateLimiter
from ._slot_catalog import (
    _AUTH_RATE_LIMIT_ENDPOINT_RECIPES as _SLOT_RECIPES,
)
from ._slot_catalog import (
    AuthRateLimitEndpointGroup,
    AuthRateLimitSlot,
)
from ._slot_catalog import (
    _AuthRateLimitEndpointCatalog as _SlotCatalog,
)
from ._slot_catalog import (
    _AuthRateLimitEndpointRecipe as _SlotRecipe,
)
from ._slot_catalog import (
    _build_auth_rate_limit_endpoint_catalog as _build_slot_catalog,
)

_SLOT_MISSING_OVERRIDE = object()
_SLOT_CATALOG = _build_slot_catalog()
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
_LENIENT_STRICT_MAX_ATTEMPTS_CAP = 5


@dataclass(slots=True, frozen=True)
class SharedRateLimitConfigOptions:
    """Shared-backend builder options for auth endpoint rate-limit configs.

    Args:
        enabled: Optional auth slot enum values to build. Defaults to all supported slots.
        disabled: Auth slot enum values to leave unset, even when they would otherwise be enabled.
        group_backends: Optional backend overrides keyed by auth slot group.
        endpoint_overrides: Optional full per-slot replacements. ``None`` disables a slot.
        trusted_proxy: Shared trusted-proxy setting applied to generated limiters.
        identity_fields: Shared request body identity fields applied to generated limiters.
        trusted_headers: Shared trusted proxy header names applied to generated limiters.
    """

    enabled: Iterable[AuthRateLimitSlot] | None = None
    disabled: Iterable[AuthRateLimitSlot] = ()
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend] | None = None
    endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None] | None = None
    trusted_proxy: bool = False
    identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS


@dataclass(slots=True, frozen=True)
class _EndpointBuildSettings:
    """Shared endpoint limiter settings resolved from builder inputs."""

    endpoint_type: type[EndpointRateLimit]
    backend: RateLimiterBackend
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend]
    trusted_proxy: bool
    identity_fields: tuple[str, ...]
    trusted_headers: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class _ResolvedEndpointItems:
    """Validated slot filters and endpoint materialization inputs."""

    recipes: tuple[_SlotRecipe, ...]
    endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None]
    enabled_slots: frozenset[AuthRateLimitSlot]
    disabled_slots: frozenset[AuthRateLimitSlot]
    endpoint_settings: _EndpointBuildSettings


@dataclass(slots=True, frozen=True)
class _AuthRateLimitConfigItems:
    """Raw shared-backend builder inputs before validation."""

    catalog: _SlotCatalog
    backend: RateLimiterBackend
    enabled: Iterable[AuthRateLimitSlot] | None
    disabled: Iterable[AuthRateLimitSlot]
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend]
    endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None]
    endpoint_type: type[EndpointRateLimit]
    trusted_proxy: bool
    identity_fields: tuple[str, ...]
    trusted_headers: tuple[str, ...]


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
    backend_value = cast("Any", backend)
    backend_type = cast("Any", type(backend))
    if (
        backend_type.__module__ == InMemoryRateLimiter.__module__
        and backend_type.__name__ == InMemoryRateLimiter.__name__
    ):
        return backend_type(
            max_attempts=min(backend_value.max_attempts, max_attempts_cap),
            window_seconds=backend_value.window_seconds,
            max_keys=backend_value.max_keys,
            sweep_interval=backend_value.sweep_interval,
        )
    if backend_type.__module__ == RedisRateLimiter.__module__ and backend_type.__name__ == RedisRateLimiter.__name__:
        return backend_type(
            redis=backend_value.redis,
            max_attempts=min(backend_value.max_attempts, max_attempts_cap),
            window_seconds=backend_value.window_seconds,
            key_prefix=backend_value.key_prefix,
        )

    msg = "AuthRateLimitConfig.lenient() only supports built-in InMemoryRateLimiter or RedisRateLimiter backends."
    raise TypeError(msg)


def _build_auth_rate_limit_endpoint(
    recipe: _SlotRecipe,
    settings: _EndpointBuildSettings,
) -> EndpointRateLimit:
    """Materialize one endpoint limiter from catalog metadata plus builder overrides.

    Returns:
        Endpoint limiter with the resolved backend, scope, and namespace.
    """
    return settings.endpoint_type(
        backend=settings.group_backends.get(recipe.group, settings.backend),
        scope=recipe.default_scope,
        namespace=recipe.default_namespace,
        trusted_proxy=settings.trusted_proxy,
        identity_fields=settings.identity_fields,
        trusted_headers=settings.trusted_headers,
    )


def _validate_shared_backend_slot_types(
    *,
    enabled_values: tuple[AuthRateLimitSlot, ...] | None,
    disabled_values: tuple[AuthRateLimitSlot, ...],
    endpoint_override_slots: tuple[AuthRateLimitSlot, ...],
) -> None:
    """Validate shared-backend slot inputs before catalog membership checks."""
    if enabled_values is not None:
        _validate_auth_rate_limit_slots(enabled_values, parameter_name="enabled")
    _validate_auth_rate_limit_slots(disabled_values, parameter_name="disabled")
    _validate_auth_rate_limit_slots(endpoint_override_slots, parameter_name="endpoint_overrides")


def _resolve_enabled_and_disabled_slot_sets(
    catalog: _SlotCatalog,
    *,
    enabled_values: tuple[AuthRateLimitSlot, ...] | None,
    disabled_values: tuple[AuthRateLimitSlot, ...],
) -> tuple[frozenset[AuthRateLimitSlot], frozenset[AuthRateLimitSlot]]:
    """Resolve shared-backend enablement inputs into immutable slot sets.

    Returns:
        Enabled and disabled slot sets in that order.
    """
    enabled_slots = catalog.resolve_enabled_slots(cast("Iterable[AuthRateLimitSlot] | None", enabled_values))
    disabled_slots = frozenset(cast("Iterable[AuthRateLimitSlot]", disabled_values))
    return enabled_slots, disabled_slots


def _validate_shared_backend_inputs(
    catalog: _SlotCatalog,
    *,
    enabled_slots: frozenset[AuthRateLimitSlot],
    disabled_slots: frozenset[AuthRateLimitSlot],
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend],
    endpoint_override_slots: tuple[AuthRateLimitSlot, ...],
) -> None:
    """Validate resolved shared-backend builder inputs against the private catalog."""
    catalog.validate_slot_names(enabled_slots, parameter_name="enabled", validator=_validate_builder_names)
    catalog.validate_slot_names(disabled_slots, parameter_name="disabled", validator=_validate_builder_names)
    catalog.validate_group_names(group_backends, parameter_name="group_backends", validator=_validate_builder_names)
    catalog.validate_slot_names(
        endpoint_override_slots,
        parameter_name="endpoint_overrides",
        validator=_validate_builder_names,
    )


def _iter_resolved_endpoint_items(
    settings: _ResolvedEndpointItems,
) -> Iterable[tuple[str, EndpointRateLimit | None]]:
    """Yield resolved endpoint config items after validation and slot filtering."""
    for recipe in settings.recipes:
        slot_override = settings.endpoint_overrides.get(recipe.slot, _SLOT_MISSING_OVERRIDE)
        if slot_override is not _SLOT_MISSING_OVERRIDE:
            yield recipe.slot.value, cast("EndpointRateLimit | None", slot_override)
            continue

        if recipe.slot not in settings.enabled_slots or recipe.slot in settings.disabled_slots:
            continue

        yield (
            recipe.slot.value,
            _build_auth_rate_limit_endpoint(
                recipe,
                settings.endpoint_settings,
            ),
        )


def _iter_auth_rate_limit_config_items(
    settings: _AuthRateLimitConfigItems,
) -> Iterable[tuple[str, EndpointRateLimit | None]]:
    """Yield dataclass kwargs for the shared-backend builder in stable slot order."""
    enabled_values = None if settings.enabled is None else tuple(settings.enabled)
    disabled_values = tuple(settings.disabled)
    endpoint_override_slots = tuple(settings.endpoint_overrides)

    _validate_shared_backend_slot_types(
        enabled_values=enabled_values,
        disabled_values=disabled_values,
        endpoint_override_slots=endpoint_override_slots,
    )
    enabled_slots, disabled_slots = _resolve_enabled_and_disabled_slot_sets(
        settings.catalog,
        enabled_values=enabled_values,
        disabled_values=disabled_values,
    )
    _validate_shared_backend_inputs(
        settings.catalog,
        enabled_slots=enabled_slots,
        disabled_slots=disabled_slots,
        group_backends=settings.group_backends,
        endpoint_override_slots=endpoint_override_slots,
    )
    yield from _iter_resolved_endpoint_items(
        _ResolvedEndpointItems(
            recipes=settings.catalog.recipes,
            endpoint_overrides=settings.endpoint_overrides,
            enabled_slots=enabled_slots,
            disabled_slots=disabled_slots,
            endpoint_settings=_EndpointBuildSettings(
                endpoint_type=settings.endpoint_type,
                backend=settings.backend,
                group_backends=settings.group_backends,
                trusted_proxy=settings.trusted_proxy,
                identity_fields=settings.identity_fields,
                trusted_headers=settings.trusted_headers,
            ),
        ),
    )


@dataclass(slots=True, frozen=True)
class AuthRateLimitConfig:
    """Optional rate-limit rules for auth-related endpoints."""

    _endpoint_rate_limit_type: ClassVar[type[EndpointRateLimit]] = EndpointRateLimit

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
            recipe.slot.value: cls._endpoint_rate_limit_type(
                backend=backend,
                scope=recipe.default_scope,
                namespace=recipe.default_namespace,
            )
            for recipe in _SLOT_RECIPES
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
            recipe.slot.value: cls._endpoint_rate_limit_type(
                backend=backend if recipe.slot in _LENIENT_AUTH_RATE_LIMIT_SHARED_SLOTS else strict_backend,
                scope=recipe.default_scope,
                namespace=recipe.default_namespace,
            )
            for recipe in _SLOT_RECIPES
        }
        return cls(**cast("Any", config_kwargs))

    @classmethod
    def from_shared_backend(
        cls,
        backend: RateLimiterBackend,
        *,
        options: SharedRateLimitConfigOptions | None = None,
    ) -> Self:
        """Build endpoint-specific limiters from the package-owned shared-backend recipe.

        The builder uses the private endpoint catalog for default scopes and namespace
        tokens, then applies override precedence in this order:

        1. ``backend`` for every enabled slot
        2. ``group_backends`` for slot groups such as ``totp`` or ``verification``
        3. ``endpoint_overrides`` for full slot replacement or explicit ``None`` disablement

        Args:
            backend: Default limiter backend for enabled auth slots.
            options: Optional shared builder options. Use
                ``SharedRateLimitConfigOptions(disabled={...})`` to leave built-in verification routes disabled.

        Returns:
            New config populated from the shared-backend builder inputs.
        """
        resolved_options = options or SharedRateLimitConfigOptions()
        group_backend_map: dict[AuthRateLimitEndpointGroup, RateLimiterBackend] = dict(
            resolved_options.group_backends or {},
        )
        endpoint_override_map = dict(resolved_options.endpoint_overrides or {})
        config_kwargs = dict(
            _iter_auth_rate_limit_config_items(
                _AuthRateLimitConfigItems(
                    catalog=_SLOT_CATALOG,
                    backend=backend,
                    enabled=resolved_options.enabled,
                    disabled=resolved_options.disabled,
                    group_backends=group_backend_map,
                    endpoint_overrides=endpoint_override_map,
                    endpoint_type=cls._endpoint_rate_limit_type,
                    trusted_proxy=resolved_options.trusted_proxy,
                    identity_fields=resolved_options.identity_fields,
                    trusted_headers=resolved_options.trusted_headers,
                ),
            ),
        )
        return cls(**cast("Any", config_kwargs))


if tuple(field.name for field in fields(AuthRateLimitConfig)) != tuple(slot.value for slot in _SLOT_CATALOG.slots):
    msg = "AuthRateLimitConfig fields must stay aligned with the private auth rate-limit endpoint catalog."
    raise RuntimeError(msg)
