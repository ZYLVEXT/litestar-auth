"""Configuration types and private endpoint metadata for auth rate limiting."""

from __future__ import annotations

import dataclasses
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any, ClassVar, Self, cast

from litestar_auth.exceptions import ConfigurationError, SecurityWarning

from ._client_host import _DEFAULT_TRUSTED_HEADERS
from ._endpoint import _DEFAULT_IDENTITY_FIELDS, EndpointRateLimit
from ._memory import InMemoryAccountLockoutStore, InMemoryRateLimiter
from ._protocol import AccountLockoutStore, RateLimiterBackend
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
_PUBLIC_RATE_LIMIT_SLOT_LABELS = {
    "login": "POST /login",
    "refresh": "POST /refresh",
    "register": "POST /register",
}
DEFAULT_ACCOUNT_LOCKOUT_FAILURE_THRESHOLD = 5
DEFAULT_ACCOUNT_LOCKOUT_WINDOW_SECONDS = 900.0
type AccountLockoutStoreFactory = Callable[[], AccountLockoutStore]


@dataclass(slots=True, frozen=True)
class AccountLockoutConfig:
    """Opt-in per-account lockout settings for password-login failures.

    Args:
        enabled: Whether the account lockout policy is active.
        failure_threshold: Failed password attempts before an account key is locked.
        window_seconds: Counter TTL and lockout window duration in seconds.
        store_factory: Optional factory for a shared custom store such as ``RedisAccountLockoutStore``.
    """

    enabled: bool = False
    failure_threshold: int = DEFAULT_ACCOUNT_LOCKOUT_FAILURE_THRESHOLD
    window_seconds: float = DEFAULT_ACCOUNT_LOCKOUT_WINDOW_SECONDS
    store_factory: AccountLockoutStoreFactory | None = None
    _resolved_store: AccountLockoutStore | None = dataclasses.field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Validate the public lockout policy inputs.

        Raises:
            ConfigurationError: If any account-lockout setting is invalid.
        """
        if not isinstance(self.enabled, bool):
            msg = "account_lockout_config.enabled must be a boolean."
            raise ConfigurationError(msg)
        threshold_is_positive_int = (
            isinstance(self.failure_threshold, int)
            and not isinstance(self.failure_threshold, bool)
            and self.failure_threshold >= 1
        )
        if not threshold_is_positive_int:
            msg = "account_lockout_config.failure_threshold must be a positive integer."
            raise ConfigurationError(msg)
        if not isinstance(self.window_seconds, int | float) or self.window_seconds <= 0:
            msg = "account_lockout_config.window_seconds must be greater than 0."
            raise ConfigurationError(msg)
        if self.store_factory is not None and not callable(self.store_factory):
            msg = "account_lockout_config.store_factory must be callable when provided."
            raise ConfigurationError(msg)

    def resolve_store(self) -> AccountLockoutStore:
        """Return the memoized account-lockout store for this config."""
        if self._resolved_store is not None:
            return self._resolved_store
        resolved_store = (
            self.store_factory()
            if self.store_factory is not None
            else InMemoryAccountLockoutStore(
                failure_threshold=self.failure_threshold,
                window_seconds=self.window_seconds,
            )
        )
        object.__setattr__(self, "_resolved_store", resolved_store)  # noqa: PLC2801
        return resolved_store


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
        trusted_proxy_hops: Shared X-Forwarded-For hop count applied to generated limiters.
    """

    enabled: Iterable[AuthRateLimitSlot] | None = None
    disabled: Iterable[AuthRateLimitSlot] = ()
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend] | None = None
    endpoint_overrides: Mapping[AuthRateLimitSlot, EndpointRateLimit | None] | None = None
    trusted_proxy: bool = False
    identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS
    trusted_proxy_hops: int = 1


@dataclass(slots=True, frozen=True)
class _EndpointBuildSettings:
    """Shared endpoint limiter settings resolved from builder inputs."""

    endpoint_type: type[EndpointRateLimit]
    backend: RateLimiterBackend
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend]
    trusted_proxy: bool
    identity_fields: tuple[str, ...]
    trusted_headers: tuple[str, ...]
    trusted_proxy_hops: int


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
    trusted_proxy_hops: int


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
        trusted_proxy_hops=settings.trusted_proxy_hops,
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
                trusted_proxy_hops=settings.trusted_proxy_hops,
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
    organization_switch: EndpointRateLimit | None = None
    organization_invitation_accept: EndpointRateLimit | None = None
    organization_invitation_decline: EndpointRateLimit | None = None
    api_key_create: EndpointRateLimit | None = None
    api_key_update: EndpointRateLimit | None = None
    api_key_use: EndpointRateLimit | None = None

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
                    trusted_proxy_hops=resolved_options.trusted_proxy_hops,
                ),
            ),
        )
        return cls(**cast("Any", config_kwargs))


def warn_missing_public_rate_limits(
    rate_limit_config: AuthRateLimitConfig | None,
    *,
    endpoint_names: Iterable[str],
    controller_name: str,
    unsafe_testing: bool = False,
    stacklevel: int = 2,
) -> None:
    """Warn when public unauthenticated endpoints are assembled without throttles."""
    if unsafe_testing:
        return

    missing_endpoint_names = tuple(
        endpoint_name
        for endpoint_name in endpoint_names
        if rate_limit_config is None or getattr(rate_limit_config, endpoint_name) is None
    )
    if not missing_endpoint_names:
        return

    endpoint_labels = ", ".join(
        _PUBLIC_RATE_LIMIT_SLOT_LABELS.get(endpoint_name, endpoint_name) for endpoint_name in missing_endpoint_names
    )
    config_fields = ", ".join(f"AuthRateLimitConfig.{endpoint_name}" for endpoint_name in missing_endpoint_names)
    warnings.warn(
        f"{controller_name} is exposing {endpoint_labels} without auth rate limiting. "
        f"Configure {config_fields} or pass unsafe_testing=True for controlled tests/local development.",
        SecurityWarning,
        stacklevel=stacklevel,
    )


# Below this response floor the locked-account short-circuit (which skips the Argon2
# verification that genuine and unknown-account failures pay) can become timing-
# distinguishable, reopening an account-enumeration oracle. The default floor (0.4s)
# comfortably dominates typical Argon2 cost; warn only when an operator lowers it.
_MIN_SAFE_ACCOUNT_LOCKOUT_RESPONSE_SECONDS = 0.2


def warn_account_lockout_response_floor_too_low(
    account_lockout_config: AccountLockoutConfig | None,
    *,
    login_minimum_response_seconds: float,
    unsafe_testing: bool = False,
    stacklevel: int = 2,
) -> None:
    """Warn when the locked-account short-circuit undercuts the login timing floor."""
    if unsafe_testing:
        return
    if account_lockout_config is None or not account_lockout_config.enabled:
        return
    if login_minimum_response_seconds >= _MIN_SAFE_ACCOUNT_LOCKOUT_RESPONSE_SECONDS:
        return
    warnings.warn(
        "Account lockout is enabled but login_minimum_response_seconds "
        f"({login_minimum_response_seconds:.3f}s) is below the safe floor "
        f"({_MIN_SAFE_ACCOUNT_LOCKOUT_RESPONSE_SECONDS:.2f}s). The locked-account path skips password "
        "hashing, so a floor under the Argon2 verification cost makes locked accounts "
        "timing-distinguishable and enables account enumeration. Keep the response-time "
        "floor above your Argon2 verification time.",
        SecurityWarning,
        stacklevel=stacklevel,
    )


if tuple(field.name for field in fields(AuthRateLimitConfig)) != tuple(slot.value for slot in _SLOT_CATALOG.slots):
    msg = "AuthRateLimitConfig fields must stay aligned with the private auth rate-limit endpoint catalog."
    raise RuntimeError(msg)
