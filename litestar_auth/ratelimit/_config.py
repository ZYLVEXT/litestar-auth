"""Configuration types and private endpoint metadata for auth rate limiting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping  # noqa: TC003
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Literal, Self, cast

from litestar.connection import Request  # noqa: TC002
from litestar.exceptions import TooManyRequestsException

from ._helpers import _DEFAULT_TRUSTED_HEADERS, _client_host, _extract_email, _safe_key_part, logger
from ._protocol import RateLimiterBackend  # noqa: TC001

type RateLimitScope = Literal["ip", "ip_email"]
type AuthRateLimitEndpointSlot = Literal[
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
type AuthRateLimitEndpointGroup = Literal["login", "password_reset", "refresh", "register", "totp", "verification"]
type AuthRateLimitNamespaceStyle = Literal["route", "snake_case"]

_DEFAULT_IDENTITY_FIELDS = ("identifier", "username", "email")
_AUTH_RATE_LIMIT_NAMESPACE_STYLES = frozenset({"route", "snake_case"})
_MISSING_OVERRIDE = object()


@dataclass(slots=True, frozen=True)
class _AuthRateLimitEndpointRecipe:
    """Package-owned metadata for a supported auth rate-limit slot."""

    slot: AuthRateLimitEndpointSlot
    default_scope: RateLimitScope
    default_namespace: str
    group: AuthRateLimitEndpointGroup


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


def _build_auth_rate_limit_recipe_index() -> MappingProxyType[AuthRateLimitEndpointSlot, _AuthRateLimitEndpointRecipe]:
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
    recipes_by_slot: MappingProxyType[AuthRateLimitEndpointSlot, _AuthRateLimitEndpointRecipe]
    slots: tuple[AuthRateLimitEndpointSlot, ...]
    slot_set: frozenset[AuthRateLimitEndpointSlot]
    slots_by_group: MappingProxyType[AuthRateLimitEndpointGroup, frozenset[AuthRateLimitEndpointSlot]]
    groups: frozenset[AuthRateLimitEndpointGroup]

    def resolve_enabled_slots(
        self,
        enabled: Iterable[AuthRateLimitEndpointSlot] | None,
    ) -> frozenset[AuthRateLimitEndpointSlot]:
        """Return the enabled slot set, defaulting to the full supported catalog."""
        return self.slot_set if enabled is None else frozenset(enabled)

    def iter_enabled_recipes(
        self,
        *,
        enabled_slots: frozenset[AuthRateLimitEndpointSlot],
        disabled_slots: frozenset[AuthRateLimitEndpointSlot],
    ) -> Iterable[_AuthRateLimitEndpointRecipe]:
        """Yield catalog entries that remain enabled after disablement is applied."""
        for recipe in self.recipes:
            if recipe.slot in enabled_slots and recipe.slot not in disabled_slots:
                yield recipe

    def validate_slot_names(self, names: Iterable[str], *, parameter_name: str) -> None:
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
    slots_by_group: dict[AuthRateLimitEndpointGroup, set[AuthRateLimitEndpointSlot]] = {}
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
_AUTH_RATE_LIMIT_ENDPOINT_RECIPES_BY_SLOT: MappingProxyType[AuthRateLimitEndpointSlot, _AuthRateLimitEndpointRecipe] = (
    _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.recipes_by_slot
)
_AUTH_RATE_LIMIT_ENDPOINT_SLOTS: tuple[AuthRateLimitEndpointSlot, ...] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slots
_AUTH_RATE_LIMIT_ENDPOINT_SLOT_SET: frozenset[AuthRateLimitEndpointSlot] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slot_set
_AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP: MappingProxyType[
    AuthRateLimitEndpointGroup,
    frozenset[AuthRateLimitEndpointSlot],
] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.slots_by_group
_AUTH_RATE_LIMIT_ENDPOINT_GROUPS: frozenset[AuthRateLimitEndpointGroup] = _AUTH_RATE_LIMIT_ENDPOINT_CATALOG.groups

#: Ordered auth slot names accepted by the shared-backend builder.
AUTH_RATE_LIMIT_ENDPOINT_SLOTS: tuple[AuthRateLimitEndpointSlot, ...] = _AUTH_RATE_LIMIT_ENDPOINT_SLOTS
#: Read-only slot sets keyed by ``AuthRateLimitEndpointGroup`` names.
AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP: MappingProxyType[
    AuthRateLimitEndpointGroup,
    frozenset[AuthRateLimitEndpointSlot],
] = _AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP
#: Convenience slot set for disabling the built-in verification routes.
AUTH_RATE_LIMIT_VERIFICATION_SLOTS: frozenset[AuthRateLimitEndpointSlot] = AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP[
    "verification"
]


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


def _build_auth_rate_limit_endpoint(  # noqa: PLR0913
    recipe: _AuthRateLimitEndpointRecipe,
    *,
    backend: RateLimiterBackend,
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend],
    namespace_style: AuthRateLimitNamespaceStyle,
    scope_overrides: Mapping[AuthRateLimitEndpointSlot, RateLimitScope],
    namespace_overrides: Mapping[AuthRateLimitEndpointSlot, str],
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
        scope=scope_overrides.get(recipe.slot, recipe.default_scope),
        namespace=namespace_overrides.get(
            recipe.slot,
            recipe.default_namespace if namespace_style == "route" else recipe.slot,
        ),
        trusted_proxy=trusted_proxy,
        identity_fields=identity_fields,
        trusted_headers=trusted_headers,
    )


def _iter_auth_rate_limit_config_items(  # noqa: PLR0913
    *,
    catalog: _AuthRateLimitEndpointCatalog,
    backend: RateLimiterBackend,
    enabled: Iterable[AuthRateLimitEndpointSlot] | None,
    disabled: Iterable[AuthRateLimitEndpointSlot],
    group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend],
    scope_overrides: Mapping[AuthRateLimitEndpointSlot, RateLimitScope],
    namespace_style: AuthRateLimitNamespaceStyle,
    namespace_overrides: Mapping[AuthRateLimitEndpointSlot, str],
    endpoint_overrides: Mapping[AuthRateLimitEndpointSlot, EndpointRateLimit | None],
    trusted_proxy: bool,
    identity_fields: tuple[str, ...],
    trusted_headers: tuple[str, ...],
) -> Iterable[tuple[AuthRateLimitEndpointSlot, EndpointRateLimit | None]]:
    """Yield dataclass kwargs for the shared-backend builder in stable slot order."""
    enabled_slots = catalog.resolve_enabled_slots(enabled)
    disabled_slots = frozenset(disabled)

    catalog.validate_slot_names(enabled_slots, parameter_name="enabled")
    catalog.validate_slot_names(disabled_slots, parameter_name="disabled")
    catalog.validate_group_names(group_backends, parameter_name="group_backends")
    catalog.validate_slot_names(scope_overrides, parameter_name="scope_overrides")
    _validate_builder_names(
        (namespace_style,),
        allowed=_AUTH_RATE_LIMIT_NAMESPACE_STYLES,
        parameter_name="namespace_style",
        item_name="auth rate-limit namespace styles",
    )
    catalog.validate_slot_names(namespace_overrides, parameter_name="namespace_overrides")
    catalog.validate_slot_names(endpoint_overrides, parameter_name="endpoint_overrides")

    for recipe in catalog.recipes:
        slot_override = endpoint_overrides.get(recipe.slot, _MISSING_OVERRIDE)
        if slot_override is not _MISSING_OVERRIDE:
            yield recipe.slot, cast("EndpointRateLimit | None", slot_override)
            continue

        if recipe.slot not in enabled_slots or recipe.slot in disabled_slots:
            continue

        yield (
            recipe.slot,
            _build_auth_rate_limit_endpoint(
                recipe,
                backend=backend,
                group_backends=group_backends,
                namespace_style=namespace_style,
                scope_overrides=scope_overrides,
                namespace_overrides=namespace_overrides,
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
        enabled: Iterable[AuthRateLimitEndpointSlot] | None = None,
        disabled: Iterable[AuthRateLimitEndpointSlot] = (),
        group_backends: Mapping[AuthRateLimitEndpointGroup, RateLimiterBackend] | None = None,
        scope_overrides: Mapping[AuthRateLimitEndpointSlot, RateLimitScope] | None = None,
        namespace_style: AuthRateLimitNamespaceStyle = "route",
        namespace_overrides: Mapping[AuthRateLimitEndpointSlot, str] | None = None,
        endpoint_overrides: Mapping[AuthRateLimitEndpointSlot, EndpointRateLimit | None] | None = None,
        trusted_proxy: bool = False,
        identity_fields: tuple[str, ...] = _DEFAULT_IDENTITY_FIELDS,
        trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
    ) -> Self:
        """Build endpoint-specific limiters from the package-owned shared-backend recipe.

        The builder uses the private endpoint catalog for default scopes and namespace
        tokens, then applies override precedence in this order:

        1. ``backend`` for every enabled slot
        2. ``group_backends`` for slot groups such as ``totp`` or ``verification``
        3. ``namespace_style`` for the supported namespace family
        4. ``scope_overrides`` / ``namespace_overrides`` for slot-specific tweaks
        5. ``endpoint_overrides`` for full slot replacement or explicit ``None`` disablement

        Args:
            backend: Default limiter backend for enabled auth slots.
            enabled: Optional auth slot names to build. Defaults to all supported slots. Use
                ``AUTH_RATE_LIMIT_ENDPOINT_SLOTS`` for the ordered full inventory.
            disabled: Auth slot names to leave unset, even when they would otherwise be enabled.
                Use ``AUTH_RATE_LIMIT_VERIFICATION_SLOTS`` to leave the built-in verification
                routes disabled without repeating literal slot names.
            group_backends: Optional backend overrides keyed by auth slot group:
                ``login``, ``refresh``, ``register``, ``password_reset``, ``totp``, or
                ``verification``.
            scope_overrides: Optional per-slot scope overrides to preserve existing key behavior.
            namespace_style: Supported namespace family for generated limiters. ``"route"``
                keeps route-oriented tokens such as ``forgot-password``. ``"snake_case"``
                uses slot-aligned tokens such as ``forgot_password``.
            namespace_overrides: Optional per-slot namespace tokens to preserve existing key names.
            endpoint_overrides: Optional full per-slot replacements. ``None`` disables a slot.
            trusted_proxy: Shared trusted-proxy setting applied to generated limiters.
            identity_fields: Shared request body identity fields applied to generated limiters.
            trusted_headers: Shared trusted proxy header names applied to generated limiters.

        Returns:
            New config populated from the shared-backend builder inputs.
        """
        group_backend_map: dict[AuthRateLimitEndpointGroup, RateLimiterBackend] = dict(group_backends or {})
        scope_override_map: dict[AuthRateLimitEndpointSlot, RateLimitScope] = dict(scope_overrides or {})
        namespace_override_map: dict[AuthRateLimitEndpointSlot, str] = dict(namespace_overrides or {})
        endpoint_override_map: dict[AuthRateLimitEndpointSlot, EndpointRateLimit | None] = dict(
            endpoint_overrides or {},
        )
        config_kwargs = dict(
            _iter_auth_rate_limit_config_items(
                catalog=_AUTH_RATE_LIMIT_ENDPOINT_CATALOG,
                backend=backend,
                enabled=enabled,
                disabled=disabled,
                group_backends=group_backend_map,
                scope_overrides=scope_override_map,
                namespace_style=namespace_style,
                namespace_overrides=namespace_override_map,
                endpoint_overrides=endpoint_override_map,
                trusted_proxy=trusted_proxy,
                identity_fields=identity_fields,
                trusted_headers=trusted_headers,
            ),
        )

        return cls(**cast("Any", config_kwargs))


if tuple(field.name for field in fields(AuthRateLimitConfig)) != _AUTH_RATE_LIMIT_ENDPOINT_SLOTS:
    msg = "AuthRateLimitConfig fields must stay aligned with the private auth rate-limit endpoint catalog."
    raise RuntimeError(msg)
