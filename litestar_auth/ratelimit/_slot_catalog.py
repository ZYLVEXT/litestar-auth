"""Private auth rate-limit slot catalog metadata."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable

type AuthRateLimitEndpointGroup = Literal["login", "password_reset", "refresh", "register", "totp", "verification"]
type _RecipeScope = Literal["ip", "ip_email"]

_AUTH_RATE_LIMIT_NAMESPACE_STYLES = frozenset({"route", "snake_case"})
_MISSING_OVERRIDE = object()


class _BuilderNamesValidator(Protocol):
    """Validator callback supplied by the config builder."""

    def __call__[NameT: str](
        self,
        names: Iterable[NameT],
        *,
        allowed: frozenset[NameT],
        parameter_name: str,
        item_name: str,
    ) -> None: ...


class AuthRateLimitSlot(StrEnum):
    """IDE-friendly enum of supported auth rate-limit endpoint slots."""

    LOGIN = auto()
    # Dedicated credential-rotation slot so operators can tune stolen-session re-verification separately from login.
    CHANGE_PASSWORD = auto()
    REFRESH = auto()
    REGISTER = auto()
    FORGOT_PASSWORD = auto()
    RESET_PASSWORD = auto()
    TOTP_ENABLE = auto()
    TOTP_CONFIRM_ENABLE = auto()
    TOTP_VERIFY = auto()
    TOTP_DISABLE = auto()
    TOTP_REGENERATE_RECOVERY_CODES = auto()
    VERIFY_TOKEN = auto()
    REQUEST_VERIFY_TOKEN = auto()


@dataclass(slots=True, frozen=True)
class _AuthRateLimitEndpointRecipe:
    """Package-owned metadata for a supported auth rate-limit slot."""

    slot: AuthRateLimitSlot
    default_scope: _RecipeScope
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

    def validate_slot_names(
        self,
        names: Iterable[AuthRateLimitSlot],
        *,
        parameter_name: str,
        validator: _BuilderNamesValidator,
    ) -> None:
        """Validate slot-keyed builder inputs against the private catalog."""
        validator(
            names,
            allowed=self.slot_set,
            parameter_name=parameter_name,
            item_name="auth rate-limit slots",
        )

    def validate_group_names(
        self,
        names: Iterable[AuthRateLimitEndpointGroup],
        *,
        parameter_name: str,
        validator: _BuilderNamesValidator,
    ) -> None:
        """Validate group-keyed builder inputs against the private catalog."""
        validator(
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
