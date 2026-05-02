"""Shared helpers for the configured superuser role name."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, cast

from litestar.exceptions import PermissionDeniedException

from litestar_auth._roles import normalize_role_name

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from litestar.connection import ASGIConnection

DEFAULT_SUPERUSER_ROLE_NAME = normalize_role_name("superuser")
SUPERUSER_ROLE_NAME_SENTINEL = "litestar_auth.superuser_role_name"

__all__ = (
    "DEFAULT_SUPERUSER_ROLE_NAME",
    "SUPERUSER_ROLE_NAME_SENTINEL",
    "normalize_superuser_role_name",
    "read_scope_superuser_role_name",
    "resolve_superuser_role_name",
    "set_scope_superuser_role_name",
)


def normalize_superuser_role_name(role_name: str) -> str:
    """Return the normalized superuser role name.

    Returns:
        The normalized role name.

    Raises:
        TypeError: If ``role_name`` is not a string.
        ValueError: If ``role_name`` normalizes to an empty value.
    """
    if not isinstance(role_name, str):
        msg = "superuser_role_name must be a string."
        raise TypeError(msg)

    try:
        return normalize_role_name(role_name)
    except ValueError as exc:
        msg = "superuser_role_name must be a non-empty role name."
        raise ValueError(msg) from exc


def resolve_superuser_role_name(source: object) -> str:
    """Return the normalized superuser role name configured on an object.

    ``LitestarAuthConfig`` and ``BaseUserManager`` both expose
    ``superuser_role_name``; objects without that attribute fall back to the
    canonical default.

    Returns:
        The normalized role name.
    """
    raw_role_name = getattr(source, "superuser_role_name", DEFAULT_SUPERUSER_ROLE_NAME)
    return normalize_superuser_role_name(cast("str", raw_role_name))


def set_scope_superuser_role_name(scope: object, source: object) -> None:
    """Store the resolved superuser role name on ASGI request scope state."""
    mutable_scope = cast("MutableMapping[str, Any]", scope)
    state = cast("MutableMapping[str, Any]", mutable_scope.setdefault("state", {}))
    state[SUPERUSER_ROLE_NAME_SENTINEL] = resolve_superuser_role_name(source)


def read_scope_superuser_role_name(connection: ASGIConnection[Any, Any, Any, Any]) -> str:
    """Return the normalized superuser role name from request scope state.

    Plugin-managed requests store the configured value in ``scope["state"]``. Direct
    guard usage outside the plugin falls back to the canonical default.

    Raises:
        PermissionDeniedException: When plugin state contains an invalid role name.
    """
    scope_state = connection.scope.get("state")
    if not isinstance(scope_state, Mapping):
        return DEFAULT_SUPERUSER_ROLE_NAME

    raw_role_name = scope_state.get(SUPERUSER_ROLE_NAME_SENTINEL, DEFAULT_SUPERUSER_ROLE_NAME)
    if not isinstance(raw_role_name, str):
        msg = "The configured superuser role name is invalid."
        raise PermissionDeniedException(detail=msg)

    try:
        return normalize_superuser_role_name(raw_role_name)
    except ValueError as exc:
        msg = "The configured superuser role name is invalid."
        raise PermissionDeniedException(detail=msg) from exc
