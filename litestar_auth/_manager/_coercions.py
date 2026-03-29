"""Shared coercion helpers for internal manager services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import msgspec

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth._manager._protocols import AccountStateUserProtocol, ManagedUserProtocol


def _as_dict(data: msgspec.Struct | Mapping[str, Any]) -> dict[str, Any]:
    """Convert msgspec structs and mappings into plain dictionaries.

    Returns:
        A plain dictionary representation of the input data.

    Raises:
        TypeError: If a msgspec struct converts to a non-dict value.
    """
    if isinstance(data, msgspec.Struct):
        built = msgspec.to_builtins(data)
        if not isinstance(built, dict):
            msg = "msgspec struct conversion must yield a dict"
            raise TypeError(msg)
        return {str(k): v for k, v in built.items()}

    return dict(data)


def _require_str(data: Mapping[str, Any], field_name: str) -> str:
    """Read a required string field from a payload mapping.

    Returns:
        The string value stored under the requested field.

    Raises:
        TypeError: If the field is missing or not a string.
    """
    value = data.get(field_name)
    if isinstance(value, str):
        return value

    msg = f"{field_name} must be a string"
    raise TypeError(msg)


def _managed_user[UP](user: UP) -> ManagedUserProtocol:
    """Cast a generic user into the protocol required by manager internals.

    ``cast`` is required: ``UP`` is not bounded to ``ManagedUserProtocol`` at the
    manager facade, but runtime user objects satisfy the structural protocol.

    Returns:
        A protocol view exposing the fields used by the manager.
    """
    return cast("ManagedUserProtocol", user)


def _account_state_user[UP](user: UP) -> AccountStateUserProtocol:
    """Cast a generic user into the protocol required by account-state checks.

    ``cast`` is required for the same structural reason as ``_managed_user``.

    Returns:
        A protocol view exposing the fields used by account-state validation.
    """
    return cast("AccountStateUserProtocol", user)
