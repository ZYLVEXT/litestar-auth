"""Internal helpers for normalized flat role membership."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable


def normalize_roles(roles: object) -> list[str]:
    """Return deterministic normalized role membership.

    Roles are trimmed, NFKC-normalized, lowercased, deduplicated, and sorted.

    Args:
        roles: Raw role input from user-facing payloads or ORM persistence.

    Returns:
        A normalized list of role names.

    Raises:
        TypeError: If the input is not an iterable of strings.
        ValueError: If any normalized role is empty.
    """
    if roles is None:
        return []
    if isinstance(roles, str):
        msg = "Roles must be provided as an iterable of non-empty strings."
        raise TypeError(msg)
    if not isinstance(roles, Iterable):
        msg = "Roles must be provided as an iterable of non-empty strings."
        raise TypeError(msg)

    normalized_roles: set[str] = set()
    for raw_role in roles:
        if not isinstance(raw_role, str):
            msg = "Roles must be provided as an iterable of non-empty strings."
            raise TypeError(msg)

        normalized_role = unicodedata.normalize("NFKC", raw_role.strip()).lower()
        if not normalized_role:
            msg = "Roles must be provided as an iterable of non-empty strings."
            raise ValueError(msg)
        normalized_roles.add(normalized_role)

    return sorted(normalized_roles)


def normalize_role_name(role: str) -> str:
    """Normalize one role name and return the scalar value.

    Returns:
        The normalized role name.
    """
    return normalize_roles((role,))[0]
