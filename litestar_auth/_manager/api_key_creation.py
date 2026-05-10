"""API-key creation input contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Required, TypedDict

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime


class ApiKeyCreateOptions(TypedDict, total=False):
    """Keyword options accepted by API-key creation methods."""

    name: Required[str]
    scopes: Sequence[str]
    current_password: str | None
    expires_at: datetime | None
    signing_required: bool
    created_via: str
    client_metadata: dict[str, str] | None


@dataclass(frozen=True, slots=True)
class ApiKeyCreateInput:
    """Normalized API-key creation inputs."""

    name: str
    scopes: Sequence[str] = ()
    current_password: str | None = None
    expires_at: datetime | None = None
    signing_required: bool = False
    created_via: str = "manager"
    client_metadata: dict[str, str] | None = None


def coerce_api_key_create_options(options: ApiKeyCreateOptions) -> ApiKeyCreateInput:
    """Return creation options with manager defaults applied.

    Raises:
        TypeError: If the required ``name`` keyword is missing.
    """
    try:
        name = options["name"]
    except KeyError as exc:
        msg = "create_api_key() missing required keyword argument: 'name'"
        raise TypeError(msg) from exc
    return ApiKeyCreateInput(
        name=name,
        scopes=options.get("scopes", ()),
        current_password=options.get("current_password"),
        expires_at=options.get("expires_at"),
        signing_required=options.get("signing_required", False),
        created_via=options.get("created_via", "manager"),
        client_metadata=options.get("client_metadata"),
    )
