"""Rate-limit identity extraction helpers."""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import TYPE_CHECKING

from litestar_auth._schema_fields import EMAIL_MAX_LENGTH

if TYPE_CHECKING:
    from ._protocol import KnownRateLimitConnection


def _bounded_identity(value: str, *, max_length: int) -> str | None:
    """Return a non-empty identity value only when it fits the configured cap."""
    bounded_value = value.strip()
    if not bounded_value or len(bounded_value) > max_length:
        return None
    return bounded_value


async def _extract_email(
    request: KnownRateLimitConnection,
    *,
    identity_fields: tuple[str, ...] = ("identifier", "username", "email"),
) -> str | None:
    """Best-effort extraction of identifier from a JSON request body.

    Searches through ``identity_fields`` in order, returning the first
    non-empty string value found. Defaults to the login schema's
    ``identifier`` / ``username`` / ``email`` keys.

    Returns:
        The identifier in NFKC + lowercase canonical form so that case and
        Unicode-equivalent variants share a rate-limit bucket with the auth
        lookup performed by ``UserPolicy.normalize_email``. ``None`` when no
        non-empty identifier is found.
    """
    try:
        payload = await request.json()
    except (TypeError, ValueError):
        return None

    if not isinstance(payload, Mapping):
        return None

    payload_mapping = {key: value for key, value in payload.items() if isinstance(key, str)}
    for field_name in identity_fields:
        value = payload_mapping.get(field_name)
        if isinstance(value, str) and value.strip():
            bounded_value = _bounded_identity(value, max_length=EMAIL_MAX_LENGTH)
            if bounded_value is None:
                return None
            return unicodedata.normalize("NFKC", bounded_value).lower()
    return None
