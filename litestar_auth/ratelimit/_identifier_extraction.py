"""Rate-limit identity extraction helpers."""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import TYPE_CHECKING

from litestar_auth._schema_fields import EMAIL_MAX_LENGTH
from litestar_auth.authentication.strategy._api_key_format import parse_api_key
from litestar_auth.authentication.strategy.api_key import ApiKeyContext
from litestar_auth.authentication.transport.api_key import API_KEY_HEADER_NAME

if TYPE_CHECKING:
    from ._protocol import KnownRateLimitConnection

_API_KEY_HMAC_SCHEME = "LSA1-HMAC-SHA256"
_API_KEY_ID_LENGTH = 64


def _bounded_identity(value: str, *, max_length: int) -> str | None:
    """Return a non-empty identity value only when it fits the configured cap."""
    bounded_value = value.strip()
    if not bounded_value or len(bounded_value) > max_length:
        return None
    return bounded_value


def _extract_api_key_id(request: KnownRateLimitConnection) -> str | None:
    """Return a resolvable API-key id from bearer or X-API-Key credentials."""
    scope = getattr(request, "scope", None)
    if isinstance(scope, dict):
        auth_context = scope.get("auth")
        if isinstance(auth_context, ApiKeyContext):
            return _bounded_identity(auth_context.key_id, max_length=_API_KEY_ID_LENGTH)
    token = _extract_api_key_token(request)
    if token is None:
        return None
    parsed = parse_api_key(token)
    if parsed is None:
        return None
    return _bounded_identity(parsed.key_id, max_length=_API_KEY_ID_LENGTH)


def _extract_api_key_token(request: KnownRateLimitConnection) -> str | None:
    """Return the raw bearer or X-API-Key credential from the request."""
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            return token.strip() or None

    header_token = request.headers.get(API_KEY_HEADER_NAME)
    if header_token is None:
        return None
    return header_token.strip() or None


def _has_hmac_api_key_authorization(request: KnownRateLimitConnection) -> bool:
    """Return whether the request used the signed API-key authorization scheme."""
    authorization = request.headers.get("Authorization")
    if authorization is None:
        return False
    scheme, _, _parameters = authorization.partition(" ")
    return scheme == _API_KEY_HMAC_SCHEME


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
