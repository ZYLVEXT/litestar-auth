"""LSA1-HMAC-SHA256 API-key request-signing helpers."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote, urlencode

from litestar_auth._keyed_digest import keyed_hex
from litestar_auth.exceptions import ErrorCode

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar.connection import ASGIConnection

API_KEY_HMAC_SCHEME = "LSA1-HMAC-SHA256"
API_KEY_HMAC_DATE_HEADER = "X-Auth-Date"
API_KEY_HMAC_NONCE_HEADER = "X-Auth-Nonce"
API_KEY_HMAC_BODY_SHA256_HEADER = "X-Auth-Content-SHA256"
API_KEY_SIGNED_BODY_SCOPE_KEY = "litestar_auth_body"

_SIGNING_REQUEST: contextvars.ContextVar[SignedApiKeyRequest | None] = contextvars.ContextVar(
    "litestar_auth_api_key_signing_request",
    default=None,
)
_MAX_NONCE_LENGTH = 128
_MAX_SIGNATURE_LENGTH = 256


@dataclass(frozen=True, slots=True)
class SignedApiKeyRequest:
    """Parsed HMAC API-key request carried from transport to strategy."""

    key_id: str
    signed_headers: tuple[str, ...]
    signature: str
    date: datetime
    nonce: str
    canonical_request: str


@dataclass(frozen=True, slots=True)
class _SignedAuthorizationParts:
    """Validated Authorization header components for signed API-key auth."""

    key_id: str
    signed_headers: tuple[str, ...]
    signature: str


@dataclass(frozen=True, slots=True)
class _RequiredSigningHeaders:
    """Validated signing headers required by signed API-key auth."""

    date: str
    nonce: str


def get_current_signed_api_key_request() -> SignedApiKeyRequest | None:
    """Return the signing request parsed for the current authentication attempt."""
    return _SIGNING_REQUEST.get()


def clear_current_signed_api_key_request() -> None:
    """Clear signing state for the current context."""
    _SIGNING_REQUEST.set(None)


def read_signed_api_key_request(connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
    """Parse ``Authorization: LSA1-HMAC-SHA256 ...`` and store canonical request context.

    Returns:
        The signing scheme marker when the request used signing auth, otherwise ``None``.
    """
    clear_current_signed_api_key_request()
    parsed_parameters = _read_signed_authorization_parameters(connection)
    if parsed_parameters is None:
        return None

    authorization_parts = _parse_signed_authorization_parts(parsed_parameters)
    if authorization_parts is None:
        return _reject_signed_api_key_request()

    signing_headers = _read_required_signing_headers(connection)
    signing_headers = _validate_required_signing_headers(signing_headers, authorization_parts.signed_headers)
    if signing_headers is None:
        return _reject_signed_api_key_request()

    date = _parse_request_datetime(signing_headers.date)
    if date is None:
        return _reject_signed_api_key_request()

    _store_signed_api_key_request(
        connection,
        authorization_parts=authorization_parts,
        date=date,
        nonce=signing_headers.nonce,
    )
    return API_KEY_HMAC_SCHEME


def _read_signed_authorization_parameters(
    connection: ASGIConnection[Any, Any, Any, Any],
) -> dict[str, str] | None:
    """Return parsed signed Authorization parameters when this request uses signing auth."""
    authorization = connection.headers.get("Authorization") or connection.headers.get("authorization")
    if authorization is None:
        return None
    scheme, _, parameters = authorization.partition(" ")
    if scheme != API_KEY_HMAC_SCHEME or not parameters:
        return None
    return _parse_authorization_parameters(parameters)


def _parse_signed_authorization_parts(parameters: Mapping[str, str]) -> _SignedAuthorizationParts | None:
    """Return validated signed Authorization components."""
    key_id = parameters.get("credential")
    signed_headers_value = parameters.get("signedheaders")
    signature = parameters.get("signature")
    authorization_parts = _validate_authorization_parts(
        key_id=key_id,
        signed_headers_value=signed_headers_value,
        signature=signature,
    )
    if authorization_parts is None:
        return None
    signed_headers = tuple(
        dict.fromkeys(
            header.strip().lower() for header in authorization_parts.signed_headers_value.split(";") if header.strip()
        ),
    )
    return _SignedAuthorizationParts(
        key_id=authorization_parts.key_id,
        signed_headers=signed_headers,
        signature=authorization_parts.signature,
    )


@dataclass(frozen=True, slots=True)
class _ValidatedAuthorizationParts:
    """Non-empty signed Authorization fields after validation."""

    key_id: str
    signed_headers_value: str
    signature: str


def _validate_authorization_parts(
    *,
    key_id: str | None,
    signed_headers_value: str | None,
    signature: str | None,
) -> _ValidatedAuthorizationParts | None:
    """Return validated string Authorization fields."""
    if key_id is None or signed_headers_value is None or signature is None:
        return None
    if _invalid_authorization_parts(key_id, signed_headers_value, signature):
        return None
    return _ValidatedAuthorizationParts(
        key_id=key_id,
        signed_headers_value=signed_headers_value,
        signature=signature,
    )


def _read_required_signing_headers(connection: ASGIConnection[Any, Any, Any, Any]) -> tuple[str | None, str | None]:
    """Return the required signed request date and nonce headers."""
    return connection.headers.get(API_KEY_HMAC_DATE_HEADER), connection.headers.get(API_KEY_HMAC_NONCE_HEADER)


def _validate_required_signing_headers(
    headers: tuple[str | None, str | None],
    signed_headers: tuple[str, ...],
) -> _RequiredSigningHeaders | None:
    """Return required signing headers after structural validation."""
    date_header, nonce = headers
    if date_header is None or nonce is None:
        return None
    if _invalid_required_signing_headers(date_header, nonce, signed_headers):
        return None
    return _RequiredSigningHeaders(date=date_header, nonce=nonce)


def _store_signed_api_key_request(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    authorization_parts: _SignedAuthorizationParts,
    date: datetime,
    nonce: str,
) -> None:
    """Store parsed signed request context for strategy verification."""
    canonical_request = build_canonical_request(connection, signed_headers=authorization_parts.signed_headers)
    _SIGNING_REQUEST.set(
        SignedApiKeyRequest(
            key_id=authorization_parts.key_id,
            signed_headers=authorization_parts.signed_headers,
            signature=authorization_parts.signature,
            date=date,
            nonce=nonce,
            canonical_request=canonical_request,
        ),
    )


def _reject_signed_api_key_request() -> str:
    """Clear parsed request context and return the signing scheme marker.

    Returns:
        The signed API-key scheme marker.
    """
    _SIGNING_REQUEST.set(None)
    return API_KEY_HMAC_SCHEME


def build_canonical_request(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    signed_headers: tuple[str, ...],
) -> str:
    """Build the LSA1 canonical request string.

    Returns:
        Newline-delimited canonical request components.
    """
    method = str(connection.scope.get("method", "")).upper()
    path = _canonical_path(connection.scope)
    query = _canonical_query_string(connection.scope.get("query_string", b""))
    headers = _canonical_headers(connection, signed_headers=signed_headers)
    body = connection.scope.get(API_KEY_SIGNED_BODY_SCOPE_KEY, b"")
    body_digest = hashlib.sha256(body if isinstance(body, bytes) else b"").hexdigest()
    return "\n".join((method, path, query, headers, ";".join(signed_headers), body_digest.lower()))


def sign_canonical_request(*, secret: str, canonical_request: str) -> str:
    """Return a hex HMAC-SHA-256 signature for a canonical request."""
    return keyed_hex(secret.encode("utf-8"), canonical_request.encode("utf-8"))


def signature_matches(*, secret: str, canonical_request: str, signature: str) -> bool:
    """Return whether ``signature`` matches the canonical request."""
    expected = sign_canonical_request(secret=secret, canonical_request=canonical_request)
    return hmac.compare_digest(expected, signature)


def classify_signed_request_skew(request: SignedApiKeyRequest, *, now: datetime, skew_seconds: int) -> ErrorCode | None:
    """Return the timestamp error code when a request falls outside the skew window."""
    if abs((now - request.date).total_seconds()) > skew_seconds:
        return ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW
    return None


def _parse_authorization_parameters(parameters: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_part in parameters.split(","):
        name, separator, value = raw_part.strip().partition("=")
        if separator:
            parsed[name.lower()] = value.strip()
    return parsed


def _parse_request_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00") if value.endswith("Z") else datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _canonical_path(scope: Mapping[str, Any]) -> str:
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, bytes):
        return quote(raw_path.decode("ascii", errors="surrogateescape"), safe="/~%-._")
    return quote(str(scope.get("path", "/")), safe="/~%-._")


def _canonical_query_string(raw_query_string: object) -> str:
    if isinstance(raw_query_string, bytes):
        query_string = raw_query_string.decode("utf-8")
    else:
        query_string = str(raw_query_string or "")
    pairs = parse_qsl(query_string, keep_blank_values=True, strict_parsing=False)
    return urlencode(sorted(pairs), doseq=True, quote_via=quote, safe="~")


def _canonical_headers(
    connection: ASGIConnection[Any, Any, Any, Any],
    *,
    signed_headers: tuple[str, ...],
) -> str:
    header_values: dict[str, list[str]] = {header_name: [] for header_name in signed_headers}
    for raw_name, raw_value in connection.scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        if name in header_values:
            header_values[name].append(" ".join(raw_value.decode("latin-1").strip().split()))
    return "\n".join(f"{name}:{','.join(header_values[name])}" for name in signed_headers)


def _invalid_authorization_parts(
    key_id: str | None,
    signed_headers_value: str | None,
    signature: str | None,
) -> bool:
    return (
        key_id is None
        or signed_headers_value is None
        or signature is None
        or not key_id
        or not signature
        or len(signature) > _MAX_SIGNATURE_LENGTH
    )


def _invalid_required_signing_headers(
    date_header: str | None,
    nonce: str | None,
    signed_headers: tuple[str, ...],
) -> bool:
    return (
        date_header is None
        or nonce is None
        or not nonce
        or len(nonce) > _MAX_NONCE_LENGTH
        or "host" not in signed_headers
        or API_KEY_HMAC_DATE_HEADER.lower() not in signed_headers
        or API_KEY_HMAC_NONCE_HEADER.lower() not in signed_headers
    )


__all__ = (
    "API_KEY_HMAC_BODY_SHA256_HEADER",
    "API_KEY_HMAC_DATE_HEADER",
    "API_KEY_HMAC_NONCE_HEADER",
    "API_KEY_HMAC_SCHEME",
    "API_KEY_SIGNED_BODY_SCOPE_KEY",
    "SignedApiKeyRequest",
    "build_canonical_request",
    "classify_signed_request_skew",
    "clear_current_signed_api_key_request",
    "get_current_signed_api_key_request",
    "read_signed_api_key_request",
    "sign_canonical_request",
    "signature_matches",
)
