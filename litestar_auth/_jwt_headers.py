"""Internal helpers for JWT JOSE header handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import jwt

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import timedelta

    from jwt.types import Options

EXPECTED_JWT_TYPE = "JWT"


@dataclass(frozen=True, slots=True)
class JwtDecodeConfig:
    """Configuration for signed JWT decode after JOSE header validation."""

    key: str | bytes
    algorithms: Sequence[str]
    audience: str
    options: Options
    issuer: str | None = None
    leeway: float | timedelta = 0


def jwt_encode_headers() -> dict[str, str]:
    """Return JOSE headers for JWTs issued by this package."""
    return {"typ": EXPECTED_JWT_TYPE}


def validate_jwt_type_header(token: str) -> None:
    """Validate the unverified JOSE ``typ`` header before signed JWT decode.

    Raises:
        jwt.InvalidTokenError: If the token is malformed or its ``typ`` header
            is missing or not exactly ``JWT``.
    """
    header = jwt.get_unverified_header(token)
    token_type = header.get("typ")
    if token_type != EXPECTED_JWT_TYPE:
        msg = "Invalid JWT type header"
        raise jwt.InvalidTokenError(msg)


def decode_signed_jwt(
    token: str,
    *,
    config: JwtDecodeConfig,
) -> dict[str, object]:
    """Validate the JOSE ``typ`` header, then decode a signed JWT.

    Returns:
        Decoded JWT claims.
    """
    validate_jwt_type_header(token)
    return jwt.decode(
        token,
        config.key,
        algorithms=config.algorithms,
        audience=config.audience,
        options=config.options,
        issuer=config.issuer,
        leeway=config.leeway,
    )
