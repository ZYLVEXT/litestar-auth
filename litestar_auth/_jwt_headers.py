"""Internal helpers for JWT JOSE header handling."""

from __future__ import annotations

import jwt

EXPECTED_JWT_TYPE = "JWT"


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
