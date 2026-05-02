"""Tests for internal JWT JOSE header helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from litestar_auth._jwt_headers import (
    EXPECTED_JWT_TYPE,
    JwtDecodeConfig,
    decode_signed_jwt,
    jwt_encode_headers,
    validate_jwt_type_header,
)

pytestmark = pytest.mark.unit

_SECRET = "jwt-header-test-secret-1234567890"


def _payload() -> dict[str, object]:
    issued_at = datetime.now(tz=UTC)
    return {
        "sub": "user-1",
        "aud": "litestar-auth:test",
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(minutes=5),
        "jti": "jwt-header-test-jti",
    }


def _token_with_headers(headers: dict[str, str | None]) -> str:
    return jwt.encode(_payload(), _SECRET, algorithm="HS256", headers=headers)


def test_jwt_encode_headers_returns_expected_typ_header() -> None:
    """Encode headers advertise the package-issued token type."""
    assert jwt_encode_headers() == {"typ": EXPECTED_JWT_TYPE}


def test_jwt_encode_headers_returns_fresh_mapping() -> None:
    """Callers cannot mutate a shared global headers mapping."""
    first_headers = jwt_encode_headers()
    first_headers["typ"] = "not-jwt"

    assert jwt_encode_headers() == {"typ": EXPECTED_JWT_TYPE}


def test_validate_jwt_type_header_accepts_expected_typ() -> None:
    """A token carrying ``typ=JWT`` passes header preflight."""
    token = _token_with_headers({"typ": EXPECTED_JWT_TYPE})

    validate_jwt_type_header(token)


def test_validate_jwt_type_header_rejects_unexpected_typ() -> None:
    """A signed token for another JWT type fails before claim validation."""
    token = _token_with_headers({"typ": "not-jwt"})

    with pytest.raises(jwt.InvalidTokenError, match="Invalid JWT type header"):
        validate_jwt_type_header(token)


def test_validate_jwt_type_header_rejects_missing_typ() -> None:
    """Missing ``typ`` is fail-closed for package-managed JWT surfaces."""
    token = _token_with_headers({"typ": None})

    with pytest.raises(jwt.InvalidTokenError, match="Invalid JWT type header"):
        validate_jwt_type_header(token)


def test_validate_jwt_type_header_rejects_malformed_token() -> None:
    """Malformed input keeps PyJWT's invalid-token exception surface."""
    with pytest.raises(jwt.InvalidTokenError):
        validate_jwt_type_header("not-a-jwt")


def test_decode_signed_jwt_accepts_expected_typ() -> None:
    """Signed decode validates ``typ=JWT`` before returning claims."""
    token = _token_with_headers({"typ": EXPECTED_JWT_TYPE})

    payload = decode_signed_jwt(
        token,
        config=JwtDecodeConfig(
            key=_SECRET,
            algorithms=["HS256"],
            audience="litestar-auth:test",
            options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
        ),
    )

    assert payload["sub"] == "user-1"


def test_decode_signed_jwt_rejects_missing_typ_before_claim_decode() -> None:
    """The combined helper preserves the fail-closed missing-``typ`` branch."""
    token = _token_with_headers({"typ": None})

    with pytest.raises(jwt.InvalidTokenError, match="Invalid JWT type header"):
        decode_signed_jwt(
            token,
            config=JwtDecodeConfig(
                key=_SECRET,
                algorithms=["HS256"],
                audience="wrong-audience",
                options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
            ),
        )
