"""Unit tests for shared opaque-token strategy primitives."""

from __future__ import annotations

import pytest

from litestar_auth.authentication.strategy import _opaque_tokens as opaque_tokens_module
from litestar_auth.authentication.strategy._opaque_tokens import (
    MIN_TOKEN_BYTES,
    build_opaque_token_key,
    digest_opaque_token,
    mint_opaque_token,
    validate_token_bytes,
)
from litestar_auth.exceptions import ConfigurationError

pytestmark = pytest.mark.unit
SHA256_HEX_DIGEST_LENGTH = 64


def test_digest_opaque_token_matches_existing_hmac_sha256_contract() -> None:
    """Opaque-token digests should remain stable for existing persisted tokens."""
    digest = digest_opaque_token(
        token_hash_secret=b"redis-token-hash-secret-1234567890",
        token="token-write",
    )

    assert digest == "230d559b9628a64d84235938949c717091b338e14d29d54623dca331d1423722"


def test_build_opaque_token_key_prefixes_digest_without_leaking_raw_token() -> None:
    """Redis token keys should be prefix plus digest, not the raw token."""
    token_key = build_opaque_token_key(
        key_prefix="litestar_auth:token:",
        token_hash_secret=b"redis-token-hash-secret-1234567890",
        token="token-write",
    )

    assert token_key == ("litestar_auth:token:230d559b9628a64d84235938949c717091b338e14d29d54623dca331d1423722")
    assert "token-write" not in token_key


def test_mint_opaque_token_returns_raw_token_and_existing_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minting should pair the generated token with the existing HMAC-SHA256 digest."""
    monkeypatch.setattr(opaque_tokens_module.secrets, "token_urlsafe", lambda token_bytes: f"raw-{token_bytes}")

    token, token_digest = mint_opaque_token(
        token_bytes=32,
        token_hash_secret=b"redis-token-hash-secret-1234567890",
    )

    assert token == "raw-32"
    assert token_digest == digest_opaque_token(
        token_hash_secret=b"redis-token-hash-secret-1234567890",
        token="raw-32",
    )
    assert len(token_digest) == SHA256_HEX_DIGEST_LENGTH


def test_validate_token_bytes_accepts_minimum_value() -> None:
    """At-or-above the floor passes silently."""
    validate_token_bytes(MIN_TOKEN_BYTES, label="DatabaseTokenStrategy")


def test_validate_token_bytes_rejects_below_minimum() -> None:
    """Below the 128-bit floor must surface an actionable ConfigurationError."""
    with pytest.raises(ConfigurationError, match="token_bytes=8 is below the minimum of 16"):
        validate_token_bytes(MIN_TOKEN_BYTES - 8, label="DatabaseTokenStrategy")
