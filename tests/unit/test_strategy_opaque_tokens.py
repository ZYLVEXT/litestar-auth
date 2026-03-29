"""Unit tests for shared opaque-token strategy primitives."""

from __future__ import annotations

import pytest

from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key, digest_opaque_token

pytestmark = pytest.mark.unit


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
