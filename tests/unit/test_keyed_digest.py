"""Tests for private keyed digest helpers."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from litestar_auth._keyed_digest import keyed_bytes, keyed_hex

pytestmark = pytest.mark.unit


def test_keyed_hex_matches_legacy_single_payload_hmac_expression() -> None:
    """Hex helper output must preserve persisted token and fingerprint digests."""
    key = b"shared-keyed-digest-secret"
    payload = b"user-id\x1femail@example.test\x1fhashed-password"

    assert keyed_hex(key, payload) == hmac.new(key, payload, hashlib.sha256).hexdigest()


def test_keyed_hex_matches_legacy_incremental_hmac_expression() -> None:
    """Multiple payload parts should match direct incremental HMAC updates."""
    key = b"shared-keyed-digest-secret"
    parts = (b"GET", b"\n", b"/api/resource", b"\n", b"a=1")
    legacy_digest = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        legacy_digest.update(part)

    assert keyed_hex(key, *parts) == legacy_digest.hexdigest()


def test_keyed_bytes_matches_legacy_hmac_digest_expression() -> None:
    """Bytes helper output must preserve stored API-key secret digests."""
    key = b"api-key-hash-secret"
    payload = b"api-key-secret"

    assert keyed_bytes(key, payload) == hmac.new(key, payload, hashlib.sha256).digest()
