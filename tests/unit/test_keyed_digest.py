"""Tests for private keyed digest helpers."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from litestar_auth._keyed_digest import hkdf_sha256_32, keyed_bytes, keyed_hex

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


def test_hkdf_sha256_32_matches_rfc5869_first_output_block() -> None:
    """HKDF helper should match RFC 5869 extract/expand output for one SHA-256 block."""
    key_material = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    assert (
        hkdf_sha256_32(key_material, salt=salt, info=info).hex()
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    )
