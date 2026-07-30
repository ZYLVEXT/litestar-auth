"""Tests for private keyed digest helpers."""

from __future__ import annotations

import pytest

from litestar_auth._keyed_digest import hkdf_sha256_32

pytestmark = pytest.mark.unit


def test_hkdf_sha256_32_matches_rfc5869_first_output_block() -> None:
    """HKDF helper should match RFC 5869 extract/expand output for one SHA-256 block."""
    key_material = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")

    assert (
        hkdf_sha256_32(key_material, salt=salt, info=info).hex()
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    )
