"""Tests for msgspec user schemas."""

from __future__ import annotations

import uuid

import msgspec
import pytest

from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH
from litestar_auth.schemas import UserCreate, UserRead, UserUpdate

pytestmark = pytest.mark.unit


def test_user_read_round_trips_without_sensitive_fields() -> None:
    """UserRead serializes only public user data."""
    user_id = uuid.uuid4()
    payload = UserRead(
        id=user_id,
        email="reader@example.com",
        is_active=True,
        is_verified=False,
        is_superuser=False,
    )

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=UserRead)

    assert decoded == payload
    assert b"hashed_password" not in encoded
    assert b"totp_secret" not in encoded


def test_user_create_decodes_plain_text_password_payload() -> None:
    """UserCreate accepts the expected registration fields."""
    payload = msgspec.json.decode(
        b'{"email":"creator@example.com","password":"plain-text-password"}',
        type=UserCreate,
    )

    assert payload == UserCreate(email="creator@example.com", password="plain-text-password")


def test_user_create_accepts_128_character_password() -> None:
    """UserCreate accepts passwords up to the tightened 128-character limit."""
    password = "p" * 128

    payload = msgspec.json.decode(
        f'{{"email":"creator@example.com","password":"{password}"}}'.encode(),
        type=UserCreate,
    )

    assert payload == UserCreate(email="creator@example.com", password=password)


def test_user_create_rejects_password_longer_than_128_characters() -> None:
    """UserCreate rejects overlong passwords before hashing work starts."""
    password = "p" * 129

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            f'{{"email":"creator@example.com","password":"{password}"}}'.encode(),
            type=UserCreate,
        )


def test_user_create_rejects_password_shorter_than_config_default_minimum() -> None:
    """UserCreate enforces the configured default minimum password length."""
    password = "p" * (DEFAULT_MINIMUM_PASSWORD_LENGTH - 1)

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            f'{{"email":"creator@example.com","password":"{password}"}}'.encode(),
            type=UserCreate,
        )


def test_user_update_omits_unset_optional_fields() -> None:
    """UserUpdate excludes defaulted optional fields from serialized output."""
    payload = UserUpdate(email="updated@example.com", is_verified=True)

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=UserUpdate)

    assert decoded == payload
    assert encoded == b'{"email":"updated@example.com","is_verified":true}'
