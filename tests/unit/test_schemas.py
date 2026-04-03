"""Tests for msgspec auth payload schemas."""

from __future__ import annotations

import uuid
from typing import Annotated, Any, cast, get_args, get_origin, get_type_hints

import msgspec
import pytest

from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from litestar_auth.controllers.auth import _LOGIN_EMAIL_MAX_LENGTH, LoginCredentials, RefreshTokenRequest
from litestar_auth.controllers.reset import ForgotPassword, ResetPassword
from litestar_auth.controllers.totp import (
    TotpConfirmEnableRequest,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpVerifyRequest,
)
from litestar_auth.controllers.verify import RequestVerifyToken, VerifyToken
from litestar_auth.schemas import UserCreate, UserRead, UserUpdate

pytestmark = pytest.mark.unit


def _field_meta(schema_type: type[msgspec.Struct], field_name: str) -> msgspec.Meta:
    """Return the ``msgspec.Meta`` attached to a struct field annotation.

    Raises:
        AssertionError: If the field annotation does not expose ``msgspec.Meta``.
    """
    annotation = get_type_hints(schema_type, include_extras=True)[field_name]

    for candidate in (annotation, *get_args(annotation)):
        value = getattr(candidate, "__value__", candidate)
        if get_origin(value) is not Annotated:
            continue

        _, meta = get_args(value)
        return meta

    msg = f"{schema_type.__name__}.{field_name} is missing msgspec metadata."
    raise AssertionError(msg)


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


def test_user_create_accepts_password_at_configured_maximum() -> None:
    """UserCreate accepts passwords up to the configured maximum length."""
    password = "p" * MAX_PASSWORD_LENGTH

    payload = msgspec.json.decode(
        f'{{"email":"creator@example.com","password":"{password}"}}'.encode(),
        type=UserCreate,
    )

    assert payload == UserCreate(email="creator@example.com", password=password)


def test_user_create_rejects_password_longer_than_configured_maximum() -> None:
    """UserCreate rejects overlong passwords before hashing work starts."""
    password = "p" * (MAX_PASSWORD_LENGTH + 1)

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


@pytest.mark.parametrize("schema_type", [ForgotPassword, RequestVerifyToken])
def test_email_only_payloads_preserve_shared_email_validation(schema_type: type[msgspec.Struct]) -> None:
    """Email-only payloads keep the shared email pattern and length contract."""
    payload = cast(
        "Any",
        msgspec.json.decode(
            b'{"email":"person@example.com"}',
            type=schema_type,
        ),
    )

    assert payload.email == "person@example.com"

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(b'{"email":"not-an-email"}', type=schema_type)


def test_login_credentials_preserve_identifier_length_limits() -> None:
    """LoginCredentials keeps the shared identifier size contract."""
    identifier = "i" * _LOGIN_EMAIL_MAX_LENGTH

    payload = msgspec.json.decode(
        msgspec.json.encode({"identifier": identifier, "password": "correct-password"}),
        type=LoginCredentials,
    )

    assert payload.identifier == identifier

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode(
                {"identifier": "i" * (_LOGIN_EMAIL_MAX_LENGTH + 1), "password": "correct-password"},
            ),
            type=LoginCredentials,
        )


@pytest.mark.parametrize(
    ("schema_type", "field_name", "expected_min_length"),
    [
        (UserCreate, "password", DEFAULT_MINIMUM_PASSWORD_LENGTH),
        (UserUpdate, "password", DEFAULT_MINIMUM_PASSWORD_LENGTH),
        (LoginCredentials, "password", 1),
        (ResetPassword, "password", 1),
        (TotpEnableRequest, "password", 1),
    ],
)
def test_password_payload_metadata_tracks_runtime_password_policy(
    schema_type: type[msgspec.Struct],
    field_name: str,
    expected_min_length: int,
) -> None:
    """Password-bearing payload metadata stays aligned with config-level length constants."""
    metadata = _field_meta(schema_type, field_name)

    assert metadata.min_length == expected_min_length
    assert metadata.max_length == MAX_PASSWORD_LENGTH


@pytest.mark.parametrize(
    ("schema_type", "field_name", "other_fields", "max_length"),
    [
        (RefreshTokenRequest, "refresh_token", {}, 512),
        (VerifyToken, "token", {}, 2048),
        (ResetPassword, "token", {"password": "new-password"}, 2048),
        (TotpVerifyRequest, "pending_token", {"code": "123456"}, 2048),
        (TotpConfirmEnableRequest, "enrollment_token", {"code": "123456"}, 2048),
    ],
)
def test_token_payloads_preserve_shared_length_limits(
    schema_type: type[msgspec.Struct],
    field_name: str,
    other_fields: dict[str, str],
    max_length: int,
) -> None:
    """Token-bearing payloads keep their existing size limits."""
    token = "t" * max_length

    payload = msgspec.json.decode(
        msgspec.json.encode({field_name: token, **other_fields}),
        type=schema_type,
    )

    assert getattr(payload, field_name) == token

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({field_name: "t" * (max_length + 1), **other_fields}),
            type=schema_type,
        )


@pytest.mark.parametrize(
    ("schema_type", "other_fields"),
    [
        (LoginCredentials, {"identifier": "user@example.com"}),
        (ResetPassword, {"token": "valid-token"}),
        (TotpEnableRequest, {}),
    ],
)
def test_non_empty_password_payloads_preserve_shared_limits(
    schema_type: type[msgspec.Struct],
    other_fields: dict[str, str],
) -> None:
    """Auth lifecycle password payloads keep the shared non-empty maximum-length limit."""
    payload = cast(
        "Any",
        msgspec.json.decode(
            msgspec.json.encode({"password": "p" * MAX_PASSWORD_LENGTH, **other_fields}),
            type=schema_type,
        ),
    )

    assert payload.password == "p" * MAX_PASSWORD_LENGTH

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"password": "", **other_fields}),
            type=schema_type,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"password": "p" * (MAX_PASSWORD_LENGTH + 1), **other_fields}),
            type=schema_type,
        )


@pytest.mark.parametrize(
    ("schema_type", "other_fields"),
    [
        (TotpVerifyRequest, {"pending_token": "pending-token"}),
        (TotpConfirmEnableRequest, {"enrollment_token": "enrollment-token"}),
        (TotpDisableRequest, {}),
    ],
)
def test_totp_code_payloads_preserve_exact_length(
    schema_type: type[msgspec.Struct],
    other_fields: dict[str, str],
) -> None:
    """TOTP request payloads keep the six-character code contract."""
    payload = cast(
        "Any",
        msgspec.json.decode(
            msgspec.json.encode({"code": "123456", **other_fields}),
            type=schema_type,
        ),
    )

    assert payload.code == "123456"

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"code": "12345", **other_fields}),
            type=schema_type,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"code": "1234567", **other_fields}),
            type=schema_type,
        )
