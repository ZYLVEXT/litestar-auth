"""Tests for msgspec auth payload schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, cast, get_args, get_origin, get_type_hints

import msgspec
import pytest

import litestar_auth._schema_fields as schema_fields_module
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from litestar_auth.controllers._auth_helpers import _LOGIN_EMAIL_MAX_LENGTH
from litestar_auth.controllers.auth import LoginCredentials, RefreshTokenRequest
from litestar_auth.controllers.reset import ForgotPassword, ResetPassword
from litestar_auth.controllers.totp import (
    TotpConfirmEnableRequest,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpVerifyRequest,
)
from litestar_auth.controllers.verify import RequestVerifyToken, VerifyToken
from litestar_auth.payloads import (
    ApiKeyAdminCreateRequest,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyListResponse,
    ApiKeyRead,
    ApiKeyUpdateRequest,
    RefreshSessionListResponse,
    RefreshSessionRead,
)
from litestar_auth.schemas import AdminUserUpdate, UserCreate, UserEmailField, UserPasswordField, UserRead, UserUpdate

pytestmark = pytest.mark.unit


class CustomRegistrationSchema(msgspec.Struct, forbid_unknown_fields=True):
    """Custom registration payload reusing the canonical public user schema helpers."""

    email: UserEmailField
    password: UserPasswordField
    display_name: str


def _annotation_meta(annotation: object, *, label: str) -> msgspec.Meta:
    """Return the ``msgspec.Meta`` attached to an annotation or type alias.

    Raises:
        AssertionError: If the annotation does not expose ``msgspec.Meta``.
    """
    for candidate in (annotation, *get_args(annotation)):
        value = getattr(candidate, "__value__", candidate)
        if get_origin(value) is not Annotated:
            continue

        _, meta = get_args(value)
        return meta

    msg = f"{label} is missing msgspec metadata."
    raise AssertionError(msg)


def _field_meta(schema_type: type[msgspec.Struct], field_name: str) -> msgspec.Meta:
    """Return the ``msgspec.Meta`` attached to a struct field annotation."""
    return _annotation_meta(
        get_type_hints(schema_type, include_extras=True)[field_name],
        label=f"{schema_type.__name__}.{field_name}",
    )


def test_user_read_round_trips_without_sensitive_fields() -> None:
    """UserRead serializes only public user data."""
    user_id = uuid.uuid4()
    payload = UserRead(
        id=user_id,
        email="reader@example.com",
        is_active=True,
        is_verified=False,
        roles=["member"],
    )

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=UserRead)

    assert decoded == payload
    assert b"hashed_password" not in encoded
    assert b"totp_secret" not in encoded
    assert b'"roles":["member"]' in encoded


def test_user_read_field_order_uses_roles_as_authorization_surface() -> None:
    """UserRead keeps the public positional field order for the role-based API surface."""
    assert UserRead.__struct_fields__ == ("id", "email", "is_active", "is_verified", "roles")


def test_refresh_session_list_response_round_trips_without_token_details() -> None:
    """Refresh session responses expose public ids and bounded metadata, never token material."""
    created_at = datetime(2026, 5, 9, 1, 20, tzinfo=UTC)
    last_used_at = datetime(2026, 5, 9, 1, 25, tzinfo=UTC)
    payload = RefreshSessionListResponse(
        sessions=[
            RefreshSessionRead(
                session_id="a4ff5e6a-60f8-4a8e-9684-7239150fd91b",
                created_at=created_at,
                last_used_at=last_used_at,
                is_current=True,
                client_metadata={"user_agent": "LitestarAuth Test/1.0"},
            ),
            RefreshSessionRead(
                session_id="5f9bbfbf-d2db-4614-a8ea-17df6d66b60d",
                created_at=created_at,
            ),
        ],
    )

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=RefreshSessionListResponse)

    assert decoded == payload
    assert b'"session_id":"a4ff5e6a-60f8-4a8e-9684-7239150fd91b"' in encoded
    assert b'"is_current":true' in encoded
    assert b'"client_metadata":{"user_agent":"LitestarAuth Test/1.0"}' in encoded
    assert b"refresh_token" not in encoded
    assert b"token_digest" not in encoded
    assert b"access_token" not in encoded


def test_refresh_session_metadata_rejects_unbounded_values() -> None:
    """Session client metadata keeps the documented bounded string contract."""
    oversized_user_agent = "x" * 256
    body = msgspec.json.encode(
        {
            "sessions": [
                {
                    "session_id": "session-id",
                    "created_at": "2026-05-09T01:20:00Z",
                    "client_metadata": {"user_agent": oversized_user_agent},
                },
            ],
        },
    )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(body, type=RefreshSessionListResponse)


def test_api_key_payloads_round_trip_without_secret_in_metadata() -> None:
    """API-key read/list payloads expose metadata without raw credential material."""
    created_at = datetime(2026, 5, 9, 12, 0, tzinfo=UTC)
    read = ApiKeyRead(
        key_id="akid_public",
        name="CLI",
        scopes=["read"],
        prefix_env="prod",
        created_at=created_at,
    )
    response = ApiKeyCreateResponse(api_key="ak_prod_akid_public.raw-secret", key=read)

    encoded_create = msgspec.json.encode(response)
    encoded_list = msgspec.json.encode(ApiKeyListResponse(api_keys=[read]))

    assert msgspec.json.decode(encoded_create, type=ApiKeyCreateResponse) == response
    assert msgspec.json.decode(encoded_list, type=ApiKeyListResponse).api_keys == [read]
    assert b"raw-secret" in encoded_create
    assert b"raw-secret" not in encoded_list


def test_api_key_create_and_update_payloads_are_strict() -> None:
    """API-key mutation payloads reject unknown fields and malformed scopes."""
    create = msgspec.json.decode(
        b'{"name":"CLI","current_password":"secret","scopes":["read:users"]}',
        type=ApiKeyCreateRequest,
    )
    admin_create = msgspec.json.decode(
        b'{"name":"Admin CLI","scopes":["read:users"]}',
        type=ApiKeyAdminCreateRequest,
    )
    create_without_password = msgspec.json.decode(
        b'{"name":"CLI","scopes":["read:users"]}',
        type=ApiKeyCreateRequest,
    )
    update = msgspec.json.decode(
        b'{"name":"Renamed","current_password":"secret","scopes":["write-users"]}',
        type=ApiKeyUpdateRequest,
    )

    assert create.name == "CLI"
    assert admin_create.name == "Admin CLI"
    assert create_without_password.current_password is None
    assert update.name == "Renamed"
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"name":"Admin CLI","current_password":"target-password","scopes":["read:users"]}',
            type=ApiKeyAdminCreateRequest,
        )
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"name":"CLI","current_password":"secret","deprecated":true}',
            type=ApiKeyCreateRequest,
        )
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"current_password":"secret","scopes":["bad scope"]}',
            type=ApiKeyUpdateRequest,
        )


def test_user_update_field_order_uses_roles_as_authorization_surface() -> None:
    """UserUpdate keeps the public update fields for the role-based API surface."""
    assert UserUpdate.__struct_fields__ == ("email", "current_password", "totp_code")


def test_admin_user_update_field_order_matches_user_update_surface() -> None:
    """AdminUserUpdate preserves the current privileged update surface."""
    assert AdminUserUpdate.__struct_fields__ == ("password", "email", "is_active", "is_verified", "roles")


def test_user_create_decodes_plain_text_password_payload() -> None:
    """UserCreate accepts the expected registration fields."""
    payload = msgspec.json.decode(
        b'{"email":"creator@example.com","password":"plain-text-password"}',
        type=UserCreate,
    )

    assert payload == UserCreate(email="creator@example.com", password="plain-text-password")


def test_user_create_rejects_unknown_fields() -> None:
    """Built-in registration schema rejects undeclared fields."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"email":"creator@example.com","password":"plain-text-password","deprecated_admin_flag":true}',
            type=UserCreate,
        )


def test_user_update_rejects_unknown_fields() -> None:
    """Built-in update schema rejects undeclared fields."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"email":"updated@example.com","deprecated_admin_flag":true}',
            type=UserUpdate,
        )


def test_user_update_rejects_password_field() -> None:
    """Built-in self-update schema no longer accepts password rotation."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"password":"plain-text-password"}',
            type=UserUpdate,
        )


def test_admin_user_update_round_trips_with_all_none_defaults() -> None:
    """AdminUserUpdate can be instantiated empty and converted back from builtins."""
    payload = AdminUserUpdate()
    builtins = msgspec.to_builtins(payload)

    assert builtins == {}
    assert msgspec.convert(builtins, type=AdminUserUpdate) == payload


def test_admin_user_update_rejects_unknown_fields() -> None:
    """AdminUserUpdate keeps strict request decoding for privileged writes."""
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            b'{"email":"updated@example.com","deprecated_admin_flag":true}',
            type=AdminUserUpdate,
        )


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


def test_custom_registration_schema_reuses_public_email_and_password_contract() -> None:
    """Custom registration schemas can reuse the canonical public user field aliases."""
    payload = msgspec.json.decode(
        msgspec.json.encode(
            {
                "email": "creator@example.com",
                "password": "p" * DEFAULT_MINIMUM_PASSWORD_LENGTH,
                "display_name": "Creator",
            },
        ),
        type=CustomRegistrationSchema,
    )

    assert payload.password == "p" * DEFAULT_MINIMUM_PASSWORD_LENGTH

    max_payload = msgspec.json.decode(
        msgspec.json.encode(
            {
                "email": "creator@example.com",
                "password": "p" * MAX_PASSWORD_LENGTH,
                "display_name": "Creator",
            },
        ),
        type=CustomRegistrationSchema,
    )

    assert max_payload.password == "p" * MAX_PASSWORD_LENGTH

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode(
                {
                    "email": "not-an-email",
                    "password": "p" * DEFAULT_MINIMUM_PASSWORD_LENGTH,
                    "display_name": "Creator",
                },
            ),
            type=CustomRegistrationSchema,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode(
                {
                    "email": "creator@example.com",
                    "password": "p" * (DEFAULT_MINIMUM_PASSWORD_LENGTH - 1),
                    "display_name": "Creator",
                },
            ),
            type=CustomRegistrationSchema,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode(
                {
                    "email": "creator@example.com",
                    "password": "p" * (MAX_PASSWORD_LENGTH + 1),
                    "display_name": "Creator",
                },
            ),
            type=CustomRegistrationSchema,
        )


def test_builtin_and_custom_password_fields_reuse_public_alias() -> None:
    """Built-in and app-owned schemas reuse the same public password field alias."""
    admin_update_annotation = get_type_hints(AdminUserUpdate, include_extras=True)["password"]
    create_annotation = get_type_hints(UserCreate, include_extras=True)["password"]
    custom_annotation = get_type_hints(CustomRegistrationSchema, include_extras=True)["password"]
    password_field_value = getattr(UserPasswordField, "__value__", UserPasswordField)

    assert (
        getattr(get_args(admin_update_annotation)[0], "__value__", get_args(admin_update_annotation)[0])
        == password_field_value
    )
    assert get_args(admin_update_annotation)[1] is type(None)
    assert getattr(create_annotation, "__value__", create_annotation) == password_field_value
    assert getattr(custom_annotation, "__value__", custom_annotation) == password_field_value


def test_builtin_and_custom_email_fields_reuse_public_alias() -> None:
    """Built-in and app-owned schemas reuse the same public email field alias."""
    admin_update_annotation = get_type_hints(AdminUserUpdate, include_extras=True)["email"]
    create_annotation = get_type_hints(UserCreate, include_extras=True)["email"]
    update_annotation = get_type_hints(UserUpdate, include_extras=True)["email"]
    custom_annotation = get_type_hints(CustomRegistrationSchema, include_extras=True)["email"]
    email_field_value = getattr(UserEmailField, "__value__", UserEmailField)

    assert (
        getattr(get_args(admin_update_annotation)[0], "__value__", get_args(admin_update_annotation)[0])
        == email_field_value
    )
    assert get_args(admin_update_annotation)[1] is type(None)
    assert getattr(create_annotation, "__value__", create_annotation) == email_field_value
    assert getattr(custom_annotation, "__value__", custom_annotation) == email_field_value
    assert getattr(get_args(update_annotation)[0], "__value__", get_args(update_annotation)[0]) == email_field_value
    assert get_args(update_annotation)[1] is type(None)


def test_public_password_alias_reuses_internal_metadata_source() -> None:
    """The public password alias keeps the shared internal ``msgspec.Meta`` contract."""
    public_meta = _annotation_meta(UserPasswordField, label="UserPasswordField")
    internal_meta = _annotation_meta(
        schema_fields_module.UserPasswordField,
        label="litestar_auth._schema_fields.UserPasswordField",
    )

    assert public_meta is internal_meta


def test_public_email_alias_reuses_internal_metadata_source() -> None:
    """The public email alias keeps the shared internal ``msgspec.Meta`` contract."""
    public_meta = _annotation_meta(UserEmailField, label="UserEmailField")
    internal_meta = _annotation_meta(
        schema_fields_module.EmailField,
        label="litestar_auth._schema_fields.EmailField",
    )

    assert public_meta is internal_meta


def test_user_update_omits_unset_optional_fields() -> None:
    """UserUpdate excludes defaulted optional fields from serialized output.

    The self-service self-update schema accepts email plus optional
    current-password proof (privileged fields belong on AdminUserUpdate);
    ``omit_defaults=True`` plus the empty payload below proves no defaulted
    fields leak into encoded output.
    """
    payload = UserUpdate(email="updated@example.com")

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=UserUpdate)

    assert decoded == payload
    assert encoded == b'{"email":"updated@example.com"}'

    empty_payload = UserUpdate()
    assert msgspec.json.encode(empty_payload) == b"{}"


def test_user_update_serializes_current_password_step_up_field() -> None:
    """UserUpdate carries current-password proof only as an email-change step-up field."""
    payload = UserUpdate(email="updated@example.com", current_password="current-password")

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=UserUpdate)

    assert decoded == payload
    assert encoded == b'{"email":"updated@example.com","current_password":"current-password"}'


@pytest.mark.parametrize(
    "field_name",
    ["is_active", "is_verified", "roles", "password", "hashed_password"],
)
def test_user_update_rejects_privileged_or_credential_fields_at_decode(field_name: str) -> None:
    """UserUpdate fails closed at msgspec decode for any privileged/credential field.

    ``forbid_unknown_fields=True`` rejects the body before the persistence
    layer's defense-in-depth deny-list ever runs. A regression that
    re-introduces ``is_active`` / ``is_verified`` / ``roles`` (or password
    fields) on the self-service contract would cause this test to fail and
    the privilege-escalation surface would be visible in CI.
    """
    privileged_value: object = False if field_name in {"is_active", "is_verified"} else "value"
    body = msgspec.json.encode({"email": "user@example.com", field_name: privileged_value})

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(body, type=UserUpdate)


def test_admin_user_update_serializes_privileged_fields() -> None:
    """AdminUserUpdate is the privileged contract that legitimately carries those fields."""
    payload = AdminUserUpdate(email="updated@example.com", is_verified=True, roles=["admin"])

    encoded = msgspec.json.encode(payload)
    decoded = msgspec.json.decode(encoded, type=AdminUserUpdate)

    assert decoded == payload
    assert encoded == b'{"email":"updated@example.com","is_verified":true,"roles":["admin"]}'


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
        (AdminUserUpdate, "password", DEFAULT_MINIMUM_PASSWORD_LENGTH),
        (UserCreate, "password", DEFAULT_MINIMUM_PASSWORD_LENGTH),
        (CustomRegistrationSchema, "password", DEFAULT_MINIMUM_PASSWORD_LENGTH),
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
        (TotpConfirmEnableRequest, {"enrollment_token": "enrollment-token"}),
    ],
)
def test_totp_enrollment_code_payload_preserves_exact_length(
    schema_type: type[msgspec.Struct],
    other_fields: dict[str, str],
) -> None:
    """TOTP enrollment payloads keep the six-character code contract."""
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


def test_totp_disable_payload_accepts_totp_or_recovery_code_lengths() -> None:
    """TOTP disable accepts six-digit TOTP codes and 28-character recovery codes."""
    totp_payload = msgspec.json.decode(msgspec.json.encode({"code": "123456"}), type=TotpDisableRequest)
    recovery_payload = msgspec.json.decode(msgspec.json.encode({"code": "0" * 28}), type=TotpDisableRequest)

    assert totp_payload.code == "123456"
    assert recovery_payload.code == "0" * 28

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode({"code": "12345"}), type=TotpDisableRequest)

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode({"code": "0" * 27}), type=TotpDisableRequest)

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode({"code": "ABCDEF"}), type=TotpDisableRequest)


def test_totp_verify_payload_accepts_totp_or_recovery_code_lengths() -> None:
    """TOTP verify accepts six-digit TOTP codes and 28-character recovery codes."""
    totp_payload = msgspec.json.decode(
        msgspec.json.encode({"pending_token": "pending-token", "code": "123456"}),
        type=TotpVerifyRequest,
    )
    recovery_payload = msgspec.json.decode(
        msgspec.json.encode({"pending_token": "pending-token", "code": "0" * 28}),
        type=TotpVerifyRequest,
    )

    assert totp_payload.code == "123456"
    assert recovery_payload.code == "0" * 28

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"pending_token": "pending-token", "code": "12345"}),
            type=TotpVerifyRequest,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"pending_token": "pending-token", "code": "0" * 27}),
            type=TotpVerifyRequest,
        )

    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(
            msgspec.json.encode({"pending_token": "pending-token", "code": "ABCDEF"}),
            type=TotpVerifyRequest,
        )
