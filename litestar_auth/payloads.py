"""Public msgspec payloads for built-in auth and user flows.

The supported import path for these structs is ``litestar_auth.payloads``.
Payload structs are intentionally not re-exported from ``litestar_auth``; import
them from this module so imports stay explicit for readers and tooling.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import Annotated

import msgspec

import litestar_auth._schema_fields as schema_fields  # noqa: TC001

type SessionClientMetadataKey = Annotated[
    str,
    msgspec.Meta(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$"),
]
type SessionClientMetadataValue = Annotated[str, msgspec.Meta(min_length=1, max_length=255)]
type ApiKeyNameField = Annotated[str, msgspec.Meta(min_length=1, max_length=120)]
type ApiKeyScopeField = Annotated[str, msgspec.Meta(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9:_-]+$")]
type ApiKeyIdField = Annotated[str, msgspec.Meta(min_length=1, max_length=128)]


class LoginCredentials(msgspec.Struct):
    """Login payload accepted by the auth controller."""

    identifier: schema_fields.LoginIdentifierField
    password: schema_fields.PasswordField


class RefreshTokenRequest(msgspec.Struct):
    """Refresh payload accepted by the auth controller."""

    refresh_token: schema_fields.RefreshTokenField


class RefreshSessionRead(msgspec.Struct):
    """Safe refresh-session representation returned by session/device APIs.

    The public ``session_id`` is intentionally distinct from stored token
    digests and raw refresh tokens. ``client_metadata`` is limited to bounded,
    non-secret client hints such as the normalized ``user_agent`` value stored
    by the database token strategy.
    """

    session_id: str
    created_at: datetime
    last_used_at: datetime | None = None
    is_current: bool | None = None
    client_metadata: dict[SessionClientMetadataKey, SessionClientMetadataValue] | None = None


class RefreshSessionListResponse(msgspec.Struct):
    """Response returned when listing active refresh sessions for a user."""

    sessions: list[RefreshSessionRead]


class ApiKeyRead(msgspec.Struct):
    """Safe API-key metadata returned by API-key management endpoints."""

    key_id: ApiKeyIdField
    name: str
    scopes: list[str]
    prefix_env: str
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiKeyListResponse(msgspec.Struct):
    """Response returned when listing API keys."""

    api_keys: list[ApiKeyRead]


class ApiKeyCreateRequest(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to create a user-owned API key."""

    name: ApiKeyNameField
    current_password: schema_fields.PasswordField | None = None
    scopes: list[ApiKeyScopeField] = []
    expires_at: datetime | None = None
    signing_required: bool = False


class ApiKeyAdminCreateRequest(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used by superusers to create an API key for a path-selected user."""

    name: ApiKeyNameField
    scopes: list[ApiKeyScopeField] = []
    expires_at: datetime | None = None
    signing_required: bool = False


class ApiKeyCreateResponse(msgspec.Struct):
    """Creation response containing the one-time raw API key."""

    api_key: str
    key: ApiKeyRead


class ApiKeyUpdateRequest(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
    """Payload used to update mutable API-key metadata."""

    current_password: schema_fields.PasswordField
    name: ApiKeyNameField | None = None
    scopes: list[ApiKeyScopeField] | None = None


class ForgotPassword(msgspec.Struct):
    """Payload used to request a reset-password token."""

    email: schema_fields.EmailField


class ResetPassword(msgspec.Struct):
    """Payload used to reset a password with a previously issued token."""

    token: schema_fields.LongLivedTokenField
    password: schema_fields.PasswordField


class VerifyToken(msgspec.Struct):
    """Payload used to complete an email-verification flow."""

    token: schema_fields.LongLivedTokenField


class RequestVerifyToken(msgspec.Struct):
    """Payload used to request a fresh email-verification token."""

    email: schema_fields.EmailField


class TotpEnableResponse(msgspec.Struct):
    """Response returned when 2FA enrollment is initiated (phase 1).

    The secret is not yet persisted. The client must confirm enrollment via
    ``/enable/confirm`` with a valid TOTP code to activate 2FA.
    """

    secret: str
    uri: str
    enrollment_token: str


class TotpEnableRequest(msgspec.Struct):
    """Optional step-up payload for enabling 2FA."""

    password: schema_fields.PasswordField


class TotpRegenerateRecoveryCodesRequest(msgspec.Struct):
    """Step-up payload for rotating TOTP recovery codes.

    Required only when ``totp_enable_requires_password=True``. When that
    policy is disabled, the regenerate route accepts no request body.
    """

    current_password: schema_fields.PasswordField


class TotpRecoveryCodesResponse(msgspec.Struct):
    """Response containing one-time plaintext TOTP recovery codes.

    The values are returned only from confirm-enable or regenerate responses.
    Storage keeps only hashed values in the user model.
    """

    recovery_codes: tuple[str, ...]


class TotpVerifyRequest(msgspec.Struct):
    """Payload for completing 2FA login verification.

    ``code`` accepts either a current TOTP code or an unused recovery code.
    """

    pending_token: schema_fields.LongLivedTokenField
    code: schema_fields.TotpVerificationCodeField


class TotpConfirmEnableRequest(msgspec.Struct):
    """Payload for confirming TOTP enrollment (phase 2)."""

    enrollment_token: schema_fields.LongLivedTokenField
    code: schema_fields.TotpCodeField


class TotpConfirmEnableResponse(msgspec.Struct):
    """Response returned when 2FA is successfully confirmed and persisted.

    Recovery codes are returned only in this response and should be shown once.
    The library persists only hashed recovery-code values.
    """

    enabled: bool
    recovery_codes: tuple[str, ...]


class TotpDisableRequest(msgspec.Struct):
    """Payload for disabling 2FA.

    ``code`` accepts either a current TOTP code or an unused recovery code.
    """

    code: schema_fields.TotpVerificationCodeField


__all__ = (
    "ApiKeyAdminCreateRequest",
    "ApiKeyCreateRequest",
    "ApiKeyCreateResponse",
    "ApiKeyIdField",
    "ApiKeyListResponse",
    "ApiKeyNameField",
    "ApiKeyRead",
    "ApiKeyScopeField",
    "ApiKeyUpdateRequest",
    "ForgotPassword",
    "LoginCredentials",
    "RefreshSessionListResponse",
    "RefreshSessionRead",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "SessionClientMetadataKey",
    "SessionClientMetadataValue",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableRequest",
    "TotpEnableResponse",
    "TotpRecoveryCodesResponse",
    "TotpRegenerateRecoveryCodesRequest",
    "TotpVerifyRequest",
    "VerifyToken",
)
