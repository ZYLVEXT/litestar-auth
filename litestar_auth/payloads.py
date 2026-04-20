"""Public msgspec payloads for built-in auth and user flows.

The supported import path for these structs is ``litestar_auth.payloads``.
Payload structs are intentionally not re-exported from ``litestar_auth``; import
them from this module so imports stay explicit for readers and tooling.
"""

from __future__ import annotations

import msgspec

import litestar_auth._schema_fields as schema_fields  # noqa: TC001


class LoginCredentials(msgspec.Struct):
    """Login payload accepted by the auth controller."""

    identifier: schema_fields.LoginIdentifierField
    password: schema_fields.PasswordField


class RefreshTokenRequest(msgspec.Struct):
    """Refresh payload accepted by the auth controller."""

    refresh_token: schema_fields.RefreshTokenField


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


class TotpVerifyRequest(msgspec.Struct):
    """Payload for completing 2FA login verification."""

    pending_token: schema_fields.LongLivedTokenField
    code: schema_fields.TotpCodeField


class TotpConfirmEnableRequest(msgspec.Struct):
    """Payload for confirming TOTP enrollment (phase 2)."""

    enrollment_token: schema_fields.LongLivedTokenField
    code: schema_fields.TotpCodeField


class TotpConfirmEnableResponse(msgspec.Struct):
    """Response returned when 2FA is successfully confirmed and persisted."""

    enabled: bool


class TotpDisableRequest(msgspec.Struct):
    """Payload for disabling 2FA."""

    code: schema_fields.TotpCodeField


__all__ = (
    "ForgotPassword",
    "LoginCredentials",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableRequest",
    "TotpEnableResponse",
    "TotpVerifyRequest",
    "VerifyToken",
)
