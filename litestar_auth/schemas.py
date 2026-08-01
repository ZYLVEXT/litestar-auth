"""Public msgspec schemas and schema helpers for litestar-auth user payloads.

Import ``UserEmailField`` and ``UserPasswordField`` from this module when
app-owned ``msgspec.Struct`` payloads for newly chosen passwords should share
the built-in password metadata. Use ``CurrentPasswordField`` for bounded
current-password proof that must continue accepting credentials created under
an older password policy. Self-service ``UserUpdate`` accepts
``current_password`` only as a step-up credential for email changes; use the
dedicated ``ChangePasswordRequest`` contract for authenticated password
rotation.
"""

from __future__ import annotations

import uuid  # ruff: ignore[typing-only-standard-library-import]

import msgspec

import litestar_auth._schema_fields as schema_fields

type UserEmailField = schema_fields.EmailField
type UserPasswordField = schema_fields.UserPasswordField
type CurrentPasswordField = schema_fields.PasswordField


class UserRead(msgspec.Struct):
    """Public user representation returned by the API."""

    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    roles: list[str]


class UserCreate(schema_fields.RedactedReprMixin, msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to create a new user."""

    email: UserEmailField
    password: UserPasswordField


class UserUpdate(schema_fields.RedactedReprMixin, msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
    """Self-service profile-update payload (non-privileged).

    Security:
        Privileged fields (``is_active``, ``is_verified``, ``roles``) are not
        accepted on this self-service contract. They belong to
        :class:`AdminUserUpdate` via privileged ``PATCH /users/{user_id}``
        instead. Email changes require ``current_password`` so the authenticated
        session re-proves the user's password before identity mutation.
        Password rotation goes through :class:`ChangePasswordRequest` on
        ``POST /users/me/change-password`` so the current password can be
        re-verified first. ``forbid_unknown_fields=True`` rejects any of those
        fields at decode time, so the persistence layer's defense-in-depth
        deny-list never has to run on an incoming self-service body.
    """

    email: UserEmailField | None = None
    current_password: CurrentPasswordField | None = None
    totp_code: schema_fields.TotpCodeField | None = None


class AdminUserUpdate(schema_fields.RedactedReprMixin, msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
    """Privileged admin update payload.

    Admin writes may include ``password`` for operator-initiated credential
    rotation. ``current_password`` and ``totp_code`` are step-up proof for the
    authenticated admin and are not forwarded to persistence. This schema is
    used for ``PATCH /users/{user_id}``, not for self-service ``PATCH
    /users/me`` requests.
    """

    password: UserPasswordField | None = None
    email: UserEmailField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    roles: list[str] | None = None
    current_password: CurrentPasswordField | None = None
    totp_code: schema_fields.TotpCodeField | None = None


class ChangePasswordRequest(schema_fields.RedactedReprMixin, msgspec.Struct, forbid_unknown_fields=True):
    """Self-service password-rotation payload.

    ``POST /users/me/change-password`` requires the current password plus the
    replacement password. The controller re-verifies the current credential
    before delegating the new password to the manager update lifecycle.
    """

    current_password: CurrentPasswordField
    new_password: UserPasswordField


__all__ = (
    "AdminUserUpdate",
    "ChangePasswordRequest",
    "CurrentPasswordField",
    "UserCreate",
    "UserEmailField",
    "UserPasswordField",
    "UserRead",
    "UserUpdate",
)
