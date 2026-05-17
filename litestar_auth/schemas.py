"""Public msgspec schemas and schema helpers for litestar-auth user payloads.

Import ``UserEmailField`` and ``UserPasswordField`` from this module when
app-owned ``msgspec.Struct`` user create, self-update, admin update, or
change-password schemas should share the same email and password metadata as
the built-in payloads. Self-service ``UserUpdate`` accepts
``current_password`` only as a step-up credential for email changes; use the
dedicated ``ChangePasswordRequest`` contract for authenticated password
rotation.
"""

from __future__ import annotations

import uuid  # noqa: TC003
from typing import Annotated

import msgspec

import litestar_auth._schema_fields as schema_fields

type UserEmailField = Annotated[
    str,
    schema_fields.EMAIL_FIELD_META,
]
type UserPasswordField = Annotated[
    str,
    schema_fields.USER_PASSWORD_FIELD_META,
]


class UserRead(msgspec.Struct):
    """Public user representation returned by the API."""

    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    roles: list[str]


class UserCreate(msgspec.Struct, forbid_unknown_fields=True):
    """Payload used to create a new user."""

    email: UserEmailField
    password: UserPasswordField


class UserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
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
    current_password: UserPasswordField | None = None
    totp_code: schema_fields.TotpCodeField | None = None


class AdminUserUpdate(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
    """Privileged admin update payload.

    Admin writes may include ``password`` for operator-initiated credential
    rotation. This schema is used for ``PATCH /users/{user_id}``, not for
    self-service ``PATCH /users/me`` requests.
    """

    password: UserPasswordField | None = None
    email: UserEmailField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    roles: list[str] | None = None


class ChangePasswordRequest(msgspec.Struct, forbid_unknown_fields=True):
    """Self-service password-rotation payload.

    ``POST /users/me/change-password`` requires the current password plus the
    replacement password. The controller re-verifies the current credential
    before delegating the new password to the manager update lifecycle.
    """

    current_password: UserPasswordField
    new_password: UserPasswordField


__all__ = (
    "AdminUserUpdate",
    "ChangePasswordRequest",
    "UserCreate",
    "UserEmailField",
    "UserPasswordField",
    "UserRead",
    "UserUpdate",
)
