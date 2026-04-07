"""Public msgspec schemas and schema helpers for litestar-auth user payloads.

Import ``UserEmailField`` and ``UserPasswordField`` from this module when
app-owned ``msgspec.Struct`` user create/update schemas should share the same
email and password metadata as the built-in ``UserCreate`` and ``UserUpdate``
payloads.
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
    is_superuser: bool


class UserCreate(msgspec.Struct):
    """Payload used to create a new user."""

    email: UserEmailField
    password: UserPasswordField


class UserUpdate(msgspec.Struct, omit_defaults=True):
    """Partial user update payload."""

    password: UserPasswordField | None = None
    email: UserEmailField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None


__all__ = ("UserCreate", "UserEmailField", "UserPasswordField", "UserRead", "UserUpdate")
