"""Public msgspec schemas and schema helpers for litestar-auth user payloads.

Import ``UserPasswordField`` from this module when app-owned ``msgspec.Struct``
user create/update schemas should share the same password-length metadata as the
built-in ``UserCreate`` and ``UserUpdate`` payloads.
"""

from __future__ import annotations

import uuid  # noqa: TC003
from typing import Annotated

import msgspec

import litestar_auth._schema_fields as schema_fields  # noqa: TC001
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH

type UserPasswordField = Annotated[
    str,
    msgspec.Meta(min_length=DEFAULT_MINIMUM_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH),
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

    email: schema_fields.EmailField
    password: UserPasswordField


class UserUpdate(msgspec.Struct, omit_defaults=True):
    """Partial user update payload."""

    password: UserPasswordField | None = None
    email: schema_fields.EmailField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None


__all__ = ("UserCreate", "UserPasswordField", "UserRead", "UserUpdate")
