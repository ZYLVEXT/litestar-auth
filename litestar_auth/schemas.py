"""Msgspec schemas for litestar-auth user payloads."""

from __future__ import annotations

import uuid  # noqa: TC003

import msgspec

import litestar_auth._schema_fields as schema_fields  # noqa: TC001


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
    password: schema_fields.UserPasswordField


class UserUpdate(msgspec.Struct, omit_defaults=True):
    """Partial user update payload."""

    password: schema_fields.UserPasswordField | None = None
    email: schema_fields.EmailField | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
