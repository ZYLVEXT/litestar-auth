"""Msgspec schemas for litestar-auth user payloads."""

from __future__ import annotations

import uuid  # noqa: TC003
from typing import Annotated

import msgspec

from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH

_EMAIL_META = msgspec.Meta(max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PASSWORD_META = msgspec.Meta(min_length=DEFAULT_MINIMUM_PASSWORD_LENGTH, max_length=128)


class UserRead(msgspec.Struct):
    """Public user representation returned by the API."""

    id: uuid.UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool


class UserCreate(msgspec.Struct):
    """Payload used to create a new user."""

    email: Annotated[str, _EMAIL_META]
    password: Annotated[str, _PASSWORD_META]


class UserUpdate(msgspec.Struct, omit_defaults=True):
    """Partial user update payload."""

    password: Annotated[str, _PASSWORD_META] | None = None
    email: Annotated[str, _EMAIL_META] | None = None
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
