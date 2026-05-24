"""Shared controller-local step-up request payloads."""

from __future__ import annotations

import msgspec

import litestar_auth._schema_fields as schema_fields  # noqa: TC001
from litestar_auth.schemas import UserPasswordField  # noqa: TC001


class _AdminCurrentPasswordStepUpRequest(msgspec.Struct, omit_defaults=True, forbid_unknown_fields=True):
    """Reusable current-password field contract for privileged admin step-up bodies."""

    current_password: UserPasswordField | None = None


class AdminUserDeleteStepUpRequest(_AdminCurrentPasswordStepUpRequest):
    """Step-up proof payload for privileged admin user deletion."""

    totp_code: schema_fields.TotpCodeField | None = None
