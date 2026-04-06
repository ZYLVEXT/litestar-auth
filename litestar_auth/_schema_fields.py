"""Internal msgspec field aliases shared across auth payload schemas.

Public code should import ``UserPasswordField`` from ``litestar_auth.schemas``
when custom user create/update payloads need the built-in password policy.
"""

from __future__ import annotations

from typing import Annotated

import msgspec

from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
EMAIL_MAX_LENGTH = 320
LOGIN_IDENTIFIER_MAX_LENGTH = 320
REFRESH_TOKEN_MAX_LENGTH = 512
LONG_LIVED_TOKEN_MAX_LENGTH = 2048
TOTP_CODE_LENGTH = 6

type EmailField = Annotated[str, msgspec.Meta(max_length=EMAIL_MAX_LENGTH, pattern=EMAIL_PATTERN)]
type UserPasswordField = Annotated[
    str,
    msgspec.Meta(min_length=DEFAULT_MINIMUM_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH),
]
type PasswordField = Annotated[str, msgspec.Meta(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
type LoginIdentifierField = Annotated[str, msgspec.Meta(min_length=1, max_length=LOGIN_IDENTIFIER_MAX_LENGTH)]
type RefreshTokenField = Annotated[str, msgspec.Meta(min_length=1, max_length=REFRESH_TOKEN_MAX_LENGTH)]
type LongLivedTokenField = Annotated[str, msgspec.Meta(min_length=1, max_length=LONG_LIVED_TOKEN_MAX_LENGTH)]
type TotpCodeField = Annotated[str, msgspec.Meta(min_length=TOTP_CODE_LENGTH, max_length=TOTP_CODE_LENGTH)]
