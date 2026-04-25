"""Internal msgspec field aliases shared across auth payload schemas.

Public code should import ``UserEmailField`` / ``UserPasswordField`` from
``litestar_auth.schemas`` when custom user create/update payloads need the
built-in user-schema contract.
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
TOTP_RECOVERY_CODE_LENGTH = 28
TOTP_VERIFICATION_CODE_PATTERN = rf"^(?:\d{{{TOTP_CODE_LENGTH}}}|[0-9a-f]{{{TOTP_RECOVERY_CODE_LENGTH}}})$"

EMAIL_FIELD_META = msgspec.Meta(max_length=EMAIL_MAX_LENGTH, pattern=EMAIL_PATTERN)
USER_PASSWORD_FIELD_META = msgspec.Meta(
    min_length=DEFAULT_MINIMUM_PASSWORD_LENGTH,
    max_length=MAX_PASSWORD_LENGTH,
)

type EmailField = Annotated[str, EMAIL_FIELD_META]
type UserPasswordField = Annotated[str, USER_PASSWORD_FIELD_META]
type PasswordField = Annotated[str, msgspec.Meta(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
type LoginIdentifierField = Annotated[str, msgspec.Meta(min_length=1, max_length=LOGIN_IDENTIFIER_MAX_LENGTH)]
type RefreshTokenField = Annotated[str, msgspec.Meta(min_length=1, max_length=REFRESH_TOKEN_MAX_LENGTH)]
type LongLivedTokenField = Annotated[str, msgspec.Meta(min_length=1, max_length=LONG_LIVED_TOKEN_MAX_LENGTH)]
type TotpCodeField = Annotated[str, msgspec.Meta(min_length=TOTP_CODE_LENGTH, max_length=TOTP_CODE_LENGTH)]
type TotpVerificationCodeField = Annotated[
    str,
    msgspec.Meta(
        min_length=TOTP_CODE_LENGTH,
        max_length=TOTP_RECOVERY_CODE_LENGTH,
        pattern=TOTP_VERIFICATION_CODE_PATTERN,
    ),
]
