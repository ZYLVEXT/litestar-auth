"""Shared email normalization policy for account-owned identifiers."""

from __future__ import annotations

import re
import unicodedata

EMAIL_MAX_LENGTH = 320
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_EMAIL_RE = re.compile(EMAIL_PATTERN)


def normalize_email(email: str) -> str:
    """Normalize and validate an email address with the account identity policy.

    Returns:
        The normalized email address.

    Raises:
        ValueError: If the normalized address is invalid.
    """
    normalized = unicodedata.normalize("NFKC", email.strip()).lower()
    if len(normalized) > EMAIL_MAX_LENGTH or not _EMAIL_RE.fullmatch(normalized):
        msg = "Invalid email address."
        raise ValueError(msg)
    return normalized
