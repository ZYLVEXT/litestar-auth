"""Typed errors and outcomes for Standard Webhooks verification."""

from __future__ import annotations

from enum import StrEnum


class WebhookFailureCode(StrEnum):
    """Bounded failure codes returned to callers without key-discrimination detail."""

    MALFORMED_HEADERS = "malformed_headers"
    DUPLICATE_HEADER = "duplicate_header"
    BODY_TOO_LARGE = "body_too_large"
    TIMESTAMP_INVALID = "timestamp_invalid"
    TIMESTAMP_OUT_OF_TOLERANCE = "timestamp_out_of_tolerance"
    SIGNATURE_INVALID = "signature_invalid"
    KEY_UNAVAILABLE = "key_unavailable"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    OWNER_MISMATCH = "owner_mismatch"
    ENDPOINT_MISMATCH = "endpoint_mismatch"
    STORE_UNAVAILABLE = "store_unavailable"


class WebhookVerificationError(Exception):
    """Fail-closed verification error with a secret-free bounded code."""

    def __init__(self, code: WebhookFailureCode) -> None:
        """Bind the public failure code without embedding raw material."""
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        """Return a secret-free representation."""
        return f"WebhookVerificationError(code={self.code!r})"
