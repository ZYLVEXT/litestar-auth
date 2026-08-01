"""Typed failure codes for payment HTTP Message Signature verification."""

from __future__ import annotations

from enum import StrEnum


class HttpSignatureFailureCode(StrEnum):
    """Stable integrity failure codes (secret-free)."""

    MALFORMED = "malformed"
    BODY_TOO_LARGE = "body_too_large"
    DIGEST_MISMATCH = "digest_mismatch"
    CONTENT_TYPE_REJECTED = "content_type_rejected"
    CONTENT_ENCODING_REJECTED = "content_encoding_rejected"
    QUERY_REJECTED = "query_rejected"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_EXPIRED = "signature_expired"
    NOT_YET_VALID = "not_yet_valid"
    PROFILE_MISMATCH = "profile_mismatch"
    KEY_BINDING_MISMATCH = "key_binding_mismatch"
    NONCE_REPLAY = "nonce_replay"
    STORE_UNAVAILABLE = "store_unavailable"
    MISSING_COMPONENT = "missing_component"


class HttpSignatureVerificationError(Exception):
    """Fail-closed integrity verification error."""

    def __init__(self, code: HttpSignatureFailureCode) -> None:
        """Bind a secret-free failure code."""
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        """Omit request material from representations."""
        return f"HttpSignatureVerificationError(code={self.code!r})"
