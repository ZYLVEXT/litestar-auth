"""RFC 9530 ``Content-Digest`` helpers for sha-256."""

from __future__ import annotations

import base64
import hashlib
import re

from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError

CONTENT_DIGEST_SHA256 = "sha-256"
_DIGEST_PATTERN = re.compile(r"^sha-256=:(?P<digest>[A-Za-z0-9+/=]+):$")


def content_digest_sha256(body: bytes) -> str:
    """Return an RFC 9530 ``Content-Digest`` header value for ``body``.

    Returns:
        ``sha-256=:base64:`` for the exact raw body.
    """
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"{CONTENT_DIGEST_SHA256}=:{digest}:"


def verify_content_digest(*, header_value: str, body: bytes) -> None:
    """Validate ``Content-Digest`` against the exact raw body.

    Raises:
        HttpSignatureVerificationError: On malformed or mismatched digests.
    """
    match = _DIGEST_PATTERN.fullmatch(header_value.strip())
    if match is None:
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
    try:
        presented = base64.b64decode(match.group("digest"), validate=True)
    except ValueError as exc:
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED) from exc
    expected = hashlib.sha256(body).digest()
    if len(presented) != len(expected) or presented != expected:
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.DIGEST_MISMATCH)
