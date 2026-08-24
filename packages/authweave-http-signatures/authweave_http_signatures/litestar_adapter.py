"""Litestar helpers for reading an exact raw body before verification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class _LitestarRequest(Protocol):
    def stream(self) -> AsyncIterator[bytes]: ...


async def read_bounded_raw_body(connection: _LitestarRequest, *, maximum_bytes: int) -> bytes:
    """Stream the request body up to ``maximum_bytes`` without JSON parsing.

    Returns:
        The exact raw body bytes.

    Raises:
        HttpSignatureVerificationError: If the body is incomplete or too large.

    Raises:
        ValueError: If the call cannot complete.
    """
    if maximum_bytes <= 0:
        msg = "maximum_bytes must be positive"
        raise ValueError(msg)
    chunks: list[bytes] = []
    total = 0
    oversized = False
    stream: AsyncIterator[bytes] = connection.stream()
    try:
        async for chunk in stream:
            total += len(chunk)
            if total > maximum_bytes:
                oversized = True
                break
            chunks.append(chunk)
    except Exception as exc:
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED) from exc
    if oversized:
        raise HttpSignatureVerificationError(HttpSignatureFailureCode.BODY_TOO_LARGE)
    return b"".join(chunks)
