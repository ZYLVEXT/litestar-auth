"""Bounded Standard Webhooks header and signing-input helpers."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass

from authweave_webhooks.errors import WebhookFailureCode, WebhookVerificationError
from authweave_webhooks.models import (
    ED25519_SIGNATURE_BYTES,
    HEADER_ID,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    MAX_BODY_BYTES,
    MAX_SIGNATURES,
    MAX_WEBHOOK_ID_LENGTH,
    SIGNATURE_VERSION,
)

_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_TIMESTAMP_PATTERN = re.compile(r"^[0-9]+$")


@dataclass(frozen=True, slots=True)
class ParsedWebhookHeaders:
    """Exactly one id, timestamp, and signature list after duplicate rejection."""

    webhook_id: str
    timestamp: int
    signatures: tuple[bytes, ...]


def build_signing_input(*, webhook_id: str, timestamp: int, body: bytes) -> bytes:
    """Build the Standard Webhooks signed byte sequence.

    Returns:
        ASCII ``webhook-id.timestamp.`` concatenated with the exact raw body.
    """
    prefix = f"{webhook_id}.{timestamp}.".encode("ascii")
    return prefix + body


def parse_headers(
    headers: Mapping[str, str] | list[tuple[str, str]],
    *,
    body: bytes,
    max_body_bytes: int = MAX_BODY_BYTES,
) -> ParsedWebhookHeaders:
    """Parse and bound Standard Webhooks headers before cryptographic verify.

    Returns:
        The parsed header triple.

    Raises:
        WebhookVerificationError: On duplicate, malformed, or oversized input.
    """
    if len(body) > max_body_bytes:
        raise WebhookVerificationError(WebhookFailureCode.BODY_TOO_LARGE)

    values = _collect_headers(headers)
    webhook_id = _require_one(values, HEADER_ID)
    timestamp_raw = _require_one(values, HEADER_TIMESTAMP)
    signature_raw = _require_one(values, HEADER_SIGNATURE)

    if (
        not webhook_id
        or len(webhook_id) > MAX_WEBHOOK_ID_LENGTH
        or "." in webhook_id
        or _ID_PATTERN.fullmatch(webhook_id) is None
    ):
        raise WebhookVerificationError(WebhookFailureCode.MALFORMED_HEADERS)
    if not timestamp_raw or "." in timestamp_raw or _TIMESTAMP_PATTERN.fullmatch(timestamp_raw) is None:
        raise WebhookVerificationError(WebhookFailureCode.TIMESTAMP_INVALID)

    signatures = _parse_signatures(signature_raw)
    return ParsedWebhookHeaders(webhook_id=webhook_id, timestamp=int(timestamp_raw), signatures=signatures)


def format_signature_header(signatures: list[bytes]) -> str:
    """Format one or more Ed25519 signatures as a Standard Webhooks header.

    Returns:
        A space-delimited ``v1a,<base64>`` list.
    """
    if not signatures or len(signatures) > MAX_SIGNATURES:
        msg = f"signature count must be 1..{MAX_SIGNATURES}"
        raise ValueError(msg)
    parts: list[str] = []
    for signature in signatures:
        if len(signature) != ED25519_SIGNATURE_BYTES:
            msg = "Ed25519 signature must be 64 bytes"
            raise ValueError(msg)
        parts.append(f"{SIGNATURE_VERSION},{base64.b64encode(signature).decode('ascii')}")
    return " ".join(parts)


def _collect_headers(headers: Mapping[str, str] | list[tuple[str, str]]) -> dict[str, list[str]]:
    items = headers.items() if not isinstance(headers, list) else headers
    collected: dict[str, list[str]] = {}
    for raw_name, raw_value in items:
        name = raw_name.lower()
        if name not in {HEADER_ID, HEADER_TIMESTAMP, HEADER_SIGNATURE}:
            continue
        collected.setdefault(name, []).append(raw_value)
    return collected


def _require_one(values: dict[str, list[str]], name: str) -> str:
    present = values.get(name, [])
    if len(present) > 1:
        raise WebhookVerificationError(WebhookFailureCode.DUPLICATE_HEADER)
    if len(present) != 1:
        raise WebhookVerificationError(WebhookFailureCode.MALFORMED_HEADERS)
    return present[0]


def _parse_signatures(raw: str) -> tuple[bytes, ...]:
    parts = raw.split()
    if not parts or len(parts) > MAX_SIGNATURES:
        raise WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID)
    signatures: list[bytes] = []
    for part in parts:
        version, sep, payload = part.partition(",")
        if sep != "," or version != SIGNATURE_VERSION or not payload:
            raise WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID)
        try:
            decoded = base64.b64decode(payload, validate=True)
        except ValueError as exc:
            raise WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID) from exc
        if len(decoded) != ED25519_SIGNATURE_BYTES:
            raise WebhookVerificationError(WebhookFailureCode.SIGNATURE_INVALID)
        signatures.append(decoded)
    return tuple(signatures)
