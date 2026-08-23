"""Immutable webhook models and key-document contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
MAX_BODY_BYTES: Final = 262_144
MAX_WEBHOOK_ID_LENGTH: Final = 128
MAX_SIGNATURES: Final = 3
MAX_PUBLIC_KEYS: Final = 3
DEFAULT_TIMESTAMP_TOLERANCE_SECONDS: Final = 300
SIGNATURE_VERSION: Final = "v1a"
HEADER_ID: Final = "webhook-id"
HEADER_TIMESTAMP: Final = "webhook-timestamp"
HEADER_SIGNATURE: Final = "webhook-signature"


@dataclass(frozen=True, slots=True)
class Ed25519PublicKey:
    """One onboarding-trusted Ed25519 public key (32 raw bytes)."""

    public_key: bytes

    def __post_init__(self) -> None:
        """Reject non-Ed25519 key material.

        Raises:
            ValueError: If the call cannot complete.
        """
        if len(self.public_key) != ED25519_PUBLIC_KEY_BYTES:
            msg = "Ed25519 public key must be 32 bytes"
            raise ValueError(msg)

    def __repr__(self) -> str:
        """Omit raw key bytes from representations.

        Returns:
            The repr  .
        """
        return "Ed25519PublicKey(public_key=...)"


@dataclass(frozen=True, slots=True)
class PublicKeyDocument:
    """Bounded public-key set for one merchant/endpoint environment.

    At most three keys cover active/next/retiring rotation overlap. Private keys
    never appear in this document.
    """

    version: str
    environment: str
    owner: str
    endpoint: str
    not_before: int
    retire_after: int | None
    keys: tuple[Ed25519PublicKey, ...]

    def __post_init__(self) -> None:
        """Enforce rotation cardinality and identity bounds.

        Raises:
            ValueError: If the call cannot complete.
        """
        if not self.version or not self.environment or not self.owner or not self.endpoint:
            msg = "version, environment, owner, and endpoint are required"
            raise ValueError(msg)
        if not self.keys or len(self.keys) > MAX_PUBLIC_KEYS:
            msg = f"public key document must contain 1..{MAX_PUBLIC_KEYS} keys"
            raise ValueError(msg)
        if self.retire_after is not None and self.retire_after < self.not_before:
            msg = "retire_after must be >= not_before"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class VerifiedWebhook:
    """Immutable verification result produced before JSON parsing."""

    webhook_id: str
    timestamp: int
    body: bytes
    environment: str
    owner: str
    endpoint: str
    key_document_version: str
    replay_detected: bool = False

    def __repr__(self) -> str:
        """Omit raw body bytes from representations.

        Returns:
            The repr  .
        """
        return (
            "VerifiedWebhook("
            f"webhook_id={self.webhook_id!r}, timestamp={self.timestamp}, "
            f"body_len={len(self.body)}, environment={self.environment!r}, "
            f"owner={self.owner!r}, endpoint={self.endpoint!r}, "
            f"key_document_version={self.key_document_version!r}, "
            f"replay_detected={self.replay_detected!r})"
        )


@dataclass(frozen=True, slots=True)
class WebhookDelivery:
    """Producer output: exact headers and raw body for one delivery attempt."""

    webhook_id: str
    timestamp: int
    body: bytes
    signature_header: str

    def headers(self) -> dict[str, str]:
        """Return the three Standard Webhooks headers for this attempt."""
        return {
            HEADER_ID: self.webhook_id,
            HEADER_TIMESTAMP: str(self.timestamp),
            HEADER_SIGNATURE: self.signature_header,
        }

    def __repr__(self) -> str:
        """Omit raw body and signature material from representations.

        Returns:
            The repr  .
        """
        return (
            "WebhookDelivery("
            f"webhook_id={self.webhook_id!r}, timestamp={self.timestamp}, "
            f"body_len={len(self.body)}, signature_header=...)"
        )
