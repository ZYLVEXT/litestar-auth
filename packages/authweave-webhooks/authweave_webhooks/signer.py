"""Ed25519 signing protocol and local keyring signer."""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from authweave_webhooks.headers import build_signing_input, format_signature_header
from authweave_webhooks.models import WebhookDelivery


class AsyncMessageSigner(Protocol):
    """Sign bounded webhook bytes using an approved key reference.

    Implementations must accept a key reference, never raw private key bytes, in
    the public call signature. Private material stays inside the signer/KMS.
    """

    async def sign(self, *, key_ref: str, message: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over ``message``.

        Returns:
            The raw Ed25519 signature bytes.
        """
        ...


class LocalEd25519KeyringSigner:
    """Reference signer that looks up private keys by opaque key reference.

    Intended for tests and single-process demos. Production deployments should
    use a KMS/HSM-backed ``AsyncMessageSigner``. Private keys never appear in
    ``repr`` or raised error messages.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        """Bind opaque key references to private keys held only in memory.

        Raises:
            ValueError: If the call cannot complete.
        """
        if not keys:
            msg = "keyring must contain at least one key"
            raise ValueError(msg)
        self._keys = dict(keys)

    def __repr__(self) -> str:
        """List key references without private material.

        Returns:
            The repr  .
        """
        refs = sorted(self._keys)
        return f"LocalEd25519KeyringSigner(key_refs={refs!r})"

    async def sign(self, *, key_ref: str, message: bytes) -> bytes:
        """Sign ``message`` with the referenced key.

        Returns:
            The raw Ed25519 signature.

        Raises:
            KeyError: If the key reference is unknown.
        """
        try:
            private_key = self._keys[key_ref]
        except KeyError as exc:
            msg = "unknown key reference"
            raise KeyError(msg) from exc
        return private_key.sign(message)


async def create_delivery(
    *,
    signer: AsyncMessageSigner,
    key_refs: list[str],
    webhook_id: str,
    timestamp: int,
    body: bytes,
) -> WebhookDelivery:
    """Construct one Standard Webhooks delivery attempt.

    ``webhook_id`` must be stable across retries; ``timestamp`` is the attempt
    time and should be refreshed on retry. ``key_refs`` may include active and
    next keys during rotation overlap.

    Returns:
        Headers-ready delivery material.

    Raises:
        ValueError: If identifiers are malformed.
    """
    if not webhook_id or "." in webhook_id:
        msg = "webhook_id must be non-empty and must not contain '.'"
        raise ValueError(msg)
    if timestamp < 0:
        msg = "timestamp must be non-negative"
        raise ValueError(msg)
    message = build_signing_input(webhook_id=webhook_id, timestamp=timestamp, body=body)
    signatures = [await signer.sign(key_ref=key_ref, message=message) for key_ref in key_refs]
    return WebhookDelivery(
        webhook_id=webhook_id,
        timestamp=timestamp,
        body=body,
        signature_header=format_signature_header(signatures),
    )
