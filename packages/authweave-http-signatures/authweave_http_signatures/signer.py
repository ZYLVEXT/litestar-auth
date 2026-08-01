"""Ed25519 signer seam and payment-message signing helper."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms

from authweave_http_signatures.digest import content_digest_sha256
from authweave_http_signatures.models import HttpMessageView, PaymentSignaturePolicy


class AsyncMessageSigner(Protocol):
    """Sign bounded bytes using an opaque key reference (never raw private keys)."""

    async def sign(self, *, key_ref: str, message: bytes) -> bytes:
        """Return a raw Ed25519 signature over ``message``."""
        ...


class LocalEd25519KeyringSigner:
    """Reference signer for tests and single-process demos."""

    __slots__ = ("_keys",)

    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        """Bind opaque key references to in-memory private keys."""
        if not keys:
            msg = "keyring must contain at least one key"
            raise ValueError(msg)
        self._keys = dict(keys)

    def __repr__(self) -> str:
        """List key references without private material."""
        return f"LocalEd25519KeyringSigner(key_refs={sorted(self._keys)!r})"

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


@dataclass
class _MessageAdapter:
    """Minimal request shape accepted by ``http-message-signatures``."""

    method: str
    url: str
    headers: dict[str, str]


class _KeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        self._keys = keys

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        return self._keys[key_id]

    def resolve_public_key(self, key_id: str) -> object:
        return self._keys[key_id].public_key()


async def sign_payment_message(  # ruff: ignore[unused-async] - stable async signer API
    *,
    view: HttpMessageView,
    policy: PaymentSignaturePolicy,
    key_id: str,
    private_key: Ed25519PrivateKey,
    nonce: str,
    now: datetime | None = None,
    lifetime: timedelta | None = None,
) -> HttpMessageView:
    """Attach ``Content-Digest`` and RFC 9421 signature headers for profile v1.

    Returns:
        A new ``HttpMessageView`` with digest and signature headers applied.

    Raises:
        ValueError: If required application headers are missing.
    """
    _ = AsyncMessageSigner  # protocol exported for application KMS adapters
    created = now or datetime.now(UTC)
    signature_lifetime = timedelta(seconds=policy.max_signature_lifetime_seconds) if lifetime is None else lifetime
    if not timedelta(0) < signature_lifetime <= timedelta(seconds=policy.max_signature_lifetime_seconds):
        msg = "signature lifetime is invalid"
        raise ValueError(msg)
    expires = created + signature_lifetime
    headers = dict(view.headers_dict())
    headers["content-digest"] = content_digest_sha256(view.body)
    if "content-type" not in {name.lower() for name in headers}:
        msg = "content-type is required"
        raise ValueError(msg)
    if "idempotency-key" not in {name.lower() for name in headers}:
        msg = "idempotency-key is required"
        raise ValueError(msg)
    if policy.require_authorization_component and "authorization" not in {name.lower() for name in headers}:
        msg = "authorization is required for DPoP variant"
        raise ValueError(msg)
    # Canonical lowercase names for covered components.
    normalized = {name.lower(): value for name, value in headers.items()}
    adapter = _MessageAdapter(method=view.method, url=view.target_uri, headers=normalized)
    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.ED25519,
        key_resolver=_KeyResolver({key_id: private_key}),
    )
    signer.sign(
        adapter,
        key_id=key_id,
        created=created,
        expires=expires,
        nonce=nonce,
        label=policy.signature_label,
        tag=policy.profile_tag,
        covered_component_ids=list(policy.covered_components),
        include_alg=True,
    )
    # Reconstruct header tuple preserving signature headers from the adapter.
    final_headers = tuple((name, value) for name, value in adapter.headers.items())
    return HttpMessageView(method=view.method, target_uri=view.target_uri, headers=final_headers, body=view.body)
