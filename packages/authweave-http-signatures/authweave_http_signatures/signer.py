"""Local Ed25519 payment-message signing helper."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms

from authweave_http_signatures.digest import content_digest_sha256
from authweave_http_signatures.models import HttpMessageView, PaymentSignaturePolicy


@dataclass
class _MessageAdapter:
    """Minimal request shape accepted by ``http-message-signatures``."""

    method: str
    url: str = field(repr=False)
    headers: dict[str, str] = field(repr=False)


class _KeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, keys: dict[str, Ed25519PrivateKey]) -> None:
        self._keys = keys

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        return self._keys[key_id]

    def resolve_public_key(self, key_id: str) -> object:
        return self._keys[key_id].public_key()


def sign_payment_message(
    *,
    view: HttpMessageView,
    policy: PaymentSignaturePolicy,
    key_id: str,
    private_key: Ed25519PrivateKey,
    nonce: str,
    now: datetime | None = None,
    lifetime: timedelta | None = None,
) -> HttpMessageView:
    """Attach profile-v1 digest and signature headers with a local private key.

    This reference helper is for tests and in-process signers. Production KMS/HSM
    integrations should construct the same RFC 9421 profile outside AuthWeave so
    private key material remains non-exportable.

    Returns:
        A new ``HttpMessageView`` with digest and signature headers applied.

    Raises:
        ValueError: If required application headers are missing.
    """
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
