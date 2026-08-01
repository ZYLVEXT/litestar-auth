"""Asymmetric Standard Webhooks toolkit for AuthWeave integrations."""

from authweave_webhooks.duplicate import DuplicateDeliveryGuard
from authweave_webhooks.errors import WebhookFailureCode, WebhookVerificationError
from authweave_webhooks.headers import build_signing_input, format_signature_header, parse_headers
from authweave_webhooks.keys import PublicKeyResolver, StaticPublicKeyResolver
from authweave_webhooks.models import (
    DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    HEADER_ID,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    MAX_BODY_BYTES,
    MAX_PUBLIC_KEYS,
    MAX_SIGNATURES,
    MAX_WEBHOOK_ID_LENGTH,
    SIGNATURE_VERSION,
    Ed25519PublicKey,
    PublicKeyDocument,
    VerifiedWebhook,
    WebhookDelivery,
)
from authweave_webhooks.signer import AsyncMessageSigner, LocalEd25519KeyringSigner, create_delivery
from authweave_webhooks.verify import StandardWebhooksVerifier

__version__ = "7.1.0"

__all__ = (
    "DEFAULT_TIMESTAMP_TOLERANCE_SECONDS",
    "HEADER_ID",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "MAX_BODY_BYTES",
    "MAX_PUBLIC_KEYS",
    "MAX_SIGNATURES",
    "MAX_WEBHOOK_ID_LENGTH",
    "SIGNATURE_VERSION",
    "AsyncMessageSigner",
    "DuplicateDeliveryGuard",
    "Ed25519PublicKey",
    "LocalEd25519KeyringSigner",
    "PublicKeyDocument",
    "PublicKeyResolver",
    "StandardWebhooksVerifier",
    "StaticPublicKeyResolver",
    "VerifiedWebhook",
    "WebhookDelivery",
    "WebhookFailureCode",
    "WebhookVerificationError",
    "__version__",
    "build_signing_input",
    "create_delivery",
    "format_signature_header",
    "parse_headers",
)
