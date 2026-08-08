"""Payment HTTP Message Signatures profile for AuthWeave."""

from authweave_http_signatures.binding import SignatureKeyBinding
from authweave_http_signatures.digest import CONTENT_DIGEST_SHA256, content_digest_sha256, verify_content_digest
from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError
from authweave_http_signatures.models import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    DEFAULT_MAX_SIGNATURE_LIFETIME_SECONDS,
    DEFAULT_NONCE_TTL_SECONDS,
    JSON_MEDIA_TYPES,
    PROFILE_TAG,
    SIGNATURE_LABEL,
    HttpMessageView,
    PaymentSignaturePolicy,
    VerifiedHttpSignature,
)
from authweave_http_signatures.nonce import SignatureNonceGuard
from authweave_http_signatures.proxy_target import UNIX_SOCKET_PROXY, AllowlistedProxyExternalTarget
from authweave_http_signatures.signer import sign_payment_message
from authweave_http_signatures.verify import PaymentHttpSignatureVerifier

__version__ = "7.3.2"

__all__ = (
    "CONTENT_DIGEST_SHA256",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_SIGNATURE_LIFETIME_SECONDS",
    "DEFAULT_NONCE_TTL_SECONDS",
    "JSON_MEDIA_TYPES",
    "PROFILE_TAG",
    "SIGNATURE_LABEL",
    "UNIX_SOCKET_PROXY",
    "AllowlistedProxyExternalTarget",
    "HttpMessageView",
    "HttpSignatureFailureCode",
    "HttpSignatureVerificationError",
    "PaymentHttpSignatureVerifier",
    "PaymentSignaturePolicy",
    "SignatureKeyBinding",
    "SignatureNonceGuard",
    "VerifiedHttpSignature",
    "__version__",
    "content_digest_sha256",
    "sign_payment_message",
    "verify_content_digest",
)
