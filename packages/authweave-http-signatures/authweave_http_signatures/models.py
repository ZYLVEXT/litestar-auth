"""Immutable HTTP message view and payment signature policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

PROFILE_TAG: Final = "authweave-payment-http-sig-v1"
SIGNATURE_LABEL: Final = "payment"
DEFAULT_MAX_BODY_BYTES: Final = 262_144
DEFAULT_MAX_CLOCK_SKEW_SECONDS: Final = 30
DEFAULT_MAX_SIGNATURE_LIFETIME_SECONDS: Final = 300
DEFAULT_NONCE_TTL_SECONDS: Final = 600
JSON_MEDIA_TYPES: Final = frozenset({"application/json", "application/json; charset=utf-8"})

_COVERED_BASE: Final = ("@method", "@target-uri", "content-digest", "content-type", "idempotency-key")
_COVERED_DPOP: Final = (*_COVERED_BASE, "authorization")


@dataclass(frozen=True, slots=True)
class HttpMessageView:
    """Exact raw HTTP request projection used for digest and signature checks."""

    method: str
    target_uri: str = field(repr=False)
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    body: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        """Reject empty method/target or oversized metadata.

        Raises:
            ValueError: If the call cannot complete.
        """
        if not self.method or not self.method.isascii() or any(ch.isspace() for ch in self.method):
            msg = "method must be non-empty printable ASCII without whitespace"
            raise ValueError(msg)
        if not self.target_uri or not self.target_uri.startswith("https://"):
            msg = "target_uri must be an absolute https URI"
            raise ValueError(msg)
        if len(self.body) > DEFAULT_MAX_BODY_BYTES * 2:
            msg = "body exceeds absolute safety ceiling"
            raise ValueError(msg)

    def header(self, name: str) -> str | None:
        """Return the single value for ``name`` (case-insensitive) or ``None``.

        Returns:
            The header value when present exactly once.

        Raises:
            ValueError: If the call cannot complete.
        """
        needle = name.lower()
        matches = [value for header, value in self.headers if header.lower() == needle]
        if len(matches) > 1:
            msg = f"duplicate header: {name}"
            raise ValueError(msg)
        return matches[0] if matches else None

    def headers_dict(self) -> dict[str, str]:
        """Return a case-preserving single-value header mapping.

        Returns:
            Header name to value.

        Raises:
            ValueError: If any header name is duplicated.
        """
        result: dict[str, str] = {}
        for name, value in self.headers:
            key = name.lower()
            if key in {item.lower() for item in result}:
                msg = f"duplicate header: {name}"
                raise ValueError(msg)
            result[name] = value
        return result


@dataclass(frozen=True, slots=True)
class PaymentSignaturePolicy:
    """Exact payment HTTP signature profile v1 policy."""

    require_authorization_component: bool = False
    allow_query: bool = False
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS
    max_signature_lifetime_seconds: int = DEFAULT_MAX_SIGNATURE_LIFETIME_SECONDS
    nonce_ttl_seconds: int = DEFAULT_NONCE_TTL_SECONDS
    json_media_types: frozenset[str] = field(default_factory=lambda: JSON_MEDIA_TYPES)
    profile_tag: str = PROFILE_TAG
    signature_label: str = SIGNATURE_LABEL

    def __post_init__(self) -> None:
        """Reject non-positive bounds or empty profile identity.

        Raises:
            ValueError: If the call cannot complete.
        """
        if self.max_body_bytes <= 0 or self.max_clock_skew_seconds < 0:
            msg = "body/clock policy is invalid"
            raise ValueError(msg)
        if self.max_signature_lifetime_seconds <= 0 or self.nonce_ttl_seconds <= 0:
            msg = "lifetime policy is invalid"
            raise ValueError(msg)
        if not self.profile_tag or not self.signature_label or not self.json_media_types:
            msg = "profile identity and media types are required"
            raise ValueError(msg)

    @property
    def covered_components(self) -> tuple[str, ...]:
        """The exact covered-component list for this route variant.

        Returns:
            Covered component identifiers in profile order.
        """
        return _COVERED_DPOP if self.require_authorization_component else _COVERED_BASE


@dataclass(frozen=True, slots=True)
class VerifiedHttpSignature:
    """Secret-free result after digest, signature, binding, and nonce checks."""

    key_id: str
    nonce: str
    profile_tag: str
    created: int
    expires: int
    idempotency_key: str
    content_type: str
    body: bytes

    def __repr__(self) -> str:
        """Omit raw body bytes from representations.

        Returns:
            The repr  .
        """
        return (
            "VerifiedHttpSignature("
            f"key_id={self.key_id!r}, nonce=..., profile_tag={self.profile_tag!r}, "
            f"idempotency_key={self.idempotency_key!r})"
        )
