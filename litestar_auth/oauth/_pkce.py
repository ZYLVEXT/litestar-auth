"""PKCE S256 primitives for OAuth authorization-code flows."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Literal

_PKCE_CODE_VERIFIER_LENGTH = 64
# 48 random bytes encode to exactly 64 unpadded base64url characters
# (48 == 16 * 3, so base64 needs no padding). 384 bits of entropy comfortably
# exceed the RFC 7636 §4.1 256-bit recommendation, and ``secrets.token_urlsafe``
# emits only ``[A-Za-z0-9_-]`` — a strict subset of the PKCE unreserved alphabet
# ``[A-Za-z0-9-._~]`` — so output is RFC-conformant by construction without any
# truncation or alphabet filtering at runtime.
_PKCE_VERIFIER_RANDOM_BYTES = 48
_PKCE_CODE_CHALLENGE_METHOD: Literal["S256"] = "S256"


@dataclass(frozen=True, slots=True)
class PkceMaterial:
    """PKCE S256 material generated for one OAuth authorization-code flow."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: Literal["S256"]


def _generate_pkce_material() -> PkceMaterial:
    """Generate PKCE S256 material for one authorization-code flow.

    Returns:
        Verifier, challenge, and S256 method marker for provider authorization.
    """
    code_verifier = _generate_pkce_code_verifier()
    return PkceMaterial(
        code_verifier=code_verifier,
        code_challenge=_build_pkce_code_challenge(code_verifier),
        code_challenge_method=_PKCE_CODE_CHALLENGE_METHOD,
    )


def _generate_pkce_code_verifier() -> str:
    """Generate an RFC 7636 §4.1 code verifier (64 chars, 384 bits of entropy).

    The verifier is drawn directly from ``secrets.token_urlsafe`` — its alphabet
    ``[A-Za-z0-9_-]`` is a strict subset of the PKCE unreserved alphabet, and 48
    random bytes encode to exactly 64 unpadded base64url characters, so no
    truncation or alphabet filtering is needed at runtime.

    Returns:
        A 64-character verifier suitable for S256 PKCE.

    Raises:
        RuntimeError: If the platform RNG returned material of unexpected length.
    """
    code_verifier = secrets.token_urlsafe(_PKCE_VERIFIER_RANDOM_BYTES)
    if len(code_verifier) != _PKCE_CODE_VERIFIER_LENGTH:
        # Defensive: ``token_urlsafe(48)`` is contractually 64 chars on CPython.
        # Catching a length drift here surfaces interpreter regressions before
        # the verifier reaches a provider's PKCE validation.
        msg = "Generated PKCE code verifier has unexpected length."
        raise RuntimeError(msg)
    return code_verifier


def _build_pkce_code_challenge(code_verifier: str) -> str:
    """Return the unpadded base64url SHA-256 challenge for a PKCE verifier.

    Returns:
        RFC 7636 S256 code challenge.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
