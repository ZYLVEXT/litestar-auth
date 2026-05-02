"""PKCE S256 primitives for OAuth authorization-code flows."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Literal

_PKCE_CODE_VERIFIER_LENGTH = 64
_PKCE_CODE_CHALLENGE_METHOD: Literal["S256"] = "S256"
_PKCE_UNRESERVED_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


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
    """Generate an RFC 7636 code verifier from the unreserved URI alphabet.

    Returns:
        A 64-character verifier suitable for S256 PKCE.

    Raises:
        RuntimeError: If the generated verifier violates the PKCE alphabet or length contract.
    """
    code_verifier = secrets.token_urlsafe(64)[:_PKCE_CODE_VERIFIER_LENGTH]
    if len(code_verifier) != _PKCE_CODE_VERIFIER_LENGTH or not set(code_verifier) <= _PKCE_UNRESERVED_ALPHABET:
        msg = "Generated PKCE code verifier is invalid."
        raise RuntimeError(msg)
    return code_verifier


def _build_pkce_code_challenge(code_verifier: str) -> str:
    """Return the unpadded base64url SHA-256 challenge for a PKCE verifier.

    Returns:
        RFC 7636 S256 code challenge.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
