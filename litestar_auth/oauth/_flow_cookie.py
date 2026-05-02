"""Encrypted OAuth flow-cookie envelope primitives."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Any, NoReturn

import msgspec
from litestar.exceptions import ClientException

from litestar_auth.config import validate_secret_length
from litestar_auth.exceptions import ErrorCode

_OAUTH_FLOW_COOKIE_VERSION = "v2"
_OAUTH_FLOW_COOKIE_SEPARATOR = "."
_OAUTH_FLOW_COOKIE_FERNET_KEY_BYTES = 32
_OAUTH_FLOW_COOKIE_HKDF_SALT = b"litestar-auth:oauth-flow-cookie:v2"
_OAUTH_FLOW_COOKIE_HKDF_INFO = b"litestar-auth OAuth flow-cookie Fernet key"


@dataclass(frozen=True, slots=True)
class _OAuthFlowCookie:
    """OAuth flow material persisted between authorize and callback.

    The serialized form is encrypted by :class:`_OAuthFlowCookieCipher`; the
    dataclass itself never crosses the browser boundary in plaintext.
    """

    state: str
    code_verifier: str


@dataclass(frozen=True, slots=True)
class _OAuthFlowCookieCipher:
    """Encrypt and authenticate transient OAuth state + PKCE verifier material."""

    _fernet: Any
    _invalid_token_type: type[Exception]

    @classmethod
    def from_secret(cls, secret: str) -> _OAuthFlowCookieCipher:
        """Return a Fernet-backed cipher derived from the configured server secret.

        Args:
            secret: High-entropy secret used only for transient OAuth flow-cookie encryption.

        Returns:
            Cipher instance that hides the raw secret from repr output.

        Raises:
            ImportError: If the optional OAuth crypto dependency is not installed.
        """
        validate_secret_length(secret, label="oauth_flow_cookie_secret")
        try:
            from cryptography.fernet import Fernet, InvalidToken  # noqa: PLC0415
            from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: PLC0415
        except ImportError as exc:
            msg = "Install litestar-auth[oauth] to use encrypted OAuth flow cookies."
            raise ImportError(msg) from exc

        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=_OAUTH_FLOW_COOKIE_FERNET_KEY_BYTES,
            salt=_OAUTH_FLOW_COOKIE_HKDF_SALT,
            info=_OAUTH_FLOW_COOKIE_HKDF_INFO,
        ).derive(secret.encode("utf-8"))
        return cls(_fernet=Fernet(urlsafe_b64encode(key_material)), _invalid_token_type=InvalidToken)

    def encrypt(self, flow_cookie: _OAuthFlowCookie) -> str:
        """Return a versioned encrypted cookie value."""
        payload = msgspec.json.encode(flow_cookie)
        token = self._fernet.encrypt(payload).decode("ascii").rstrip("=")
        return f"{_OAUTH_FLOW_COOKIE_VERSION}{_OAUTH_FLOW_COOKIE_SEPARATOR}{token}"

    def decrypt(self, cookie_value: str | None) -> _OAuthFlowCookie:
        """Decrypt and validate a cookie value, mapping every failure to invalid state.

        Returns:
            Decrypted OAuth flow material.
        """
        if not cookie_value:
            _raise_invalid_oauth_state()
        version, separator, token = cookie_value.partition(_OAUTH_FLOW_COOKIE_SEPARATOR)
        if version != _OAUTH_FLOW_COOKIE_VERSION or separator != _OAUTH_FLOW_COOKIE_SEPARATOR or not token:
            _raise_invalid_oauth_state()

        try:
            padding = "=" * (-len(token) % 4)
            payload = self._fernet.decrypt(f"{token}{padding}".encode("ascii"))
            flow_cookie = msgspec.json.decode(payload, type=_OAuthFlowCookie)
        except (UnicodeEncodeError, ValueError, self._invalid_token_type, msgspec.DecodeError):
            _raise_invalid_oauth_state()

        if not flow_cookie.state or not flow_cookie.code_verifier:
            _raise_invalid_oauth_state()
        return flow_cookie


def _raise_invalid_oauth_state() -> NoReturn:
    """Raise the stable invalid OAuth state response.

    Raises:
        ClientException: Always raised with the public invalid-state response shape.
    """
    raise ClientException(
        status_code=400,
        detail="Invalid OAuth state.",
        extra={"code": ErrorCode.OAUTH_STATE_INVALID.value},
    )
