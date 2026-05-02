"""Internal helpers for TOTP enrollment-token state."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Self, cast

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from litestar_auth._optional_deps import require_cryptography_fernet
from litestar_auth._secrets_at_rest import FernetKeyring, SecretAtRestError
from litestar_auth.config import TOTP_ENROLL_AUDIENCE
from litestar_auth.exceptions import ConfigurationError, TokenError
from litestar_auth.totp_flow import InvalidTotpPendingTokenError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import ModuleType

    from litestar_auth._secrets_at_rest import FernetKey
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.totp import TotpEnrollmentStore

_TOTP_ENROLL_TOKEN_LIFETIME_SECONDS = 300  # 5 minutes
_DEFAULT_TOTP_FERNET_KEY_ID = "default"
_ENROLLMENT_ENCODING_CLAIM = "enc"
_ENROLLMENT_ENCODING_FERNET = "fernet"
_ENROLLMENT_ENCODING_PLAIN = "plain"
_TOTP_ENROLLMENT_FERNET_INSTALL_HINT = "Install litestar-auth[totp] to use TOTP enrollment-token encryption."


_load_cryptography_fernet = cast(
    "Callable[[], ModuleType]",
    partial(require_cryptography_fernet, install_hint=_TOTP_ENROLLMENT_FERNET_INSTALL_HINT),
)


@dataclass(frozen=True, slots=True)
class _EnrollmentTokenCipher:
    """Fernet cipher dedicated to server-side TOTP enrollment secret values."""

    _keyring: FernetKeyring
    _legacy_single_key_id: str | None = None

    @classmethod
    def from_keyring(
        cls,
        *,
        active_key_id: str,
        keys: Mapping[str, FernetKey],
        legacy_single_key_id: str | None = None,
    ) -> Self:
        """Build a cipher from a versioned Fernet keyring.

        Returns:
            A cipher bound to the provided keyring for enrollment-token claims.

        Raises:
            SecretAtRestError: If the keyring or legacy key id is invalid.
        """
        keyring = FernetKeyring(
            active_key_id=active_key_id,
            keys=keys,
            _load_cryptography_fernet=cast("Any", _load_cryptography_fernet),
        )
        if legacy_single_key_id is not None and legacy_single_key_id not in keyring.keys:
            msg = "Legacy single-key id must reference a configured Fernet key."
            raise SecretAtRestError(msg)
        return cls(
            _keyring=keyring,
            _legacy_single_key_id=legacy_single_key_id,
        )

    def encrypt(self, plaintext: str) -> str:
        """Return a Fernet token string for the provided plaintext secret.

        Returns:
            Fernet-encrypted ciphertext decoded as a UTF-8 string.
        """
        return self._keyring.encrypt(plaintext)

    def decrypt(self, ciphertext: str) -> str | None:
        """Decrypt a Fernet token string.

        Returns:
            The plaintext secret, or ``None`` when the ciphertext is invalid.
        """
        try:
            return self._keyring.decrypt(ciphertext)
        except SecretAtRestError:
            return self._decrypt_legacy_single_key_value(ciphertext)

    def _decrypt_legacy_single_key_value(self, ciphertext: str) -> str | None:
        """Return plaintext for raw Fernet values minted by the former single-key path."""
        if self._legacy_single_key_id is None:
            return None
        key = self._keyring.keys[self._legacy_single_key_id]
        fernet_module = cast("Any", _load_cryptography_fernet())
        key_material = key if isinstance(key, bytes) else key.encode("utf-8")
        fernet = fernet_module.Fernet(key_material)
        try:
            return cast("str", fernet.decrypt(ciphertext.encode()).decode())
        except fernet_module.InvalidToken:
            return None


def _resolve_enrollment_token_cipher(
    *,
    totp_secret_key: str | None,
    totp_secret_keyring: FernetKeyringConfig | None = None,
    unsafe_testing: bool,
) -> _EnrollmentTokenCipher | None:
    """Build the enrollment secret-value cipher, enforcing production posture.

    Returns:
        A cipher when ``totp_secret_keyring`` or ``totp_secret_key`` is configured,
        otherwise ``None`` (only allowed in explicit ``unsafe_testing`` mode).

    Raises:
        ConfigurationError: If key inputs are ambiguous or missing outside explicit
            ``unsafe_testing`` mode.
    """
    if totp_secret_key is not None and totp_secret_keyring is not None:
        msg = "Configure TOTP enrollment encryption with totp_secret_key or totp_secret_keyring, not both."
        raise ConfigurationError(msg)
    if totp_secret_keyring is not None:
        return _EnrollmentTokenCipher.from_keyring(
            active_key_id=totp_secret_keyring.active_key_id,
            keys=totp_secret_keyring.keys,
        )
    if totp_secret_key is not None:
        return _EnrollmentTokenCipher.from_keyring(
            active_key_id=_DEFAULT_TOTP_FERNET_KEY_ID,
            keys={_DEFAULT_TOTP_FERNET_KEY_ID: totp_secret_key},
            legacy_single_key_id=_DEFAULT_TOTP_FERNET_KEY_ID,
        )
    if unsafe_testing:
        return None

    msg = (
        "totp_secret_keyring or totp_secret_key is required when unsafe_testing=False. "
        "TOTP enrollment secrets must be encrypted before they are written to the enrollment store."
    )
    raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class _EnrollmentTokenClaims:
    """Validated enrollment-token claims needed to consume server-side state."""

    user_id: str
    jti: str
    encoding: str


def _sign_enrollment_token(
    *,
    user_id: str,
    signing_key: str,
    jti: str,
    encoding: str,
    lifetime_seconds: int = _TOTP_ENROLL_TOKEN_LIFETIME_SECONDS,
) -> str:
    """Sign a short-lived JWT pointing at server-side TOTP enrollment state.

    Returns:
        Encoded JWT string.
    """
    issued_at = datetime.now(tz=UTC)
    payload = {
        "sub": user_id,
        "aud": TOTP_ENROLL_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + timedelta(seconds=lifetime_seconds),
        "jti": jti,
        _ENROLLMENT_ENCODING_CLAIM: encoding,
    }
    return jwt.encode(payload, signing_key, algorithm="HS256")


def _encode_enrollment_secret(secret: str, *, cipher: _EnrollmentTokenCipher | None) -> tuple[str, str]:
    """Return the server-side enrollment-store value and its encoding marker."""
    if cipher is None:
        return secret, _ENROLLMENT_ENCODING_PLAIN
    return cipher.encrypt(secret), _ENROLLMENT_ENCODING_FERNET


def _decode_enrollment_secret(
    encoded_secret: str,
    *,
    cipher: _EnrollmentTokenCipher | None,
    encoding: str,
) -> str | None:
    """Return the plain-text enrollment secret from a server-side store value."""
    if cipher is None:
        return encoded_secret if encoding == _ENROLLMENT_ENCODING_PLAIN else None
    if encoding != _ENROLLMENT_ENCODING_FERNET:
        return None
    return cipher.decrypt(encoded_secret)


@dataclass(frozen=True, slots=True)
class _EnrollmentTokenIssueConfig:
    signing_key: str
    cipher: _EnrollmentTokenCipher | None
    enrollment_store: TotpEnrollmentStore
    lifetime_seconds: int = _TOTP_ENROLL_TOKEN_LIFETIME_SECONDS


async def _issue_enrollment_token(
    *,
    user_id: str,
    secret: str,
    config: _EnrollmentTokenIssueConfig,
) -> str:
    """Store pending enrollment state and return a signed client token.

    Returns:
        Signed enrollment JWT containing lookup claims for the stored secret.

    Raises:
        TokenError: If the enrollment store refuses the write.
    """
    jti = secrets.token_hex(16)
    encoded_secret, encoding = _encode_enrollment_secret(secret, cipher=config.cipher)
    stored = await config.enrollment_store.save(
        user_id=user_id,
        jti=jti,
        secret=encoded_secret,
        ttl_seconds=config.lifetime_seconds,
    )
    if not stored:
        msg = (
            "Could not record TOTP enrollment state (in-memory store at capacity). "
            "Use RedisTotpEnrollmentStore or increase max_entries."
        )
        raise TokenError(msg)
    return _sign_enrollment_token(
        user_id=user_id,
        signing_key=config.signing_key,
        jti=jti,
        encoding=encoding,
        lifetime_seconds=config.lifetime_seconds,
    )


def _decode_enrollment_token(
    token: str,
    *,
    signing_key: str,
    expected_user_id: str,
    cipher: _EnrollmentTokenCipher | None,
) -> _EnrollmentTokenClaims:
    """Decode and validate an enrollment JWT.

    The ``enc`` claim must match the currently configured cipher posture:
    tokens minted in plaintext mode are rejected when a cipher is active, and
    Fernet-encoded tokens are rejected when no cipher is configured.

    Returns:
        Validated enrollment claims used to consume server-side state.

    """
    payload = _decode_enrollment_token_payload(token, signing_key=signing_key)
    _validate_enrollment_token_subject(payload, expected_user_id=expected_user_id)
    jti = _validate_enrollment_token_jti(payload)
    encoding = _validate_enrollment_token_encoding(payload, cipher=cipher)

    return _EnrollmentTokenClaims(user_id=expected_user_id, jti=jti, encoding=encoding)


def _decode_enrollment_token_payload(token: str, *, signing_key: str) -> Mapping[str, Any]:
    """Decode a signed enrollment JWT into its raw claim payload.

    Returns:
        The decoded JWT claims.

    Raises:
        InvalidTotpPendingTokenError: If the token is expired or invalid.
    """
    try:
        return cast(
            "Mapping[str, Any]",
            jwt.decode(
                token,
                signing_key,
                algorithms=["HS256"],
                audience=TOTP_ENROLL_AUDIENCE,
                options={
                    "require": [
                        "exp",
                        "aud",
                        "iat",
                        "nbf",
                        "jti",
                        "sub",
                        _ENROLLMENT_ENCODING_CLAIM,
                    ],
                },
            ),
        )
    except (ExpiredSignatureError, InvalidTokenError) as exc:
        raise InvalidTotpPendingTokenError from exc


def _validate_enrollment_token_subject(payload: Mapping[str, Any], *, expected_user_id: str) -> None:
    """Reject enrollment JWTs whose subject does not match the authenticated user.

    Raises:
        InvalidTotpPendingTokenError: If the subject is missing, malformed, or mismatched.
    """
    subject = payload.get("sub")
    if not isinstance(subject, str) or not hmac.compare_digest(subject, expected_user_id):
        raise InvalidTotpPendingTokenError


def _validate_enrollment_token_jti(payload: Mapping[str, Any]) -> str:
    """Return a validated hex enrollment-token identifier.

    Returns:
        A 32-character hexadecimal enrollment token identifier.

    Raises:
        InvalidTotpPendingTokenError: If the identifier is missing or malformed.
    """
    jti = payload.get("jti")
    if not isinstance(jti, str) or len(jti) != 32:  # noqa: PLR2004
        raise InvalidTotpPendingTokenError
    try:
        bytes.fromhex(jti)
    except ValueError as exc:
        raise InvalidTotpPendingTokenError from exc
    return jti


def _validate_enrollment_token_encoding(
    payload: Mapping[str, Any],
    *,
    cipher: _EnrollmentTokenCipher | None,
) -> str:
    """Return the enrollment secret encoding when it matches the configured cipher posture.

    Returns:
        The validated encoding marker.

    Raises:
        InvalidTotpPendingTokenError: If the encoding claim does not match the configured cipher.
    """
    expected_encoding = _ENROLLMENT_ENCODING_FERNET if cipher is not None else _ENROLLMENT_ENCODING_PLAIN
    encoding = payload.get(_ENROLLMENT_ENCODING_CLAIM)
    if encoding != expected_encoding:
        raise InvalidTotpPendingTokenError
    return cast("str", encoding)


async def _consume_enrollment_secret(
    claims: _EnrollmentTokenClaims,
    *,
    enrollment_store: TotpEnrollmentStore,
    cipher: _EnrollmentTokenCipher | None,
) -> str:
    """Consume server-side enrollment state and return the plain-text TOTP secret.

    Returns:
        Plain-text TOTP secret for code verification and persistence.

    Raises:
        InvalidTotpPendingTokenError: If the state is missing, stale, reused, or undecryptable.
    """
    encoded_secret = await enrollment_store.consume(user_id=claims.user_id, jti=claims.jti)
    if not encoded_secret:
        raise InvalidTotpPendingTokenError
    secret = _decode_enrollment_secret(encoded_secret, cipher=cipher, encoding=claims.encoding)
    if not secret:
        raise InvalidTotpPendingTokenError
    return secret
