"""Versioned Fernet storage helpers for secrets persisted at rest."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol, cast

from litestar_auth._optional_deps import require_cryptography_fernet

FERNET_STORAGE_PREFIX = "fernet"
FERNET_STORAGE_VERSION = "v1"
_STORAGE_SEPARATOR = ":"
_VERSIONED_FERNET_PARTS = 4
_FERNET_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", re.ASCII)
_FERNET_INSTALL_HINT = "Install litestar-auth[oauth,totp] to use Fernet secret-at-rest encryption."

type FernetKey = str | bytes


class _FernetCipher(Protocol):
    """Runtime Fernet cipher surface used by the keyring."""

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt bytes and return a Fernet token."""

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt a Fernet token and return plaintext bytes."""


class _FernetFactory(Protocol):
    """Runtime Fernet constructor surface used by the keyring."""

    def __call__(self, key: bytes) -> _FernetCipher:
        """Build a Fernet cipher for a raw Fernet key."""


class _FernetModule(Protocol):
    """Runtime cryptography.fernet module surface used by the keyring."""

    Fernet: _FernetFactory
    InvalidToken: type[Exception]


type FernetModuleLoader = Callable[[], _FernetModule]


def _load_cryptography_fernet() -> _FernetModule:
    """Load ``cryptography.fernet`` with the secret-at-rest install hint.

    Returns:
        The imported ``cryptography.fernet`` module.
    """
    return cast("_FernetModule", require_cryptography_fernet(install_hint=_FERNET_INSTALL_HINT))


class SecretAtRestError(RuntimeError):
    """Raised when versioned Fernet storage cannot be processed safely."""


class UnknownFernetKeyError(SecretAtRestError):
    """Raised when stored data references a key id absent from the keyring."""


@dataclass(frozen=True, slots=True)
class VersionedFernetValue:
    """Parsed ``fernet:v1:<key_id>:<ciphertext>`` storage value."""

    key_id: str
    ciphertext: str

    def encode(self) -> str:
        """Return this parsed value encoded for storage."""
        return encode_versioned_fernet_value(key_id=self.key_id, ciphertext=self.ciphertext)


@dataclass(frozen=True, slots=True)
class FernetKeyring:
    """Small versioned-Fernet keyring for encrypting secrets at rest."""

    active_key_id: str
    keys: Mapping[str, FernetKey] = field(repr=False)
    _load_cryptography_fernet: FernetModuleLoader = field(
        default=_load_cryptography_fernet,
        repr=False,
        compare=False,
        hash=False,
    )
    _fernet_by_key_id: Mapping[str, _FernetCipher] = field(init=False, repr=False, compare=False, hash=False)
    _invalid_token_error: type[Exception] = field(init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        """Validate the keyring and mount Fernet ciphers for each configured key.

        Raises:
            SecretAtRestError: If the keyring shape or configured key material is invalid.
        """
        normalized_keys = _normalize_keys(self.keys)
        if not normalized_keys:
            msg = "Fernet keyring requires at least one configured key."
            raise SecretAtRestError(msg)

        active_key_id = validate_fernet_key_id(self.active_key_id)
        if active_key_id not in normalized_keys:
            msg = "Fernet keyring active key id must reference a configured key."
            raise SecretAtRestError(msg)

        fernet_module = self._load_cryptography_fernet()
        fernet_by_key_id: dict[str, _FernetCipher] = {}
        for key_id, key in normalized_keys.items():
            try:
                fernet_by_key_id[key_id] = fernet_module.Fernet(_coerce_fernet_key(key))
            except (TypeError, ValueError) as exc:
                msg = "Configured Fernet key material is invalid."
                raise SecretAtRestError(msg) from exc

        object.__setattr__(self, "active_key_id", active_key_id)
        object.__setattr__(self, "keys", MappingProxyType(normalized_keys))
        object.__setattr__(self, "_fernet_by_key_id", MappingProxyType(fernet_by_key_id))
        object.__setattr__(self, "_invalid_token_error", fernet_module.InvalidToken)

    def __repr__(self) -> str:
        """Return a representation that never exposes raw Fernet keys."""
        masked_keys = dict.fromkeys(self.keys, "***")
        return f"{type(self).__name__}(active_key_id={self.active_key_id!r}, keys={masked_keys!r})"

    __str__ = __repr__

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext with the active key and return a versioned storage value.

        Returns:
            A ``fernet:v1:<key_id>:<ciphertext>`` storage value.
        """
        ciphertext = self._fernet_by_key_id[self.active_key_id].encrypt(plaintext.encode("utf-8")).decode("utf-8")
        return encode_versioned_fernet_value(key_id=self.active_key_id, ciphertext=ciphertext)

    def decrypt(self, stored: str) -> str:
        """Decrypt a versioned storage value with the key id embedded in that value.

        Returns:
            The decrypted plaintext secret.

        Raises:
            SecretAtRestError: If the value is malformed or cannot be decrypted.
        """
        parsed = decode_versioned_fernet_value(stored)
        fernet = self._fernet_for_key_id(parsed.key_id)
        try:
            return fernet.decrypt(parsed.ciphertext.encode("utf-8")).decode("utf-8")
        except self._invalid_token_error as exc:
            msg = "Fernet secret decryption failed; key may be wrong or data corrupted."
            raise SecretAtRestError(msg) from exc

    def needs_rotation(self, stored: str) -> bool:
        """Return whether a stored value should be rewritten with the active key id."""
        parsed = decode_versioned_fernet_value(stored)
        self._fernet_for_key_id(parsed.key_id)
        return parsed.key_id != self.active_key_id

    def _fernet_for_key_id(self, key_id: str) -> _FernetCipher:
        """Return the Fernet cipher for ``key_id`` or fail closed.

        Raises:
            UnknownFernetKeyError: If the key id is absent from the keyring.
        """
        fernet = self._fernet_by_key_id.get(key_id)
        if fernet is None:
            msg = "Stored Fernet secret references an unknown key id."
            raise UnknownFernetKeyError(msg)
        return fernet


def validate_fernet_key_id(key_id: str) -> str:
    """Return a validated Fernet key id.

    Raises:
        SecretAtRestError: If the key id is empty, non-ASCII, too long, or contains unsupported characters.
    """
    if _FERNET_KEY_ID_RE.fullmatch(key_id) is None:
        msg = "Fernet key ids must be 1-64 ASCII letters, digits, underscores, or hyphens."
        raise SecretAtRestError(msg)
    return key_id


def encode_versioned_fernet_value(*, key_id: str, ciphertext: str) -> str:
    """Encode a Fernet ciphertext with a version and validated key id.

    Returns:
        A ``fernet:v1:<key_id>:<ciphertext>`` storage value.

    Raises:
        SecretAtRestError: If the key id or ciphertext is invalid.
    """
    validated_key_id = validate_fernet_key_id(key_id)
    if not ciphertext:
        msg = "Versioned Fernet storage requires a non-empty ciphertext."
        raise SecretAtRestError(msg)
    return _STORAGE_SEPARATOR.join(
        (FERNET_STORAGE_PREFIX, FERNET_STORAGE_VERSION, validated_key_id, ciphertext),
    )


def decode_versioned_fernet_value(stored: str) -> VersionedFernetValue:
    """Decode a ``fernet:v1:<key_id>:<ciphertext>`` storage value.

    Returns:
        The parsed key id and ciphertext.

    Raises:
        SecretAtRestError: If the storage value is malformed.
    """
    parts = stored.split(_STORAGE_SEPARATOR, _VERSIONED_FERNET_PARTS - 1)
    if len(parts) != _VERSIONED_FERNET_PARTS or parts[0] != FERNET_STORAGE_PREFIX:
        msg = "Stored Fernet secret must use fernet:v1:<key_id>:<ciphertext>."
        raise SecretAtRestError(msg)
    if parts[1] != FERNET_STORAGE_VERSION:
        msg = "Stored Fernet secret uses an unsupported storage version."
        raise SecretAtRestError(msg)
    if not parts[3]:
        msg = "Stored Fernet secret is missing ciphertext."
        raise SecretAtRestError(msg)
    return VersionedFernetValue(key_id=validate_fernet_key_id(parts[2]), ciphertext=parts[3])


def _normalize_keys(keys: Mapping[str, FernetKey]) -> dict[str, FernetKey]:
    """Return a validated copy of configured Fernet keys."""
    normalized: dict[str, FernetKey] = {}
    for key_id, key in keys.items():
        normalized[validate_fernet_key_id(key_id)] = key
    return normalized


def _coerce_fernet_key(key: FernetKey) -> bytes:
    """Return key material as bytes for ``cryptography.fernet.Fernet``."""
    return key if isinstance(key, bytes) else key.encode("utf-8")
