"""Security configuration contracts for the user manager."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from litestar_auth import config as _config
from litestar_auth._secrets_at_rest import FernetKey, FernetKeyring, SecretAtRestError, validate_fernet_key_id
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from litestar_auth.password import PasswordHelper

_MASKED = "**********"
_FERNET_KEYRING_PAIR_SIZE = 2

type FernetKeyringConfigKeys = MappingABC[str, FernetKey]


@dataclasses.dataclass(frozen=True, slots=True)
class FernetKeyringConfig:
    """Public configuration contract for versioned Fernet keyrings."""

    active_key_id: str
    keys: FernetKeyringConfigKeys = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        """Validate the keyring shape and configured Fernet key material.

        Raises:
            ConfigurationError: If the keyring shape or key material is invalid.
        """
        normalized_keys = _normalize_fernet_keyring_config_keys(self.keys)
        try:
            keyring = FernetKeyring(active_key_id=self.active_key_id, keys=normalized_keys)
        except SecretAtRestError as exc:
            raise ConfigurationError(str(exc)) from exc
        object.__setattr__(self, "active_key_id", keyring.active_key_id)
        object.__setattr__(self, "keys", MappingProxyType(dict(keyring.keys)))

    def __repr__(self) -> str:
        """Return a representation that masks every configured Fernet key."""
        masked_keys = dict.fromkeys(self.keys, "***")
        return f"{type(self).__name__}(active_key_id={self.active_key_id!r}, keys={masked_keys!r})"

    __str__ = __repr__


@dataclasses.dataclass(frozen=True, slots=True)
class UserManagerSecurity[ID]:
    """Typed public contract for manager secrets and related security inputs.

    Production deployments should keep verification, reset-password, login
    telemetry, and TOTP secret roles separate even though distinct JWT audiences
    already scope each token flow independently. Password helper and validator
    fields belong in this security bundle when a deployment needs to override
    those defaults.
    """

    verification_token_secret: str | None = dataclasses.field(default=None, repr=False)
    reset_password_token_secret: str | None = dataclasses.field(default=None, repr=False)
    login_identifier_telemetry_secret: str | None = dataclasses.field(default=None, repr=False)
    totp_secret_key: str | None = dataclasses.field(default=None, repr=False)
    totp_secret_keyring: FernetKeyringConfig | None = dataclasses.field(default=None, repr=False)
    id_parser: Callable[[str], ID] | None = dataclasses.field(default=None, repr=False)
    password_helper: PasswordHelper | None = dataclasses.field(default=None, repr=False)
    password_validator: Callable[[str], None] | None = dataclasses.field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject ambiguous TOTP secret-at-rest key inputs.

        Raises:
            ConfigurationError: If both one-key and keyring inputs are configured.
        """
        if self.totp_secret_key is None or self.totp_secret_keyring is None:
            return
        msg = "Configure TOTP secret encryption with totp_secret_key or totp_secret_keyring, not both."
        raise ConfigurationError(msg)

    def __repr__(self) -> str:
        """Return a repr that masks configured secret material."""
        return (
            "UserManagerSecurity("
            f"verification_token_secret={_mask_optional_secret(self.verification_token_secret)!r}, "
            f"reset_password_token_secret={_mask_optional_secret(self.reset_password_token_secret)!r}, "
            f"login_identifier_telemetry_secret="
            f"{_mask_optional_secret(self.login_identifier_telemetry_secret)!r}, "
            f"totp_secret_key={_mask_optional_secret(self.totp_secret_key)!r}, "
            f"totp_secret_keyring={self.totp_secret_keyring!r}, "
            f"id_parser={self.id_parser!r}, "
            f"password_helper={self.password_helper!r}, "
            f"password_validator={self.password_validator!r})"
        )


@dataclasses.dataclass(frozen=True, eq=False)
class _SecretValue:
    """Wraps a secret string so it is masked in repr/str output."""

    _value: str = dataclasses.field(repr=False)

    def get_secret_value(self) -> str:
        """Return the raw secret string."""
        return self._value

    def __repr__(self) -> str:
        return f"_SecretValue('{_MASKED}')"

    def __str__(self) -> str:
        return _MASKED


def _normalize_fernet_keyring_config_keys(keys: object) -> dict[str, FernetKey]:
    """Return a validated key-id mapping for public keyring configuration.

    Raises:
        ConfigurationError: If key ids are malformed, duplicated, or not provided as pairs.
    """
    normalized: dict[str, FernetKey] = {}
    for key_id, key in _iter_fernet_keyring_config_pairs(keys):
        validated_key_id = _validate_fernet_keyring_config_key_id(key_id)
        if validated_key_id in normalized:
            msg = "Fernet keyring key ids must be unique."
            raise ConfigurationError(msg)
        if not isinstance(key, (str, bytes)):
            msg = "Configured Fernet key material is invalid."
            raise ConfigurationError(msg)
        normalized[validated_key_id] = key
    return normalized


def _iter_fernet_keyring_config_pairs(keys: object) -> tuple[tuple[object, object], ...]:
    if isinstance(keys, MappingABC):
        items = tuple(keys.items())
    elif isinstance(keys, SequenceABC) and not isinstance(keys, (str, bytes, bytearray)):
        items = tuple(keys)
    else:
        msg = "FernetKeyringConfig keys must be a mapping or a sequence of key-id/key pairs."
        raise ConfigurationError(msg)

    return tuple(_coerce_fernet_keyring_config_pair(item) for item in items)


def _coerce_fernet_keyring_config_pair(item: object) -> tuple[object, object]:
    if (
        not isinstance(item, SequenceABC)
        or isinstance(item, (str, bytes, bytearray))
        or len(item) != _FERNET_KEYRING_PAIR_SIZE
    ):
        msg = "FernetKeyringConfig keys must contain key-id/key pairs."
        raise ConfigurationError(msg)
    return item[0], item[1]


def _validate_fernet_keyring_config_key_id(key_id: object) -> str:
    if not isinstance(key_id, str):
        msg = "Fernet key ids must be strings."
        raise ConfigurationError(msg)
    try:
        return validate_fernet_key_id(key_id)
    except SecretAtRestError as exc:
        raise ConfigurationError(str(exc)) from exc


def validate_user_manager_security_secret_roles_are_distinct(
    security: UserManagerSecurity[Any],
    *,
    totp_pending_secret: str | None = None,
    oauth_flow_cookie_secret: str | None = None,
) -> None:
    """Validate that manager-owned secret roles do not reuse unrelated key material."""
    for totp_secret_value in _iter_totp_secret_role_values(security) or (None,):
        _config.validate_secret_roles_are_distinct(
            _config.SecretRoleValues(
                verification_token_secret=security.verification_token_secret,
                reset_password_token_secret=security.reset_password_token_secret,
                login_identifier_telemetry_secret=security.login_identifier_telemetry_secret,
                totp_secret_key=totp_secret_value,
                totp_pending_secret=totp_pending_secret,
                oauth_flow_cookie_secret=oauth_flow_cookie_secret,
            ),
        )


def _iter_totp_secret_role_values(security: UserManagerSecurity[Any]) -> tuple[str, ...]:
    """Return configured raw TOTP at-rest key material for distinct-role validation."""
    values: list[str] = []
    if security.totp_secret_key:
        values.append(security.totp_secret_key)
    if security.totp_secret_keyring is not None:
        values.extend(_coerce_fernet_key_secret_role_value(key) for key in security.totp_secret_keyring.keys.values())
    return tuple(values)


def _coerce_fernet_key_secret_role_value(key: FernetKey) -> str:
    """Return Fernet key material as text for existing distinct-secret validation."""
    return key.decode("utf-8") if isinstance(key, bytes) else key


def _mask_optional_secret(secret: str | None) -> str | None:
    """Return the standard masked placeholder when a secret is configured."""
    return _MASKED if secret is not None else None
