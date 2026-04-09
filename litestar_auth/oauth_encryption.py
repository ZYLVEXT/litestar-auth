"""Explicit OAuth token encryption helpers for SQLAlchemy-backed persistence.

OAuth token storage is bound to a concrete session via
``bind_oauth_token_encryption(...)`` or by passing ``oauth_token_encryption=...``
to ``SQLAlchemyUserDatabase``. Mapped ``OAuthAccount`` instances keep plaintext
tokens in memory while mapper events encrypt them before writes and decrypt them
after loads/refreshes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast, override

from sqlalchemy import event
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import attributes, object_session

from litestar_auth.exceptions import ConfigurationError

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None  # ty: ignore[invalid-assignment]

from advanced_alchemy.types.encrypted_string import EncryptionBackend

_OAUTH_TOKEN_ENCRYPTION_INFO_KEY = "litestar_auth_oauth_token_encryption"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY = "_litestar_auth_oauth_token_encryption"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY = "_litestar_auth_oauth_token_snapshot"  # noqa: S105
_OAUTH_TOKEN_FIELDS: tuple[str, str] = ("access_token", "refresh_token")


@dataclass(frozen=True, slots=True)
class OAuthTokenEncryption:
    """Explicit OAuth token encryption policy for one session-bound persistence path."""

    key: str | bytes | None = None
    unsafe_testing: bool = False

    def require_configured(self, *, context: str = "OAuth token persistence") -> None:
        """Fail closed when encryption is required but no key is configured.

        Raises:
            ConfigurationError: When ``unsafe_testing=False`` and no encryption key is configured.
        """
        if self.unsafe_testing or self.key is not None:
            return
        msg = (
            f"oauth_token_encryption_key is required when {context}. "
            'Generate one with `python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"`.'
        )
        raise ConfigurationError(msg)

    def encrypt(self, value: str | None) -> str | None:
        """Return the value encrypted with this policy, or plaintext when disabled."""
        if value is None:
            return None
        backend = _RawFernetBackend()
        backend.mount_vault(self.key)
        return backend.encrypt(value)

    def decrypt(self, value: str | None) -> str | None:
        """Return the value decrypted with this policy, or plaintext when disabled."""
        if value is None:
            return None
        backend = _RawFernetBackend()
        backend.mount_vault(self.key)
        return backend.decrypt(value)


def bind_oauth_token_encryption(session: object, oauth_token_encryption: OAuthTokenEncryption) -> None:
    """Bind an explicit OAuth token encryption policy to a SQLAlchemy session path."""
    for target in _iter_session_targets(session):
        info = getattr(target, "info", None)
        if isinstance(info, dict):
            info[_OAUTH_TOKEN_ENCRYPTION_INFO_KEY] = oauth_token_encryption


def get_bound_oauth_token_encryption(session: object) -> OAuthTokenEncryption | None:
    """Return the OAuth token encryption policy bound to the given session path."""
    for target in _iter_session_targets(session):
        info = getattr(target, "info", None)
        if isinstance(info, dict):
            policy = _coerce_oauth_token_encryption(info.get(_OAUTH_TOKEN_ENCRYPTION_INFO_KEY))
            if policy is not None:
                return policy
    return None


def require_oauth_token_encryption(
    oauth_token_encryption: OAuthTokenEncryption | None,
    *,
    context: str = "OAuth token persistence",
) -> OAuthTokenEncryption:
    """Return the explicit policy or fail when persistence would rely on ambient state.

    Raises:
        ConfigurationError: When no explicit policy was supplied, or when a policy without a
            configured key is used while ``unsafe_testing=False``.
    """
    if oauth_token_encryption is None:
        msg = (
            f"{context} requires an explicit oauth_token_encryption policy. "
            "Pass oauth_token_encryption=OAuthTokenEncryption(...) to SQLAlchemyUserDatabase() "
            "or call bind_oauth_token_encryption(session, OAuthTokenEncryption(...))."
        )
        raise ConfigurationError(msg)
    oauth_token_encryption.require_configured(context=context)
    return oauth_token_encryption


class _RawFernetBackend(EncryptionBackend):
    """Encryption backend that uses the configured key directly as a Fernet key (no hashing).

    When key is ``None``, values are stored and returned as plain text (no encryption).
    """

    def __init__(self) -> None:
        self._fernet: Any = None

    def mount_vault(self, key: str | bytes | None) -> None:
        """Use the given key as the Fernet key, or ``None`` to disable encryption.

        Raises:
            ImportError: If cryptography is not installed and a non-``None`` key is passed.
        """
        if key is None:
            self._fernet = None
            return
        if Fernet is None:
            msg = "Install litestar-auth[oauth] to use OAuth token encryption."
            raise ImportError(msg)
        key_bytes = key.encode() if isinstance(key, str) else key
        self._fernet = Fernet(key_bytes)

    @override
    def init_engine(self, key: bytes | str) -> None:
        """No-op; ``mount_vault()`` does the work."""
        del key

    def encrypt(self, value: object) -> str:
        """Encrypt the value, or return it as plaintext if encryption is disabled.

        Returns:
            The encrypted token string, or the original plaintext when encryption is disabled.

        Raises:
            TypeError: If the value cannot be represented as a token string.
        """
        if self._fernet is None:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode("utf-8")
            msg = "OAuth token values must be strings when encryption is disabled."
            raise TypeError(msg)
        if not isinstance(value, str):
            msg = "OAuth token values must be strings."
            raise TypeError(msg)
        return self._fernet.encrypt(value.encode()).decode("utf-8")

    def decrypt(self, value: object) -> str:
        """Decrypt the value, or return it as plaintext if encryption is disabled.

        Returns:
            The decrypted token string, or the original plaintext when encryption is disabled.

        Raises:
            TypeError: If the value is not a string or bytes.
        """
        if self._fernet is None or value is None:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode("utf-8")
            msg = "OAuth token values must be strings when encryption is disabled."
            raise TypeError(msg)
        if isinstance(value, str):
            decrypted: str | bytes = self._fernet.decrypt(value.encode("utf-8"))
        elif isinstance(value, bytes):
            decrypted = self._fernet.decrypt(value)
        else:
            msg = "OAuth token values must be strings or bytes."
            raise TypeError(msg)
        return decrypted.decode("utf-8") if isinstance(decrypted, bytes) else decrypted


def register_oauth_model_encryption_events(model_base: type[Any]) -> None:
    """Register mapper events that keep OAuth token attributes plaintext in memory."""
    listeners: tuple[tuple[str, object], ...] = (
        ("load", _decrypt_loaded_oauth_tokens),
        ("refresh", _decrypt_refreshed_oauth_tokens),
        ("before_insert", _encrypt_oauth_tokens_before_insert),
        ("before_update", _encrypt_oauth_tokens_before_update),
        ("after_insert", _restore_oauth_tokens_after_write),
        ("after_update", _restore_oauth_tokens_after_write),
    )
    for identifier, listener in listeners:
        if not event.contains(model_base, identifier, listener):
            event.listen(model_base, identifier, listener, propagate=True)


def _iter_session_targets(session: object) -> tuple[object, ...]:
    """Return the concrete session objects that may carry encryption state."""
    targets: list[object] = []
    stack = [session]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        targets.append(current)
        for attribute_name in ("sync_session", "_proxied", "_session"):
            wrapped = getattr(current, attribute_name, None)
            if wrapped is not None:
                stack.append(wrapped)
    return tuple(targets)


def _set_instance_oauth_token_encryption(target: object, oauth_token_encryption: OAuthTokenEncryption) -> None:
    """Cache the session-bound policy on a loaded instance."""
    setattr(target, _OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY, oauth_token_encryption)


def _coerce_oauth_token_encryption(policy: object) -> OAuthTokenEncryption | None:
    """Normalize structurally compatible policy objects across module reloads.

    Returns:
        The current module's ``OAuthTokenEncryption`` instance when the input is
        compatible, otherwise ``None``.
    """
    if isinstance(policy, OAuthTokenEncryption):
        return policy

    key = getattr(policy, "key", None)
    unsafe_testing = getattr(policy, "unsafe_testing", False)
    encrypt = getattr(policy, "encrypt", None)
    decrypt = getattr(policy, "decrypt", None)
    require_configured = getattr(policy, "require_configured", None)
    if callable(encrypt) and callable(decrypt) and callable(require_configured):
        return OAuthTokenEncryption(
            key=cast("str | bytes | None", key),
            unsafe_testing=cast("bool", unsafe_testing),
        )
    return None


def _resolve_instance_oauth_token_encryption(
    target: object,
    *,
    session: object | None = None,
) -> OAuthTokenEncryption | None:
    """Return the policy for one ORM instance, preferring the active session binding."""
    if session is None:
        session = object_session(target)
    if session is not None:
        session_policy = get_bound_oauth_token_encryption(session)
        if session_policy is not None:
            _set_instance_oauth_token_encryption(target, session_policy)
            return session_policy
    cached_policy = _coerce_oauth_token_encryption(getattr(target, _OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY, None))
    if cached_policy is not None:
        return cached_policy
    return None


def _require_instance_oauth_token_encryption(target: object) -> OAuthTokenEncryption:
    """Return the explicit policy for a mapped OAuth instance before persistence."""
    policy = _resolve_instance_oauth_token_encryption(target)
    return require_oauth_token_encryption(policy, context="persisting OAuth access and refresh tokens")


def _decrypt_loaded_oauth_tokens(
    target: object,
    context: object,
    *,
    field_names: tuple[str, ...] = _OAUTH_TOKEN_FIELDS,
) -> None:
    """Decrypt persisted OAuth token fields after the ORM loads an instance."""
    session = getattr(context, "session", None)
    policy = _resolve_instance_oauth_token_encryption(target, session=session)
    if policy is None:
        return
    state = cast("Any", sa_inspect(target))
    for field_name in field_names:
        if state.attrs[field_name].history.has_changes():
            continue
        attributes.set_committed_value(target, field_name, policy.decrypt(getattr(target, field_name)))


def _decrypt_refreshed_oauth_tokens(target: object, context: object, attrs: object) -> None:
    """Decrypt persisted OAuth token fields after a refresh operation."""
    field_names = _OAUTH_TOKEN_FIELDS
    if isinstance(attrs, tuple | list | set | frozenset):
        field_names = tuple(field_name for field_name in _OAUTH_TOKEN_FIELDS if field_name in attrs)
    _decrypt_loaded_oauth_tokens(target, context, field_names=field_names)


def _encrypt_oauth_tokens_before_insert(mapper: object, connection: object, target: object) -> None:
    """Encrypt OAuth token fields immediately before INSERT statements."""
    del mapper, connection
    policy = _require_instance_oauth_token_encryption(target)
    snapshot: dict[str, str | None] = {}
    for field_name in _OAUTH_TOKEN_FIELDS:
        value = cast("str | None", getattr(target, field_name))
        snapshot[field_name] = value
        setattr(target, field_name, policy.encrypt(value))
    setattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY, snapshot)


def _encrypt_oauth_tokens_before_update(mapper: object, connection: object, target: object) -> None:
    """Encrypt changed OAuth token fields immediately before UPDATE statements."""
    del mapper, connection
    state = cast("Any", sa_inspect(target))
    changed_fields = tuple(
        field_name for field_name in _OAUTH_TOKEN_FIELDS if state.attrs[field_name].history.has_changes()
    )
    if not changed_fields:
        return
    policy = _require_instance_oauth_token_encryption(target)
    snapshot: dict[str, str | None] = {}
    for field_name in changed_fields:
        value = cast("str | None", getattr(target, field_name))
        snapshot[field_name] = value
        setattr(target, field_name, policy.encrypt(value))
    setattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY, snapshot)


def _restore_oauth_tokens_after_write(mapper: object, connection: object, target: object) -> None:
    """Restore plaintext OAuth token fields after a successful INSERT/UPDATE."""
    del mapper, connection
    snapshot = cast(
        "dict[str, str | None] | None",
        getattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY, None),
    )
    if snapshot is None:
        return
    for field_name, value in snapshot.items():
        attributes.set_committed_value(target, field_name, value)
    delattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY)
