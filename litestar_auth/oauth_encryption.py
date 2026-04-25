"""Explicit OAuth token encryption helpers for SQLAlchemy-backed persistence.

OAuth token storage is bound to a concrete session via
``bind_oauth_token_encryption(...)`` or by passing ``oauth_token_encryption=...``
to ``SQLAlchemyUserDatabase``. Mapped ``OAuthAccount`` instances keep plaintext
tokens in memory while mapper events encrypt them before writes and decrypt them
after loads/refreshes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast, override

from advanced_alchemy.types.encrypted_string import EncryptionBackend
from sqlalchemy import event
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session, attributes, object_session
from sqlalchemy.orm.exc import UnmappedInstanceError

from litestar_auth._secrets_at_rest import FernetKey, FernetKeyring
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

_OAUTH_TOKEN_ENCRYPTION_INFO_KEY = "litestar_auth_oauth_token_encryption"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY = "_litestar_auth_oauth_token_encryption"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY = "_litestar_auth_oauth_token_snapshot"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY = "_litestar_auth_oauth_snapshot_targets"  # noqa: S105
_OAUTH_TOKEN_FIELDS: tuple[str, str] = ("access_token", "refresh_token")
_DEFAULT_OAUTH_FERNET_KEY_ID = "default"


class _RawFernetBackend(EncryptionBackend):
    """Encryption backend that uses the configured Fernet keyring directly.

    When key is ``None``, values are stored and returned as plain text (no encryption).
    """

    def __init__(self) -> None:
        self._keyring: FernetKeyring | None = None

    def mount_vault(
        self,
        key: FernetKey | None,
        *,
        active_key_id: str = _DEFAULT_OAUTH_FERNET_KEY_ID,
        keys: Mapping[str, FernetKey] | None = None,
    ) -> None:
        """Use the given key or keyring, or ``None`` to disable encryption."""
        if keys is None:
            if key is None:
                self._keyring = None
                return
            resolved_keys: Mapping[str, FernetKey] = {active_key_id: key}
        else:
            resolved_keys = keys
        self._keyring = FernetKeyring(active_key_id=active_key_id, keys=resolved_keys)

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
        if self._keyring is None:
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
        return self._keyring.encrypt(value)

    def decrypt(self, value: object) -> str:
        """Decrypt the value, or return it as plaintext if encryption is disabled.

        Returns:
            The decrypted token string, or the original plaintext when encryption is disabled.

        Raises:
            TypeError: If the value is not a string or bytes.
        """
        if self._keyring is None or value is None:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            if isinstance(value, bytes):
                return value.decode("utf-8")
            msg = "OAuth token values must be strings when encryption is disabled."
            raise TypeError(msg)
        return self._keyring.decrypt(_coerce_oauth_token_storage_value(value))

    def needs_rotation(self, value: object) -> bool:
        """Return whether the stored value should be rewritten with the active key id."""
        if value is None or self._keyring is None:
            return False
        return self._keyring.needs_rotation(_coerce_oauth_token_storage_value(value))


@dataclass(frozen=True, slots=True)
class OAuthTokenEncryption:
    """Explicit OAuth token encryption policy for one session-bound persistence path."""

    # Security: never expose the encryption key in repr/str output.
    key: FernetKey | None = field(default=None, repr=False)
    unsafe_testing: bool = False
    active_key_id: str = _DEFAULT_OAUTH_FERNET_KEY_ID
    keys: Mapping[str, FernetKey] | None = field(default=None, repr=False, compare=False, hash=False)
    _backend: _RawFernetBackend = field(init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        """Initialize the cached Fernet backend for this policy's key.

        Raises:
            ConfigurationError: If both one-key and keyring inputs are configured.
        """
        if self.key is not None and self.keys is not None:
            msg = "OAuth token encryption accepts either key or keys, not both."
            raise ConfigurationError(msg)
        if self.keys is not None:
            object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))
        backend = _RawFernetBackend()
        backend.mount_vault(self.key, active_key_id=self.active_key_id, keys=self.keys)
        object.__setattr__(self, "_backend", backend)

    def require_configured(self, *, context: str = "OAuth token persistence") -> None:
        """Fail closed when encryption is required but no key is configured.

        Raises:
            ConfigurationError: When ``unsafe_testing=False`` and no encryption key is configured.
        """
        if self.unsafe_testing or self.key is not None or self.keys is not None:
            return
        msg = (
            f"oauth_token_encryption_key is required when {context}. "
            'Generate one with `python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"`.'
        )
        raise ConfigurationError(msg)

    def encrypt(self, value: str | None) -> str | None:
        """Return the value encrypted with this policy, or plaintext in explicit unsafe tests."""
        self.require_configured(context="encrypting OAuth tokens")
        if value is None:
            return None
        return self._backend.encrypt(value)

    def decrypt(self, value: str | None) -> str | None:
        """Return the value decrypted with this policy, or plaintext in explicit unsafe tests."""
        self.require_configured(context="decrypting OAuth tokens")
        if value is None:
            return None
        return self._backend.decrypt(value)

    def requires_reencrypt(self, value: str | None) -> bool:
        """Return whether a stored OAuth token should be rewritten with the active key."""
        self.require_configured(context="checking OAuth token rotation")
        if value is None:
            return False
        return self._backend.needs_rotation(value)

    def reencrypt(self, value: str | None) -> str | None:
        """Return a stored OAuth token rewritten with the active key."""
        self.require_configured(context="re-encrypting OAuth tokens")
        if value is None:
            return None
        plaintext = self.decrypt(value)
        return self.encrypt(plaintext)


def _coerce_oauth_token_storage_value(value: object) -> str:
    """Return ``value`` as a storage string for keyring operations.

    Raises:
        TypeError: If the value is not a string or bytes.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8")
    msg = "OAuth token values must be strings or bytes."
    raise TypeError(msg)


def bind_oauth_token_encryption(session: object, oauth_token_encryption: OAuthTokenEncryption) -> None:
    """Bind an explicit OAuth token encryption policy to a SQLAlchemy session path.

    Raises:
        TypeError: When ``oauth_token_encryption`` is not a current-module
            ``OAuthTokenEncryption`` instance.
    """
    if not isinstance(oauth_token_encryption, OAuthTokenEncryption):
        msg = "oauth_token_encryption must be an OAuthTokenEncryption instance from the current module."
        raise TypeError(msg)
    for target in _iter_session_targets(session):
        info = getattr(target, "info", None)
        if isinstance(info, dict):
            info[_OAUTH_TOKEN_ENCRYPTION_INFO_KEY] = oauth_token_encryption


def get_bound_oauth_token_encryption(session: object) -> OAuthTokenEncryption | None:
    """Return the OAuth token encryption policy bound to the given session path."""
    for target in _iter_session_targets(session):
        info = getattr(target, "info", None)
        if isinstance(info, dict):
            policy = info.get(_OAUTH_TOKEN_ENCRYPTION_INFO_KEY)
            if isinstance(policy, OAuthTokenEncryption):
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
    if not isinstance(oauth_token_encryption, OAuthTokenEncryption):
        msg = (
            f"{context} requires an OAuthTokenEncryption instance from the current module. "
            "Create a fresh OAuthTokenEncryption(...) policy before binding or passing it to "
            "SQLAlchemyUserDatabase()."
        )
        raise ConfigurationError(msg)
    oauth_token_encryption.require_configured(context=context)
    return oauth_token_encryption


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

    transaction_listeners: tuple[tuple[str, object], ...] = (
        ("after_rollback", _restore_oauth_token_snapshots_after_rollback),
        ("after_soft_rollback", _restore_oauth_token_snapshots_after_rollback),
    )
    for identifier, listener in transaction_listeners:
        if not event.contains(Session, identifier, listener):
            event.listen(Session, identifier, listener)


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
    cached_policy = getattr(target, _OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY, None)
    if isinstance(cached_policy, OAuthTokenEncryption):
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


def _track_oauth_token_snapshot_target(target: object) -> None:
    """Record a target with an in-flight plaintext snapshot on its current session."""
    try:
        session = object_session(target)
    except UnmappedInstanceError:
        return
    if session is None:
        return
    tracked_targets = cast(
        "list[object]",
        session.info.setdefault(_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY, []),
    )
    if any(existing is target for existing in tracked_targets):
        return
    tracked_targets.append(target)


def _untrack_oauth_token_snapshot_target(target: object) -> None:
    """Remove a target from the session-local snapshot tracker."""
    try:
        session = object_session(target)
    except UnmappedInstanceError:
        return
    if session is None:
        return
    tracked_targets = cast(
        "list[object] | None",
        session.info.get(_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY),
    )
    if not tracked_targets:
        return
    remaining_targets = [existing for existing in tracked_targets if existing is not target]
    if remaining_targets:
        session.info[_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = remaining_targets
        return
    session.info.pop(_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY, None)


def _restore_oauth_token_snapshot(target: object) -> None:
    """Restore plaintext OAuth token fields from the temporary write snapshot."""
    snapshot = cast(
        "dict[str, str | None] | None",
        getattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY, None),
    )
    if snapshot is None:
        _untrack_oauth_token_snapshot_target(target)
        return
    for field_name, value in snapshot.items():
        attributes.set_committed_value(target, field_name, value)
    delattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY)
    _untrack_oauth_token_snapshot_target(target)


def _snapshot_and_encrypt_oauth_tokens(
    target: object,
    *,
    field_names: tuple[str, ...],
    policy: OAuthTokenEncryption,
) -> None:
    """Encrypt selected token fields while preserving rollback-safe plaintext restoration."""
    snapshot = {field_name: cast("str | None", getattr(target, field_name)) for field_name in field_names}
    setattr(target, _OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY, snapshot)
    _track_oauth_token_snapshot_target(target)
    try:
        for field_name, value in snapshot.items():
            setattr(target, field_name, policy.encrypt(value))
    except Exception:
        _restore_oauth_token_snapshot(target)
        raise


def _restore_oauth_token_snapshots_after_rollback(session: object, *_args: object) -> None:
    """Restore and clear any OAuth token snapshots left behind by an aborted flush."""
    info = getattr(session, "info", None)
    if not isinstance(info, dict):
        return
    tracked_targets = cast(
        "list[object]",
        info.pop(_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY, []),
    )
    seen_target_ids: set[int] = set()
    for target in tracked_targets:
        target_id = id(target)
        if target_id in seen_target_ids:
            continue
        seen_target_ids.add(target_id)
        _restore_oauth_token_snapshot(target)


def _encrypt_oauth_tokens_before_insert(mapper: object, connection: object, target: object) -> None:
    """Encrypt OAuth token fields immediately before INSERT statements."""
    del mapper, connection
    policy = _require_instance_oauth_token_encryption(target)
    _snapshot_and_encrypt_oauth_tokens(target, field_names=_OAUTH_TOKEN_FIELDS, policy=policy)


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
    _snapshot_and_encrypt_oauth_tokens(target, field_names=changed_fields, policy=policy)


def _restore_oauth_tokens_after_write(mapper: object, connection: object, target: object) -> None:
    """Restore plaintext OAuth token fields after a successful INSERT/UPDATE."""
    del mapper, connection
    _restore_oauth_token_snapshot(target)
