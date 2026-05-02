"""SQLAlchemy mapper events for OAuth token encryption."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import attributes, object_session
from sqlalchemy.orm.exc import UnmappedInstanceError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_auth.oauth_encryption import OAuthTokenEncryption

_OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY = "_litestar_auth_oauth_token_encryption"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY = "_litestar_auth_oauth_token_snapshot"  # noqa: S105
_OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY = "_litestar_auth_oauth_snapshot_targets"  # noqa: S105
_OAUTH_TOKEN_FIELDS: tuple[str, str] = ("access_token", "refresh_token")


def _set_instance_oauth_token_encryption(target: object, oauth_token_encryption: OAuthTokenEncryption) -> None:
    """Cache the session-bound policy on a loaded instance."""
    setattr(target, _OAUTH_TOKEN_ENCRYPTION_INSTANCE_KEY, oauth_token_encryption)


def _resolve_instance_oauth_token_encryption(
    target: object,
    *,
    session: object | None = None,
) -> OAuthTokenEncryption | None:
    """Return the policy for one ORM instance, preferring the active session binding."""
    from litestar_auth.oauth_encryption import (  # noqa: PLC0415
        OAuthTokenEncryption,
        get_bound_oauth_token_encryption,
    )

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
    from litestar_auth.oauth_encryption import require_oauth_token_encryption  # noqa: PLC0415

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
    field_names: Sequence[str],
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
