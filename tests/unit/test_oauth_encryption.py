"""Unit tests for explicit OAuth token encryption helpers."""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase

import litestar_auth._oauth_mapper_events as oauth_mapper_events
import litestar_auth._optional_deps as optional_deps_module
from litestar_auth import oauth_encryption
from litestar_auth.models import OAuthAccountMixin, UserAuthRelationshipMixin, UserModelMixin
from litestar_auth.oauth_encryption import (
    OAuthTokenEncryption,
    _RawFernetBackend,
    bind_oauth_token_encryption,
    get_bound_oauth_token_encryption,
    require_oauth_token_encryption,
)
from tests.unit.test_definition_file_coverage import load_reloaded_test_alias

pytestmark = pytest.mark.unit


def _fernet_key_string(seed: bytes = b"0") -> str:
    """Return a deterministic valid Fernet key string."""
    pytest.importorskip("cryptography.fernet")
    return base64.urlsafe_b64encode(seed * 32).decode()


@dataclass
class _SessionInfoTarget:
    """Minimal session-like object exposing SQLAlchemy's ``info`` mapping."""

    info: dict[str, object] = field(default_factory=dict)
    _session: object | None = None


@dataclass
class _WrappedSession:
    """Wrapper that exposes an inner session via one of the supported attributes."""

    _session: object


@dataclass
class _TokenTarget:
    """Minimal OAuth-token carrier used to exercise mapper-event helpers."""

    access_token: str | None = None
    refresh_token: str | None = None
    _litestar_auth_oauth_token_encryption: object | None = None


@dataclass(frozen=True)
class _StructurallyCompatiblePolicy:
    """Policy-shaped object that is intentionally not a supported runtime policy."""

    key: str | bytes | None = None
    unsafe_testing: bool = True

    def require_configured(self, *, context: str = "OAuth token persistence") -> None:
        """Pretend to satisfy the policy surface without being accepted."""
        del context

    def encrypt(self, value: str | None) -> str | None:
        """Return a deterministic encrypted-looking value."""
        return None if value is None else f"encrypted:{value}"

    def decrypt(self, value: str | None) -> str | None:
        """Return a deterministic decrypted-looking value."""
        return None if value is None else value.removeprefix("encrypted:")


@dataclass(frozen=True)
class _History:
    """Small SQLAlchemy-history stub."""

    changed: bool

    def has_changes(self) -> bool:
        """Return whether the attribute has pending changes."""
        return self.changed


@dataclass(frozen=True)
class _AttributeState:
    """Small SQLAlchemy attribute-state stub."""

    changed: bool

    @property
    def history(self) -> _History:
        """Return the tracked change history."""
        return _History(self.changed)


class _InspectState:
    """Minimal inspection state compatible with the event helpers."""

    def __init__(self, *, access_changed: bool, refresh_changed: bool) -> None:
        """Store change-history stubs for OAuth token fields."""
        self.attrs = {
            "access_token": _AttributeState(access_changed),
            "refresh_token": _AttributeState(refresh_changed),
        }


def test_oauth_token_encryption_plaintext_policy_round_trips() -> None:
    """An explicit keyless policy preserves plaintext values in testing scenarios."""
    policy = OAuthTokenEncryption(key=None, unsafe_testing=True)

    assert policy.encrypt("plain-token") == "plain-token"
    assert policy.decrypt("plain-token") == "plain-token"
    assert policy.encrypt(None) is None
    assert policy.decrypt(None) is None


@pytest.mark.parametrize(
    ("method_name", "argument"),
    [
        ("encrypt", "plain-token"),
        ("decrypt", "plain-token"),
        ("requires_reencrypt", "plain-token"),
        ("reencrypt", "plain-token"),
        ("encrypt", None),
        ("decrypt", None),
        ("requires_reencrypt", None),
        ("reencrypt", None),
    ],
)
def test_oauth_token_encryption_keyless_policy_public_methods_fail_closed(
    method_name: str,
    argument: str | None,
) -> None:
    """Keyless OAuth token policies are unusable unless explicitly marked unsafe for tests."""
    policy = OAuthTokenEncryption(key=None)
    method = getattr(policy, method_name)

    with pytest.raises(oauth_encryption.ConfigurationError, match="oauth_token_encryption_key is required"):
        method(argument)


def test_oauth_token_encryption_with_fernet_key_round_trips() -> None:
    """A configured policy encrypts at rest and decrypts back to the original token."""
    policy = OAuthTokenEncryption(key=_fernet_key_string(), active_key_id="oauth")

    encrypted = policy.encrypt("secret-token")

    assert encrypted is not None
    assert encrypted.startswith("fernet:v1:oauth:")
    assert encrypted != "secret-token"
    assert policy.decrypt(encrypted) == "secret-token"


def test_oauth_token_encryption_decrypts_non_active_key_and_reencrypts() -> None:
    """Configured non-active key ids remain readable and can be rewritten with the active key."""
    keys = {
        "current": _fernet_key_string(b"1"),
        "old": _fernet_key_string(b"2"),
    }
    old_policy = OAuthTokenEncryption(active_key_id="old", keys=keys)
    current_policy = OAuthTokenEncryption(active_key_id="current", keys=keys)

    old_stored = old_policy.encrypt("legacy-token")
    current_stored = current_policy.encrypt("current-token")

    assert old_stored is not None
    assert current_stored is not None
    assert old_stored.startswith("fernet:v1:old:")
    assert current_stored.startswith("fernet:v1:current:")
    assert current_policy.decrypt(old_stored) == "legacy-token"
    assert current_policy.requires_reencrypt(old_stored) is True
    assert current_policy.requires_reencrypt(current_stored) is False

    rewritten = current_policy.reencrypt(old_stored)

    assert rewritten is not None
    assert rewritten.startswith("fernet:v1:current:")
    assert current_policy.decrypt(rewritten) == "legacy-token"
    assert current_policy.requires_reencrypt(rewritten) is False


def test_oauth_token_encryption_rotation_helpers_preserve_none_and_plaintext_mode() -> None:
    """Rotation helpers are no-ops for disabled values and explicit plaintext testing mode."""
    policy = OAuthTokenEncryption(key=None, unsafe_testing=True)

    assert policy.requires_reencrypt(None) is False
    assert policy.reencrypt(None) is None
    assert policy.requires_reencrypt("plain-token") is False
    assert policy.reencrypt("plain-token") == "plain-token"


def test_oauth_token_encryption_rejects_ambiguous_key_configuration() -> None:
    """A policy must not accept both the one-key and keyring configuration paths."""
    with pytest.raises(oauth_encryption.ConfigurationError, match="either key or keys"):
        OAuthTokenEncryption(
            key=_fernet_key_string(b"1"),
            keys={"current": _fernet_key_string(b"2")},
        )


def test_oauth_token_encryption_reuses_single_raw_backend_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``OAuthTokenEncryption`` mounts Fernet once; repeated encrypt/decrypt does not recreate it."""
    init_calls: list[None] = []

    class TrackingRawFernetBackend(_RawFernetBackend):
        """Counts ``__init__`` calls for the policy cache assertion."""

        def __init__(self) -> None:
            init_calls.append(None)
            super().__init__()

    monkeypatch.setattr(oauth_encryption, "_RawFernetBackend", TrackingRawFernetBackend)
    policy = OAuthTokenEncryption(key=_fernet_key_string())
    first = policy.encrypt("a")
    second = policy.encrypt("b")
    assert policy.decrypt(first) == "a"
    assert policy.decrypt(second) == "b"
    assert len(init_calls) == 1


def test_oauth_token_encryption_keyless_mounts_backend_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plaintext mode still constructs one backend with ``mount_vault(None)``."""
    init_calls: list[None] = []

    class TrackingRawFernetBackend(_RawFernetBackend):
        """Counts ``__init__`` calls for the policy cache assertion."""

        def __init__(self) -> None:
            init_calls.append(None)
            super().__init__()

    monkeypatch.setattr(oauth_encryption, "_RawFernetBackend", TrackingRawFernetBackend)
    policy = OAuthTokenEncryption(key=None, unsafe_testing=True)
    assert policy.encrypt("x") == "x"
    assert policy.decrypt("y") == "y"
    assert len(init_calls) == 1


def test_oauth_token_encryption_repr_and_hash_exclude_backend() -> None:
    """The cached Fernet backend must not affect repr, equality, or hashing."""
    policy = OAuthTokenEncryption(key=None)
    assert "_backend" not in repr(policy)
    other = OAuthTokenEncryption(key=None)
    assert policy == other
    assert hash(policy) == hash(other)


def test_oauth_token_encryption_repr_hides_configured_key() -> None:
    """Configured encryption keys stay out of repr/str surfaces."""
    key = _fernet_key_string()
    old_key = _fernet_key_string(b"1")
    policy = OAuthTokenEncryption(active_key_id="current", keys={"current": key, "old": old_key})

    rendered = repr(policy)

    assert key not in rendered
    assert old_key not in rendered
    assert "active_key_id='current'" in rendered
    assert "unsafe_testing=False" in rendered


def test_oauth_token_encryption_is_frozen() -> None:
    """Frozen dataclass instances reject attribute assignment after construction."""
    policy = OAuthTokenEncryption(key=None)
    field_name = "key"
    with pytest.raises(FrozenInstanceError):
        setattr(policy, field_name, "tamper")


def test_bind_oauth_token_encryption_tracks_wrapped_session_targets() -> None:
    """Binding through a wrapper stores the policy on the real session target."""
    target = _SessionInfoTarget()
    wrapped_session = _WrappedSession(target)
    policy = OAuthTokenEncryption(key=_fernet_key_string())

    bind_oauth_token_encryption(wrapped_session, policy)

    bound_policy = get_bound_oauth_token_encryption(wrapped_session)

    assert bound_policy is not None
    assert bound_policy.key == policy.key
    assert target.info["litestar_auth_oauth_token_encryption"] == policy


def test_bind_oauth_token_encryption_rejects_structurally_compatible_policy() -> None:
    """Binding accepts only the current module's concrete policy instances."""
    with pytest.raises(TypeError, match="OAuthTokenEncryption instance from the current module"):
        bind_oauth_token_encryption(
            _SessionInfoTarget(),
            cast("OAuthTokenEncryption", _StructurallyCompatiblePolicy()),
        )


def test_get_bound_oauth_token_encryption_ignores_reload_stale_policy_instances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Session bindings ignore policy instances created by a different module identity."""
    assert oauth_encryption.__file__ is not None
    target = _SessionInfoTarget()
    stale_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_oauth_encryption_stale_policy",
        source_path=Path(oauth_encryption.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    target.info["litestar_auth_oauth_token_encryption"] = stale_module.OAuthTokenEncryption(key=_fernet_key_string())

    assert get_bound_oauth_token_encryption(target) is None


def test_get_bound_oauth_token_encryption_returns_none_without_current_policy() -> None:
    """Unbound or structurally compatible session info is ignored."""
    target = _SessionInfoTarget(
        info={"litestar_auth_oauth_token_encryption": _StructurallyCompatiblePolicy()},
    )

    assert get_bound_oauth_token_encryption(target) is None


def test_require_oauth_token_encryption_rejects_missing_explicit_policy() -> None:
    """Direct OAuth persistence must now receive an explicit policy object."""
    with pytest.raises(oauth_encryption.ConfigurationError, match="explicit oauth_token_encryption policy"):
        require_oauth_token_encryption(None, context="persisting OAuth access and refresh tokens")


def test_require_oauth_token_encryption_rejects_structurally_compatible_policy() -> None:
    """Direct OAuth persistence rejects policy-shaped objects instead of duck-typing them."""
    with pytest.raises(oauth_encryption.ConfigurationError, match="OAuthTokenEncryption instance from the current"):
        require_oauth_token_encryption(
            cast("OAuthTokenEncryption", _StructurallyCompatiblePolicy()),
            context="persisting OAuth access and refresh tokens",
        )


def test_require_oauth_token_encryption_requires_key_outside_unsafe_testing() -> None:
    """A keyless explicit policy still fails closed outside explicit unsafe testing."""
    with pytest.raises(oauth_encryption.ConfigurationError, match="oauth_token_encryption_key is required"):
        require_oauth_token_encryption(
            OAuthTokenEncryption(key=None),
            context="persisting OAuth access and refresh tokens",
        )


def test_require_oauth_token_encryption_allows_keyless_policy_in_unsafe_testing() -> None:
    """Tests can opt into plaintext mode with an explicit keyless policy."""
    policy = OAuthTokenEncryption(key=None, unsafe_testing=True)

    assert require_oauth_token_encryption(policy, context="persisting OAuth access and refresh tokens") is policy


def test_require_oauth_token_encryption_allows_keyring_policy() -> None:
    """A configured keyring policy satisfies production persistence requirements."""
    policy = OAuthTokenEncryption(
        active_key_id="current",
        keys={"current": _fernet_key_string(b"1"), "old": _fernet_key_string(b"2")},
    )

    assert require_oauth_token_encryption(policy, context="persisting OAuth access and refresh tokens") is policy


def test_mount_vault_none_sets_fernet_none() -> None:
    """``mount_vault(None)`` disables encryption without error."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend._keyring is None
    assert backend.needs_rotation(None) is False


def test_init_engine_is_a_no_op() -> None:
    """``init_engine()`` intentionally does nothing."""
    backend = _RawFernetBackend()

    assert backend.init_engine("ignored") is None


def test_mount_vault_fernet_missing_raises_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing ``cryptography`` raises ``ImportError`` with the install hint."""
    backend = _RawFernetBackend()

    def import_module(_name: str) -> object:
        msg = "missing cryptography"
        raise ImportError(msg)

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", import_module)

    with pytest.raises(ImportError, match=r"litestar-auth\[oauth,totp\]"):
        backend.mount_vault(base64.urlsafe_b64encode(b"0" * 32).decode())


def test_raw_fernet_backend_round_trips_encrypted_values() -> None:
    """The raw backend continues to encrypt and decrypt token strings."""
    backend = _RawFernetBackend()
    backend.mount_vault(_fernet_key_string())
    token = backend.encrypt("secret")

    assert token != "secret"
    assert token.startswith("fernet:v1:default:")
    assert backend.decrypt(token) == "secret"
    assert backend.needs_rotation(token) is False


def test_raw_fernet_backend_encrypt_plaintext_mode_handles_bytes_and_rejects_other_types() -> None:
    """Plaintext mode accepts strings or bytes and rejects unsupported values."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert not backend.encrypt(None)
    assert backend.encrypt(b"plain-token") == "plain-token"

    with pytest.raises(TypeError, match="strings when encryption is disabled"):
        backend.encrypt(42)


def test_raw_fernet_backend_encrypt_rejects_non_strings_when_encrypted() -> None:
    """Encrypted mode only accepts string inputs."""
    backend = _RawFernetBackend()
    backend.mount_vault(_fernet_key_string())

    with pytest.raises(TypeError, match="OAuth token values must be strings"):
        backend.encrypt(42)


def test_raw_fernet_backend_decrypt_plaintext_mode_handles_none_bytes_and_invalid_values() -> None:
    """Plaintext decrypt supports ``None`` and bytes but rejects other value types."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert not backend.decrypt(None)
    assert backend.decrypt(b"plain-token") == "plain-token"

    with pytest.raises(TypeError, match="strings when encryption is disabled"):
        backend.decrypt(42)


def test_raw_fernet_backend_decrypt_accepts_bytes_and_rejects_invalid_values_when_encrypted() -> None:
    """Encrypted decrypt accepts byte payloads and rejects unsupported types."""

    class _FakeKeyring:
        def decrypt(self, token: str) -> str:
            """Return a deterministic plaintext token."""
            assert token == "ciphertext"
            return "plain-token"

    backend = _RawFernetBackend()
    backend._keyring = cast("Any", _FakeKeyring())

    assert backend.decrypt(b"ciphertext") == "plain-token"

    with pytest.raises(TypeError, match="strings or bytes"):
        backend.decrypt(42)


def test_register_oauth_model_encryption_events_skips_existing_listeners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listener registration is idempotent when SQLAlchemy already knows the handlers."""
    monkeypatch.setattr(oauth_encryption.event, "contains", lambda *_args, **_kwargs: True)
    listens: list[tuple[object, str]] = []
    monkeypatch.setattr(
        oauth_encryption.event,
        "listen",
        lambda model_base, identifier, *_args, **_kwargs: listens.append((model_base, identifier)),
    )

    oauth_encryption.register_oauth_model_encryption_events(object)

    assert listens == []


def test_register_oauth_model_encryption_events_adds_session_rollback_listeners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mapper registration also hooks session rollback cleanup for in-flight snapshots."""
    listens: list[tuple[object, str]] = []
    monkeypatch.setattr(oauth_encryption.event, "contains", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        oauth_encryption.event,
        "listen",
        lambda target, identifier, *_args, **_kwargs: listens.append((target, identifier)),
    )

    oauth_encryption.register_oauth_model_encryption_events(object)

    assert (oauth_encryption.Session, "after_rollback") in listens
    assert (oauth_encryption.Session, "after_soft_rollback") in listens


def test_oauth_account_mixin_registers_encryption_events_for_direct_subclasses() -> None:
    """Declaring a direct OAuth mixin subclass attaches the mapper hooks lazily."""

    class _AuthBase(DeclarativeBase):
        """Isolated declarative registry for the event-registration regression test."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class _AuthUUIDBase(UUIDPrimaryKey, _AuthBase):
        """UUID primary-key base bound to the isolated registry."""

        __abstract__ = True

    class _OAuthUser(UserModelMixin, UserAuthRelationshipMixin, _AuthUUIDBase):
        """Custom user model linked to the regression-test OAuth mapper."""

        __tablename__ = "oauth_event_user"

        auth_access_token_model = None
        auth_refresh_token_model = None
        auth_oauth_account_model = "_OAuthAccount"

    class _OAuthAccount(OAuthAccountMixin, _AuthUUIDBase):
        """Direct OAuth mixin subclass used to verify lazy hook registration."""

        __tablename__ = "oauth_event_account"

        auth_user_model = "_OAuthUser"
        auth_user_table = "oauth_event_user"

    assert event.contains(_OAuthAccount, "load", oauth_mapper_events._decrypt_loaded_oauth_tokens)
    assert event.contains(_OAuthAccount, "before_insert", oauth_mapper_events._encrypt_oauth_tokens_before_insert)
    assert event.contains(_OAuthAccount, "after_update", oauth_mapper_events._restore_oauth_tokens_after_write)
    assert _OAuthUser.auth_oauth_account_model == "_OAuthAccount"


def test_oauth_account_mixin_descendants_reuse_ancestor_encryption_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Descendants reuse the nearest registered OAuth mixin ancestor instead of duplicating hooks."""
    registrations: list[str] = []
    monkeypatch.setattr(
        "litestar_auth.models.mixins.register_oauth_model_encryption_events",
        lambda model_base: registrations.append(model_base.__name__),
    )

    class _AuthBase(DeclarativeBase):
        """Isolated declarative registry for the inherited-hook regression test."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class _AuthUUIDBase(UUIDPrimaryKey, _AuthBase):
        """UUID primary-key base bound to the inherited-hook test registry."""

        __abstract__ = True

    class _BaseOAuthAccount(OAuthAccountMixin, _AuthUUIDBase):
        """Abstract OAuth base that owns the propagated encryption hooks."""

        __abstract__ = True

    class _ConcreteOAuthAccount(_BaseOAuthAccount):
        """Concrete OAuth mapper that inherits the ancestor's encryption hooks."""

        __tablename__ = "oauth_inherited_account"

    assert _ConcreteOAuthAccount.__tablename__ == "oauth_inherited_account"
    assert registrations == ["_BaseOAuthAccount"]


def test_iter_session_targets_avoids_cycles() -> None:
    """Wrapped-session traversal should not loop forever when wrappers reference each other."""
    first = _SessionInfoTarget()
    second = _WrappedSession(first)
    first.info["wrapper"] = second
    first._session = second
    second._session = first

    targets = oauth_encryption._iter_session_targets(second)

    assert targets == (second, first)


def test_resolve_instance_oauth_token_encryption_uses_cached_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cached current-module policies on ORM instances are reused directly."""
    target = _TokenTarget()
    key_str = _fernet_key_string()
    policy = OAuthTokenEncryption(key=key_str)
    target._litestar_auth_oauth_token_encryption = policy
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: _SessionInfoTarget())

    resolved = oauth_mapper_events._resolve_instance_oauth_token_encryption(target)

    assert resolved is policy


def test_resolve_instance_oauth_token_encryption_ignores_reload_stale_cached_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cached policies from another module identity are ignored instead of normalized."""
    assert oauth_encryption.__file__ is not None
    target = _TokenTarget()
    stale_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_oauth_encryption_stale_cached_policy",
        source_path=Path(oauth_encryption.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    target._litestar_auth_oauth_token_encryption = stale_module.OAuthTokenEncryption(key=_fernet_key_string())
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: None)

    assert oauth_mapper_events._resolve_instance_oauth_token_encryption(target) is None


def test_resolve_instance_oauth_token_encryption_ignores_structurally_compatible_cached_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cached policy-shaped objects are ignored instead of normalized."""
    target = _TokenTarget(_litestar_auth_oauth_token_encryption=_StructurallyCompatiblePolicy())
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: None)

    assert oauth_mapper_events._resolve_instance_oauth_token_encryption(target) is None


def test_decrypt_loaded_oauth_tokens_returns_early_without_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load-time decryption is skipped when no explicit policy was bound."""
    calls: list[str] = []
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: None)
    monkeypatch.setattr(
        oauth_mapper_events.attributes,
        "set_committed_value",
        lambda *_args, **_kwargs: calls.append("set"),
    )

    oauth_mapper_events._decrypt_loaded_oauth_tokens(_TokenTarget(access_token="encrypted"), object())

    assert calls == []


def test_decrypt_loaded_oauth_tokens_skips_changed_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load-time decryption leaves locally changed fields untouched."""
    target = _TokenTarget(access_token="changed-access", refresh_token="stored-refresh")
    session = _SessionInfoTarget()
    bind_oauth_token_encryption(session, OAuthTokenEncryption(key=None, unsafe_testing=True))
    committed_values: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        oauth_mapper_events,
        "sa_inspect",
        lambda _target: _InspectState(access_changed=True, refresh_changed=False),
    )
    monkeypatch.setattr(
        oauth_mapper_events.attributes,
        "set_committed_value",
        lambda _target, field_name, value: committed_values.append((field_name, value)),
    )

    oauth_mapper_events._decrypt_loaded_oauth_tokens(target, type("Ctx", (), {"session": session})())

    assert committed_values == [("refresh_token", "stored-refresh")]


def test_encrypt_oauth_tokens_before_update_skips_when_no_fields_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Update-time encryption is a no-op when neither token field changed."""
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    monkeypatch.setattr(
        oauth_mapper_events,
        "sa_inspect",
        lambda _target: _InspectState(access_changed=False, refresh_changed=False),
    )

    oauth_mapper_events._encrypt_oauth_tokens_before_update(object(), object(), target)

    assert not hasattr(target, "_litestar_auth_oauth_token_snapshot")


def test_track_oauth_token_snapshot_target_tolerates_unmapped_and_unbound_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tracking helper is a no-op for unmapped instances or targets without a session."""
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    monkeypatch.setattr(
        oauth_mapper_events,
        "object_session",
        lambda _target: (_ for _ in ()).throw(oauth_mapper_events.UnmappedInstanceError(_target)),
    )

    oauth_mapper_events._track_oauth_token_snapshot_target(target)
    oauth_mapper_events._untrack_oauth_token_snapshot_target(target)

    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: None)

    oauth_mapper_events._track_oauth_token_snapshot_target(target)
    oauth_mapper_events._untrack_oauth_token_snapshot_target(target)


def test_track_oauth_token_snapshot_target_skips_duplicate_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tracking helper records a target only once per session."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = [target]
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)

    oauth_mapper_events._track_oauth_token_snapshot_target(target)

    assert session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] == [target]


def test_untrack_oauth_token_snapshot_target_preserves_other_tracked_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Untracking one target keeps other in-flight targets registered on the session."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    other = _TokenTarget(access_token="other-access", refresh_token="other-refresh")
    session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = [target, other]
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)

    oauth_mapper_events._untrack_oauth_token_snapshot_target(target)

    assert session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] == [other]


def test_restore_oauth_token_snapshot_without_snapshot_only_clears_tracking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Targets without a snapshot still clear the session-local tracking marker."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = [target]
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)

    oauth_mapper_events._restore_oauth_token_snapshot(target)

    assert oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY not in session.info


def test_encrypt_oauth_tokens_before_insert_restores_plaintext_when_encryption_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encryption failures restore plaintext values and clear temporary session tracking."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")

    class _ExplodingPolicy:
        def encrypt(self, value: str | None) -> str | None:
            if value == "stored-refresh":
                msg = "cannot encrypt refresh token"
                raise RuntimeError(msg)
            return None if value is None else f"encrypted:{value}"

    def _set_committed_value(current_target: _TokenTarget, field_name: str, value: str | None) -> None:
        setattr(current_target, field_name, value)

    monkeypatch.setattr(
        oauth_mapper_events,
        "_require_instance_oauth_token_encryption",
        lambda _target: _ExplodingPolicy(),
    )
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)
    monkeypatch.setattr(oauth_mapper_events.attributes, "set_committed_value", _set_committed_value)

    with pytest.raises(RuntimeError, match="cannot encrypt refresh token"):
        oauth_mapper_events._encrypt_oauth_tokens_before_insert(object(), object(), target)

    assert target.access_token == "stored-access"
    assert target.refresh_token == "stored-refresh"
    assert not hasattr(target, oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY)
    assert oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY not in session.info


def test_restore_oauth_token_snapshots_after_rollback_ignores_non_session_objects() -> None:
    """Rollback cleanup returns early when the event target does not expose session info."""
    oauth_mapper_events._restore_oauth_token_snapshots_after_rollback(object())


def test_restore_oauth_token_snapshots_after_rollback_restores_plaintext_and_clears_tracking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback cleanup restores plaintext token values for any tracked write target."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")

    class _Policy:
        def encrypt(self, value: str | None) -> str | None:
            return None if value is None else f"encrypted:{value}"

    def _set_committed_value(current_target: _TokenTarget, field_name: str, value: str | None) -> None:
        setattr(current_target, field_name, value)

    monkeypatch.setattr(oauth_mapper_events, "_require_instance_oauth_token_encryption", lambda _target: _Policy())
    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)
    monkeypatch.setattr(oauth_mapper_events.attributes, "set_committed_value", _set_committed_value)

    oauth_mapper_events._encrypt_oauth_tokens_before_insert(object(), object(), target)

    assert target.access_token == "encrypted:stored-access"
    assert target.refresh_token == "encrypted:stored-refresh"
    assert session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] == [target]

    oauth_mapper_events._restore_oauth_token_snapshots_after_rollback(cast("object", session))

    assert target.access_token == "stored-access"
    assert target.refresh_token == "stored-refresh"
    assert not hasattr(target, oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY)
    assert oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY not in session.info


def test_restore_oauth_token_snapshots_after_rollback_skips_duplicate_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback cleanup restores each tracked target at most once."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    setattr(
        target,
        oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY,
        {
            "access_token": "stored-access",
            "refresh_token": "stored-refresh",
        },
    )
    session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = [target, target]
    committed_values: list[tuple[str, str | None]] = []

    def _set_committed_value(current_target: _TokenTarget, field_name: str, value: str | None) -> None:
        committed_values.append((field_name, value))
        setattr(current_target, field_name, value)

    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)
    monkeypatch.setattr(oauth_mapper_events.attributes, "set_committed_value", _set_committed_value)

    oauth_mapper_events._restore_oauth_token_snapshots_after_rollback(cast("object", session))

    assert committed_values == [
        ("access_token", "stored-access"),
        ("refresh_token", "stored-refresh"),
    ]


def test_restore_oauth_tokens_after_write_skips_when_no_snapshot() -> None:
    """Restore-time hooks do nothing when no write snapshot is present."""
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")

    oauth_mapper_events._restore_oauth_tokens_after_write(object(), object(), target)

    assert target.access_token == "stored-access"
    assert target.refresh_token == "stored-refresh"


def test_restore_oauth_tokens_after_write_clears_session_tracking(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful writes restore plaintext values and drop the tracked-target marker."""
    session = _SessionInfoTarget()
    target = _TokenTarget(access_token="encrypted:stored-access", refresh_token="stored-refresh")
    setattr(
        target,
        oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_SNAPSHOT_KEY,
        {"access_token": "stored-access"},
    )
    session.info[oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY] = [target]

    def _set_committed_value(current_target: _TokenTarget, field_name: str, value: str | None) -> None:
        setattr(current_target, field_name, value)

    monkeypatch.setattr(oauth_mapper_events, "object_session", lambda _target: session)
    monkeypatch.setattr(oauth_mapper_events.attributes, "set_committed_value", _set_committed_value)

    oauth_mapper_events._restore_oauth_tokens_after_write(object(), object(), target)

    assert target.access_token == "stored-access"
    assert oauth_mapper_events._OAUTH_TOKEN_ENCRYPTION_TRACKED_TARGETS_KEY not in session.info
