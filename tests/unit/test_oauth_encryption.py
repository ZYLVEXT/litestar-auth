"""Unit tests for explicit OAuth token encryption helpers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field

import pytest

from litestar_auth import oauth_encryption
from litestar_auth.oauth_encryption import (
    Fernet as _FernetImport,
)
from litestar_auth.oauth_encryption import (
    OAuthTokenEncryption,
    _RawFernetBackend,
    bind_oauth_token_encryption,
    get_bound_oauth_token_encryption,
    require_oauth_token_encryption,
)

pytestmark = pytest.mark.unit


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


def test_oauth_encryption_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module-body execution."""
    reloaded_module = importlib.reload(oauth_encryption)

    assert reloaded_module.OAuthTokenEncryption.__name__ == OAuthTokenEncryption.__name__
    assert reloaded_module.require_oauth_token_encryption.__name__ == require_oauth_token_encryption.__name__


def test_oauth_token_encryption_plaintext_policy_round_trips() -> None:
    """An explicit keyless policy preserves plaintext values in testing scenarios."""
    policy = OAuthTokenEncryption(key=None)

    assert policy.encrypt("plain-token") == "plain-token"
    assert policy.decrypt("plain-token") == "plain-token"
    assert policy.encrypt(None) is None
    assert policy.decrypt(None) is None


def test_oauth_token_encryption_with_fernet_key_round_trips() -> None:
    """A configured policy encrypts at rest and decrypts back to the original token."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    policy = OAuthTokenEncryption(key=_FernetImport.generate_key())

    encrypted = policy.encrypt("secret-token")

    assert encrypted is not None
    assert encrypted != "secret-token"
    assert policy.decrypt(encrypted) == "secret-token"


def test_bind_oauth_token_encryption_tracks_wrapped_session_targets() -> None:
    """Binding through a wrapper stores the policy on the real session target."""
    target = _SessionInfoTarget()
    wrapped_session = _WrappedSession(target)
    policy = OAuthTokenEncryption(key="a" * 44)

    bind_oauth_token_encryption(wrapped_session, policy)

    bound_policy = get_bound_oauth_token_encryption(wrapped_session)

    assert bound_policy is not None
    assert bound_policy.key == policy.key
    assert target.info["litestar_auth_oauth_token_encryption"] == policy


def test_get_bound_oauth_token_encryption_normalizes_pre_reload_policy_instances() -> None:
    """Reloaded helpers still recognize a policy object that was bound before reload."""
    target = _SessionInfoTarget()
    stale_policy = OAuthTokenEncryption(key="a" * 44)

    bind_oauth_token_encryption(target, stale_policy)
    reloaded_module = importlib.reload(oauth_encryption)

    assert reloaded_module.get_bound_oauth_token_encryption(target) == reloaded_module.OAuthTokenEncryption(
        key="a" * 44,
    )


def test_get_bound_oauth_token_encryption_returns_none_without_compatible_policy() -> None:
    """Unbound or incompatible session info is ignored."""
    target = _SessionInfoTarget(info={"litestar_auth_oauth_token_encryption": object()})

    assert get_bound_oauth_token_encryption(target) is None


def test_require_oauth_token_encryption_rejects_missing_explicit_policy() -> None:
    """Direct OAuth persistence must now receive an explicit policy object."""
    with pytest.raises(oauth_encryption.ConfigurationError, match="explicit oauth_token_encryption policy"):
        require_oauth_token_encryption(None, context="persisting OAuth access and refresh tokens")


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


def test_mount_vault_none_sets_fernet_none() -> None:
    """``mount_vault(None)`` disables encryption without error."""
    backend = _RawFernetBackend()
    backend.mount_vault(None)

    assert backend._fernet is None


def test_init_engine_is_a_no_op() -> None:
    """``init_engine()`` intentionally does nothing."""
    backend = _RawFernetBackend()

    assert backend.init_engine("ignored") is None


def test_mount_vault_fernet_missing_raises_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing ``cryptography`` raises ``ImportError`` with the install hint."""
    backend = _RawFernetBackend()
    monkeypatch.setattr(oauth_encryption, "Fernet", None)

    with pytest.raises(ImportError, match=r"litestar-auth\[oauth\]"):
        backend.mount_vault("anykey")


def test_raw_fernet_backend_round_trips_encrypted_values() -> None:
    """The raw backend continues to encrypt and decrypt token strings."""
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())
    token = backend.encrypt("secret")

    assert token != "secret"
    assert backend.decrypt(token) == "secret"


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
    if _FernetImport is None:
        pytest.skip("cryptography is not installed in this environment")
    backend = _RawFernetBackend()
    backend.mount_vault(_FernetImport.generate_key())

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

    class _FakeFernet:
        def decrypt(self, token: bytes) -> bytes:
            """Return a deterministic plaintext token."""
            assert token == b"ciphertext"
            return b"plain-token"

    backend = _RawFernetBackend()
    backend._fernet = _FakeFernet()

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


def test_iter_session_targets_avoids_cycles() -> None:
    """Wrapped-session traversal should not loop forever when wrappers reference each other."""
    first = _SessionInfoTarget()
    second = _WrappedSession(first)
    first.info["wrapper"] = second
    first._session = second
    second._session = first

    targets = oauth_encryption._iter_session_targets(second)

    assert targets == (second, first)


def test_coerce_oauth_token_encryption_rejects_incompatible_objects() -> None:
    """Objects without the policy surface are ignored."""
    assert oauth_encryption._coerce_oauth_token_encryption(object()) is None


def test_resolve_instance_oauth_token_encryption_uses_cached_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cached policies on ORM instances survive reload-normalization logic."""
    target = _TokenTarget()
    target._litestar_auth_oauth_token_encryption = OAuthTokenEncryption(key="a" * 44)
    monkeypatch.setattr(oauth_encryption, "object_session", lambda _target: _SessionInfoTarget())

    resolved = oauth_encryption._resolve_instance_oauth_token_encryption(target)

    assert resolved == oauth_encryption.OAuthTokenEncryption(key="a" * 44)


def test_decrypt_loaded_oauth_tokens_returns_early_without_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load-time decryption is skipped when no explicit policy was bound."""
    calls: list[str] = []
    monkeypatch.setattr(oauth_encryption, "object_session", lambda _target: None)
    monkeypatch.setattr(
        oauth_encryption.attributes,
        "set_committed_value",
        lambda *_args, **_kwargs: calls.append("set"),
    )

    oauth_encryption._decrypt_loaded_oauth_tokens(_TokenTarget(access_token="encrypted"), object())

    assert calls == []


def test_decrypt_loaded_oauth_tokens_skips_changed_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load-time decryption leaves locally changed fields untouched."""
    target = _TokenTarget(access_token="changed-access", refresh_token="stored-refresh")
    session = _SessionInfoTarget()
    bind_oauth_token_encryption(session, OAuthTokenEncryption(key=None))
    committed_values: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        oauth_encryption,
        "sa_inspect",
        lambda _target: _InspectState(access_changed=True, refresh_changed=False),
    )
    monkeypatch.setattr(
        oauth_encryption.attributes,
        "set_committed_value",
        lambda _target, field_name, value: committed_values.append((field_name, value)),
    )

    oauth_encryption._decrypt_loaded_oauth_tokens(target, type("Ctx", (), {"session": session})())

    assert committed_values == [("refresh_token", "stored-refresh")]


def test_encrypt_oauth_tokens_before_update_skips_when_no_fields_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Update-time encryption is a no-op when neither token field changed."""
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")
    monkeypatch.setattr(
        oauth_encryption,
        "sa_inspect",
        lambda _target: _InspectState(access_changed=False, refresh_changed=False),
    )

    oauth_encryption._encrypt_oauth_tokens_before_update(object(), object(), target)

    assert not hasattr(target, "_litestar_auth_oauth_token_snapshot")


def test_restore_oauth_tokens_after_write_skips_when_no_snapshot() -> None:
    """Restore-time hooks do nothing when no write snapshot is present."""
    target = _TokenTarget(access_token="stored-access", refresh_token="stored-refresh")

    oauth_encryption._restore_oauth_tokens_after_write(object(), object(), target)

    assert target.access_token == "stored-access"
    assert target.refresh_token == "stored-refresh"
