"""Unit tests for internal versioned Fernet secret-at-rest helpers."""

from __future__ import annotations

import pytest

import litestar_auth._optional_deps as optional_deps_module
import litestar_auth._secrets_at_rest as secrets_at_rest

FernetKey = secrets_at_rest.FernetKey
FernetKeyring = secrets_at_rest.FernetKeyring
SecretAtRestError = secrets_at_rest.SecretAtRestError
UnknownFernetKeyError = secrets_at_rest.UnknownFernetKeyError
decode_versioned_fernet_value = secrets_at_rest.decode_versioned_fernet_value
encode_versioned_fernet_value = secrets_at_rest.encode_versioned_fernet_value
validate_fernet_key_id = secrets_at_rest.validate_fernet_key_id

pytestmark = pytest.mark.unit


class _FakeInvalidTokenError(Exception):
    """Deterministic InvalidToken replacement for keyring tests."""


class _FakeFernet:
    """Minimal Fernet-compatible cipher with deterministic test tokens."""

    def __init__(self, key: bytes) -> None:
        """Store test key material or reject a sentinel invalid value.

        Raises:
            ValueError: If the sentinel invalid key is provided.
        """
        if key == b"bad-fernet-key":
            msg = "raw bad-fernet-key leaked by fake"
            raise ValueError(msg)
        self._prefix = b"token." + key + b"."

    def encrypt(self, data: bytes) -> bytes:
        """Return deterministic ciphertext bound to this cipher's key."""
        return self._prefix + data

    def decrypt(self, token: bytes) -> bytes:
        """Return plaintext for matching test ciphertext.

        Raises:
            _FakeInvalidTokenError: If the ciphertext was not produced by this key.
        """
        if not token.startswith(self._prefix):
            raise _FakeInvalidTokenError
        return token.removeprefix(self._prefix)


class _FakeFernetFactory:
    """Callable Fernet factory replacement for protocol-typed tests."""

    def __call__(self, key: bytes) -> _FakeFernet:
        """Build a deterministic fake Fernet cipher.

        Returns:
            A fake Fernet cipher bound to ``key``.
        """
        return _FakeFernet(key)


class _FakeFernetModule(secrets_at_rest._FernetModule):
    """Minimal ``cryptography.fernet`` module replacement."""

    Fernet: _FakeFernetFactory
    InvalidToken: type[_FakeInvalidTokenError]

    def __init__(self) -> None:
        """Expose Fernet-compatible module attributes as instance attributes."""
        self.Fernet = _FakeFernetFactory()
        self.InvalidToken = _FakeInvalidTokenError


def _fake_loader() -> _FakeFernetModule:
    """Return the deterministic fake Fernet module."""
    return _FakeFernetModule()


def _build_keyring(
    *,
    active_key_id: str = "current",
    keys: dict[str, FernetKey] | None = None,
) -> FernetKeyring:
    """Build a keyring backed by the fake Fernet module.

    Returns:
        A fake-loader-backed ``FernetKeyring``.
    """
    return FernetKeyring(
        active_key_id=active_key_id,
        keys={"current": "active-key-material"} if keys is None else keys,
        _load_cryptography_fernet=_fake_loader,
    )


def test_load_cryptography_fernet_imports_on_demand(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default loader imports ``cryptography.fernet`` only when called."""
    loaded_modules: list[str] = []
    fake_module = _FakeFernetModule()

    def import_module(name: str) -> _FakeFernetModule:
        loaded_modules.append(name)
        return fake_module

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", import_module)

    assert secrets_at_rest._load_cryptography_fernet() is fake_module
    assert loaded_modules == ["cryptography.fernet"]


def test_load_cryptography_fernet_missing_dependency_raises_extra_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing cryptography raises a stable optional-extra hint."""

    def import_module(_name: str) -> _FakeFernetModule:
        msg = "missing cryptography"
        raise ImportError(msg)

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", import_module)

    with pytest.raises(ImportError, match=r"litestar-auth\[oauth,totp\]") as exc_info:
        secrets_at_rest._load_cryptography_fernet()

    assert isinstance(exc_info.value.__cause__, ImportError)


def test_fernet_keyring_encrypts_and_decrypts_with_active_key_id() -> None:
    """The keyring writes and reads the versioned active-key storage format."""
    keyring = _build_keyring()

    stored = keyring.encrypt("plain-secret")
    parsed = decode_versioned_fernet_value(stored)

    assert stored.startswith("fernet:v1:current:")
    assert parsed.key_id == "current"
    assert parsed.encode() == stored
    assert keyring.decrypt(stored) == "plain-secret"


def test_fernet_keyring_decrypts_present_non_active_key_and_detects_rotation() -> None:
    """Values encrypted under configured old keys remain readable and rotation-detectable."""
    keys: dict[str, FernetKey] = {
        "current": "active-key-material",
        "old": b"old-key-material",
    }
    old_keyring = _build_keyring(active_key_id="old", keys=keys)
    current_keyring = _build_keyring(active_key_id="current", keys=keys)

    old_stored = old_keyring.encrypt("legacy-secret")
    current_stored = current_keyring.encrypt("active-secret")

    assert current_keyring.decrypt(old_stored) == "legacy-secret"
    assert current_keyring.needs_rotation(old_stored) is True
    assert current_keyring.needs_rotation(current_stored) is False


@pytest.mark.parametrize(
    ("stored", "match"),
    [
        pytest.param("plaintext", "must use", id="not-fernet"),
        pytest.param("fernet:v2:current:ciphertext", "unsupported", id="unsupported-version"),
        pytest.param("fernet:v1:current:", "missing ciphertext", id="missing-ciphertext"),
        pytest.param("fernet:v1:bad key:ciphertext", "key ids", id="invalid-key-id"),
    ],
)
def test_decode_versioned_fernet_value_rejects_malformed_values(stored: str, match: str) -> None:
    """Malformed storage values fail with stable, secret-free messages."""
    with pytest.raises(SecretAtRestError, match=match) as exc_info:
        decode_versioned_fernet_value(stored)

    assert stored not in str(exc_info.value)


def test_encode_versioned_fernet_value_validates_key_id_and_ciphertext() -> None:
    """Encoding rejects invalid key ids and empty ciphertexts."""
    encoded = encode_versioned_fernet_value(key_id="active_01", ciphertext="ciphertext")

    assert encoded == "fernet:v1:active_01:ciphertext"
    with pytest.raises(SecretAtRestError, match="key ids"):
        encode_versioned_fernet_value(key_id="bad:key", ciphertext="ciphertext")
    with pytest.raises(SecretAtRestError, match="non-empty ciphertext"):
        encode_versioned_fernet_value(key_id="active", ciphertext="")
    with pytest.raises(SecretAtRestError, match="key ids"):
        validate_fernet_key_id("not-ascii-\u2603")


def test_fernet_keyring_unknown_key_id_fails_without_leaking_stored_value() -> None:
    """Unknown stored key ids fail closed instead of trying unrelated keys."""
    keyring = _build_keyring()
    stored = encode_versioned_fernet_value(key_id="old", ciphertext="ciphertext-token")

    with pytest.raises(UnknownFernetKeyError, match="unknown key id") as decrypt_exc_info:
        keyring.decrypt(stored)
    with pytest.raises(UnknownFernetKeyError, match="unknown key id") as rotation_exc_info:
        keyring.needs_rotation(stored)

    assert stored not in str(decrypt_exc_info.value)
    assert "ciphertext-token" not in str(rotation_exc_info.value)


def test_fernet_keyring_corrupted_ciphertext_raises_safe_runtime_error() -> None:
    """Invalid Fernet tokens raise a stable runtime error without echoing ciphertext."""
    keyring = _build_keyring()
    stored = encode_versioned_fernet_value(key_id="current", ciphertext="not-from-current-key")

    with pytest.raises(SecretAtRestError, match="decryption failed") as exc_info:
        keyring.decrypt(stored)

    assert isinstance(exc_info.value.__cause__, _FakeInvalidTokenError)
    assert "not-from-current-key" not in str(exc_info.value)


def test_fernet_keyring_validates_configured_key_shape() -> None:
    """Invalid keyring shape and bad Fernet keys fail before encryption."""
    invalid_key_material = "bad-fernet-key"

    with pytest.raises(SecretAtRestError, match="at least one configured key"):
        _build_keyring(keys={})
    with pytest.raises(SecretAtRestError, match="active key id"):
        _build_keyring(keys={"old": "old-key-material"})
    with pytest.raises(SecretAtRestError, match="key ids"):
        _build_keyring(keys={"bad key": "key-material"})
    with pytest.raises(SecretAtRestError, match="key material is invalid") as exc_info:
        _build_keyring(keys={"current": invalid_key_material})

    assert invalid_key_material not in str(exc_info.value)


def test_fernet_keyring_repr_and_str_mask_all_configured_keys() -> None:
    """The keyring representation shows key ids while hiding raw key material."""
    keys: dict[str, FernetKey] = {
        "current": "active-key-material",
        "old": b"old-key-material",
    }
    keyring = _build_keyring(keys=keys)
    rendered_values = (repr(keyring), str(keyring))

    for rendered in rendered_values:
        assert "current" in rendered
        assert "old" in rendered
        assert "***" in rendered
        assert "active-key-material" not in rendered
        assert "old-key-material" not in rendered
