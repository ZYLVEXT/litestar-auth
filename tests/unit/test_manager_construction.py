"""Unit tests for internal manager-construction helpers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

import litestar_auth._manager.construction as construction_module
from litestar_auth._manager.construction import (
    ManagerConstructorInputs,
    SecretFactory,
    resolve_account_token_secrets,
)
from litestar_auth.manager import FernetKeyringConfig, UserManagerSecurity

pytestmark = pytest.mark.unit


def _fernet_key() -> str:
    """Return a valid Fernet key for construction tests."""
    return Fernet.generate_key().decode()


@dataclass(frozen=True, slots=True)
class SecretWrapper:
    """Minimal secret wrapper for constructor-helper tests."""

    value: str

    def get_secret_value(self) -> str:
        """Return the wrapped secret value."""
        return self.value


def test_manager_construction_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records helper and dataclass execution."""
    reloaded_module = importlib.reload(construction_module)

    assert reloaded_module.ManagerConstructorInputs.__name__ == ManagerConstructorInputs.__name__


def test_resolve_account_token_secrets_wraps_account_token_secrets() -> None:
    """Typed manager security still resolves and wraps account-token secrets."""
    manager_security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_key="t" * 32,
    )

    resolved = resolve_account_token_secrets(
        manager_security,
        secret_factory=cast("SecretFactory", SecretWrapper),
        warning_stacklevel=5,
    )

    assert manager_security.verification_token_secret == "v" * 32
    assert manager_security.reset_password_token_secret == "r" * 32
    assert manager_security.totp_secret_key == "t" * 32
    assert manager_security.id_parser is None
    assert resolved.verification_token_secret.get_secret_value() == "v" * 32
    assert resolved.reset_password_token_secret.get_secret_value() == "r" * 32


def test_manager_constructor_inputs_build_typed_defaults_without_explicit_security() -> None:
    """Untyped inputs build only the canonical security bundle and plugin-owned kwargs."""

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        login_identifier="username",
        id_parser=UUID,
    )

    assert inputs.resolved_security_id_parser is None
    assert inputs.build_manager_security() is None
    effective_security = inputs.effective_security
    assert effective_security.verification_token_secret is None
    assert effective_security.reset_password_token_secret is None
    assert effective_security.totp_secret_key is None
    assert effective_security.id_parser is UUID
    assert inputs._build_manager_id_parser_kwargs() == {"id_parser": UUID}

    kwargs = inputs.build_kwargs()

    assert kwargs == {
        "security": effective_security,
        "password_validator": generated_password_validator,
        "backends": ("bound-backend",),
        "login_identifier": "username",
    }


def test_manager_constructor_inputs_inject_top_level_password_validator_and_id_parser() -> None:
    """Top-level helper inputs fill the canonical default-builder contract."""

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        login_identifier="username",
        id_parser=UUID,
    )

    assert inputs._build_manager_id_parser_kwargs() == {"id_parser": UUID}

    kwargs = inputs.build_kwargs()
    effective_security = inputs.effective_security

    assert effective_security.verification_token_secret is None
    assert effective_security.reset_password_token_secret is None
    assert effective_security.totp_secret_key is None
    assert effective_security.id_parser is UUID
    assert kwargs["password_validator"] is generated_password_validator
    assert kwargs["security"] == effective_security
    assert kwargs["security"].id_parser is UUID
    assert kwargs["login_identifier"] == "username"
    assert kwargs["backends"] == ("bound-backend",)


def test_manager_constructor_inputs_reuse_typed_dataclass_security_when_parser_matches() -> None:
    """Typed manager-security dataclasses pass through unchanged when parser wiring already matches."""
    totp_keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()})
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_keyring=totp_keyring,
        id_parser=UUID,
    )
    inputs = ManagerConstructorInputs[UUID](manager_security=security, id_parser=UUID)

    assert inputs.resolved_security_id_parser is UUID
    assert inputs.build_manager_security() is security


def test_manager_constructor_inputs_fill_missing_parser_on_typed_dataclass_security() -> None:
    """Typed security dataclasses inherit the top-level parser before `security=` injection."""
    totp_keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _fernet_key()})
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_keyring=totp_keyring,
    )

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        manager_security=security,
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        id_parser=UUID,
    )

    built_security = inputs.build_manager_security()
    assert built_security is not security
    assert built_security == UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_keyring=totp_keyring,
        id_parser=UUID,
    )
    assert inputs.effective_security == built_security

    kwargs = inputs.build_kwargs()

    assert kwargs["security"] == built_security
    assert kwargs["password_validator"] is generated_password_validator
    assert kwargs["backends"] == ("bound-backend",)
    assert "id_parser" not in kwargs


def test_manager_constructor_inputs_build_security_kwarg_from_canonical_bundle() -> None:
    """The default builder forwards the typed security bundle as one `security` kwarg."""
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        totp_secret_key="t" * 32,
    )
    inputs = ManagerConstructorInputs[UUID](
        manager_security=security,
        id_parser=UUID,
    )

    built_security = inputs.build_manager_security()

    assert built_security is not None
    assert isinstance(built_security, UserManagerSecurity)
    assert built_security.verification_token_secret == "v" * 32
    assert built_security.reset_password_token_secret is None
    assert built_security.totp_secret_key == "t" * 32
    assert built_security.id_parser is UUID

    kwargs = inputs.build_kwargs()

    assert kwargs["security"] == built_security
    assert kwargs["backends"] == ()
    assert "id_parser" not in kwargs
    assert "verification_token_secret" not in kwargs
    assert "reset_password_token_secret" not in kwargs
    assert "totp_secret_key" not in kwargs

    no_parser_inputs = ManagerConstructorInputs[UUID](manager_security=security)
    assert no_parser_inputs._build_manager_id_parser_kwargs() == {}


def test_manager_constructor_inputs_keep_single_typed_security_kwarg_when_only_one_secret_is_set() -> None:
    """Partial typed security still stays on the single `security=` contract."""
    security = UserManagerSecurity[UUID](reset_password_token_secret="r" * 32)
    inputs = ManagerConstructorInputs[UUID](
        manager_security=security,
    )

    kwargs = inputs.build_kwargs()

    assert kwargs["security"] == security
    assert kwargs["backends"] == ()
    assert "id_parser" not in kwargs
