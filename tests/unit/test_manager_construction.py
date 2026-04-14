"""Unit tests for internal manager-construction helpers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pytest

import litestar_auth._manager.construction as construction_module
from litestar_auth._manager.construction import (
    ManagerConstructorInputs,
    SecretFactory,
    resolve_account_token_secrets,
)
from litestar_auth.manager import UserManagerSecurity

pytestmark = pytest.mark.unit


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


def test_manager_constructor_inputs_preserve_explicit_kwargs_without_typed_security() -> None:
    """Generic manager kwargs stay intact without becoming plugin-managed security."""

    def explicit_id_parser(raw: str) -> UUID:
        return UUID(raw)

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={
            "password_validator": None,
            "id_parser": explicit_id_parser,
            "verification_token_secret": "v" * 32,
            "reset_password_token_secret": "r" * 32,
            "totp_secret_key": "t" * 32,
            "login_identifier": "email",
        },
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        login_identifier="username",
        id_parser=UUID,
    )

    assert inputs.has_explicit_password_validator is True
    assert inputs.explicit_password_validator is None
    assert inputs.managed_security_keys == (
        "id_parser",
        "reset_password_token_secret",
        "totp_secret_key",
        "verification_token_secret",
    )
    assert inputs.resolved_security_id_parser is None
    assert inputs.security_overlap_keys == ()
    assert inputs.build_manager_security() is None
    effective_security = inputs.effective_security
    assert effective_security.verification_token_secret is None
    assert effective_security.reset_password_token_secret is None
    assert effective_security.totp_secret_key is None
    assert effective_security.id_parser is UUID
    assert inputs._build_manager_id_parser_kwargs() == {}

    kwargs = inputs.build_kwargs()
    materialized = kwargs["security"]

    assert kwargs["password_validator"] is None
    assert materialized.verification_token_secret == "v" * 32
    assert materialized.reset_password_token_secret == "r" * 32
    assert materialized.totp_secret_key == "t" * 32
    assert materialized.id_parser is explicit_id_parser
    assert kwargs["login_identifier"] == "email"
    assert kwargs["backends"] == ("bound-backend",)


def test_manager_constructor_inputs_inject_top_level_password_validator_and_id_parser() -> None:
    """Top-level helper inputs fill missing default-builder kwargs."""

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
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


def test_manager_constructor_inputs_preserve_explicit_password_validator_callable() -> None:
    """Explicit password-validator wiring stays owned by the configured manager kwargs."""

    def explicit_password_validator(_password: str) -> None:
        return None

    def generated_password_validator(_password: str) -> None:
        msg = "Plugin-owned password validators should not replace explicit manager wiring."
        raise AssertionError(msg)

    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={"password_validator": explicit_password_validator},
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        login_identifier="username",
    )

    kwargs = inputs.build_kwargs()

    assert kwargs["password_validator"] is explicit_password_validator
    assert kwargs["login_identifier"] == "username"
    assert kwargs["backends"] == ("bound-backend",)


def test_manager_constructor_inputs_reuse_typed_dataclass_security_when_parser_matches() -> None:
    """Typed manager-security dataclasses pass through unchanged when parser wiring already matches."""
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_key="t" * 32,
        id_parser=UUID,
    )
    inputs = ManagerConstructorInputs[UUID](manager_kwargs={}, manager_security=security, id_parser=UUID)

    assert inputs.resolved_security_id_parser is UUID
    assert inputs.build_manager_security() is security


def test_manager_constructor_inputs_fill_missing_parser_on_typed_dataclass_security() -> None:
    """Typed security dataclasses inherit the top-level parser before `security=` injection."""
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_key="t" * 32,
    )

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={
            "verification_token_secret": "legacy-v" * 4,
            "reset_password_token_secret": "legacy-r" * 4,
            "totp_secret_key": "legacy-t" * 4,
            "id_parser": UUID,
        },
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
        totp_secret_key="t" * 32,
        id_parser=UUID,
    )
    assert inputs.effective_security == built_security
    assert inputs.security_overlap_keys == (
        "id_parser",
        "reset_password_token_secret",
        "totp_secret_key",
        "verification_token_secret",
    )

    kwargs = inputs.build_kwargs()

    assert kwargs["security"] == built_security
    assert kwargs["password_validator"] is generated_password_validator
    assert kwargs["backends"] == ("bound-backend",)
    assert "id_parser" not in kwargs
    assert "verification_token_secret" not in kwargs
    assert "reset_password_token_secret" not in kwargs
    assert "totp_secret_key" not in kwargs


def test_manager_constructor_inputs_build_security_kwarg_from_canonical_bundle() -> None:
    """The default builder forwards the typed security bundle as one `security` kwarg."""
    security = UserManagerSecurity[UUID](
        verification_token_secret="v" * 32,
        totp_secret_key="t" * 32,
    )
    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
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

    no_parser_inputs = ManagerConstructorInputs[UUID](manager_kwargs={}, manager_security=security)
    assert no_parser_inputs._build_manager_id_parser_kwargs() == {}


def test_manager_constructor_inputs_keep_single_typed_security_kwarg_when_only_one_secret_is_set() -> None:
    """Partial typed security still stays on the single `security=` contract."""
    security = UserManagerSecurity[UUID](reset_password_token_secret="r" * 32)
    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
        manager_security=security,
    )

    kwargs = inputs.build_kwargs()

    assert kwargs["security"] == security
    assert kwargs["backends"] == ()
    assert "id_parser" not in kwargs
