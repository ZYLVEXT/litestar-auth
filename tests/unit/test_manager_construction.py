"""Unit tests for internal manager-construction helpers."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from uuid import UUID

import pytest

import litestar_auth._manager.construction as construction_module
from litestar_auth._manager.construction import (
    ManagerConstructorInputs,
    ManagerSecretInputs,
    ResolvedUserManagerSecurity,
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


class SecurityContract:
    """Non-dataclass security contract used to cover protocol adaptation."""

    def __init__(
        self,
        *,
        verification_token_secret: str | None = None,
        reset_password_token_secret: str | None = None,
        totp_secret_key: str | None = None,
        id_parser: type[UUID] | None = None,
    ) -> None:
        """Store the configured security fields."""
        self.verification_token_secret = verification_token_secret
        self.reset_password_token_secret = reset_password_token_secret
        self.totp_secret_key = totp_secret_key
        self.id_parser = id_parser


def test_manager_construction_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records helper and dataclass execution."""
    reloaded_module = importlib.reload(construction_module)

    assert reloaded_module.ManagerConstructorInputs.__name__ == ManagerConstructorInputs.__name__
    assert reloaded_module.ResolvedUserManagerSecurity.__name__ == ResolvedUserManagerSecurity.__name__


def test_manager_secret_inputs_from_mapping_and_resolve_wraps_account_token_secrets() -> None:
    """Raw manager secret mappings resolve into wrapped verify/reset secrets plus TOTP input."""
    secret_inputs = ManagerSecretInputs.from_mapping(
        {
            "verification_token_secret": "v" * 32,
            "reset_password_token_secret": "r" * 32,
            "totp_secret_key": "t" * 32,
        },
    )

    resolved = secret_inputs.resolve(secret_factory=SecretWrapper, warning_stacklevel=5)

    assert resolved.account_token_secrets.verification_token_secret.get_secret_value() == "v" * 32
    assert resolved.account_token_secrets.reset_password_token_secret.get_secret_value() == "r" * 32
    assert resolved.totp_secret_key == "t" * 32


def test_manager_constructor_inputs_preserve_explicit_kwargs_without_typed_security() -> None:
    """Legacy explicit kwargs remain authoritative when no typed security bundle is present."""
    explicit_id_parser = UUID

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
    assert inputs.has_explicit_id_parser is True
    assert inputs.explicit_id_parser is explicit_id_parser
    assert inputs.resolved_security_id_parser is None
    assert inputs.security_overlap_keys == ()
    assert inputs.build_manager_security() is None
    assert inputs.secret_inputs == construction_module.ManagerSecretInputs(
        verification_token_secret="v" * 32,
        reset_password_token_secret="r" * 32,
        totp_secret_key="t" * 32,
    )
    assert (
        inputs._build_manager_id_parser_kwargs(
            accepts_security=False,
            accepts_id_parser=False,
        )
        == {}
    )

    kwargs = inputs.build_kwargs(
        accepts_security=False,
        accepts_id_parser=True,
        accepts_login_identifier=True,
    )

    assert kwargs["password_validator"] is None
    assert kwargs["id_parser"] is explicit_id_parser
    assert kwargs["login_identifier"] == "email"
    assert kwargs["backends"] == ("bound-backend",)


def test_manager_constructor_inputs_inject_top_level_password_validator_and_id_parser() -> None:
    """Top-level helper inputs fill missing legacy kwargs only when constructors support them."""

    def generated_password_validator(_password: str) -> None:
        return None

    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
        password_validator=generated_password_validator,
        backends=("bound-backend",),
        login_identifier="username",
        id_parser=UUID,
    )

    kwargs = inputs.build_kwargs(
        accepts_security=False,
        accepts_id_parser=True,
        accepts_login_identifier=True,
    )

    assert kwargs["password_validator"] is generated_password_validator
    assert kwargs["id_parser"] is UUID
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
    """Typed security dataclasses inherit the top-level parser before security-aware injection."""
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
    assert inputs.security_overlap_keys == (
        "id_parser",
        "reset_password_token_secret",
        "totp_secret_key",
        "verification_token_secret",
    )

    kwargs = inputs.build_kwargs(
        accepts_security=True,
        accepts_id_parser=True,
        accepts_login_identifier=False,
    )

    assert kwargs["security"] == built_security
    assert kwargs["password_validator"] is generated_password_validator
    assert kwargs["backends"] == ("bound-backend",)
    assert "id_parser" not in kwargs
    assert "verification_token_secret" not in kwargs
    assert "reset_password_token_secret" not in kwargs
    assert "totp_secret_key" not in kwargs


def test_manager_constructor_inputs_adapt_non_dataclass_security_for_legacy_constructors() -> None:
    """Protocol-compatible security objects adapt into legacy secret kwargs when needed."""
    security = SecurityContract(
        verification_token_secret="v" * 32,
        totp_secret_key="t" * 32,
    )
    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
        manager_security=security,
        id_parser=UUID,
    )

    built_security = inputs.build_manager_security()
    assert isinstance(built_security, construction_module.ResolvedUserManagerSecurity)
    assert built_security.verification_token_secret == "v" * 32
    assert built_security.reset_password_token_secret is None
    assert built_security.totp_secret_key == "t" * 32
    assert built_security.id_parser is UUID

    kwargs = inputs.build_kwargs(
        accepts_security=False,
        accepts_id_parser=True,
        accepts_login_identifier=False,
    )

    assert kwargs["verification_token_secret"] == "v" * 32
    assert "reset_password_token_secret" not in kwargs
    assert kwargs["totp_secret_key"] == "t" * 32
    assert kwargs["id_parser"] is UUID
    assert kwargs["backends"] == ()

    no_parser_inputs = ManagerConstructorInputs[UUID](manager_kwargs={}, manager_security=security)
    assert (
        no_parser_inputs._build_manager_id_parser_kwargs(
            accepts_security=False,
            accepts_id_parser=True,
        )
        == {}
    )


def test_manager_constructor_inputs_skip_missing_legacy_security_kwargs() -> None:
    """Legacy compatibility kwargs include only the non-null secrets from typed security."""
    security = SecurityContract(reset_password_token_secret="r" * 32)
    inputs = ManagerConstructorInputs[UUID](
        manager_kwargs={},
        manager_security=security,
    )

    kwargs = inputs.build_kwargs(
        accepts_security=False,
        accepts_id_parser=False,
        accepts_login_identifier=False,
    )

    assert "verification_token_secret" not in kwargs
    assert kwargs["reset_password_token_secret"] == "r" * 32
    assert "totp_secret_key" not in kwargs
