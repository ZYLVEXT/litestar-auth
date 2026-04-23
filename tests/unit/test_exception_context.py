"""Focused contract tests for structured exception context."""

from __future__ import annotations

import pytest

from litestar_auth.exceptions import (
    ErrorCode,
    InsufficientRolesError,
    OAuthAccountAlreadyLinkedError,
    UserAlreadyExistsError,
    UserIdentifier,
)

pytestmark = pytest.mark.unit


def test_oauth_account_already_linked_error_context_contract() -> None:
    """OAuth link conflicts expose provider identity context and derive the default message from it."""
    error = OAuthAccountAlreadyLinkedError(
        provider="github",
        account_id="provider-user",
        existing_user_id="user-123",
    )

    assert error.provider == "github"
    assert error.account_id == "provider-user"
    assert error.existing_user_id == "user-123"
    assert str(error) == "OAuth account github:provider-user is already linked to user user-123"
    assert error.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


def test_user_already_exists_error_context_contract() -> None:
    """Duplicate-user errors expose identifier context without deriving public text from it."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value="user@example.com",
        ),
    )

    assert error.identifier == UserIdentifier(identifier_type="email", identifier_value="user@example.com")
    assert error.identifier_type == "email"
    assert error.identifier_value == "user@example.com"
    assert str(error) == UserAlreadyExistsError.default_message
    assert error.code == ErrorCode.REGISTER_USER_ALREADY_EXISTS


@pytest.mark.parametrize(
    ("require_all", "expected_message"),
    [
        (False, "The authenticated user does not have any of the required roles."),
        (True, "The authenticated user does not have all of the required roles."),
    ],
)
def test_insufficient_roles_error_context_contract(*, require_all: bool, expected_message: str) -> None:
    """Role-denial errors keep structured role context off the generated message."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"viewer"}),
        require_all=require_all,
    )

    assert error.required_roles == frozenset({"admin", "billing"})
    assert error.user_roles == frozenset({"viewer"})
    assert error.require_all is require_all
    assert str(error) == expected_message
    assert error.code == ErrorCode.INSUFFICIENT_ROLES


def test_oauth_account_already_linked_error_preserves_blank_context_without_runtime_validation() -> None:
    """OAuth context is stored as provided instead of raising ``ValueError`` in ``__init__``."""
    error = OAuthAccountAlreadyLinkedError(
        provider=" \t ",
        account_id="",
        existing_user_id=None,
    )

    assert error.provider == " \t "
    assert not error.account_id
    assert error.existing_user_id is None
    assert str(error) == "OAuth account  \t : is already linked to user None"


def test_user_already_exists_error_preserves_identifier_value_without_runtime_validation() -> None:
    """Duplicate-user context is stored verbatim when both identifier fields are present."""
    error = UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value=" \n ",
        ),
    )

    assert error.identifier == UserIdentifier(identifier_type="email", identifier_value=" \n ")
    assert error.identifier_type == "email"
    assert error.identifier_value == " \n "
    assert str(error) == UserAlreadyExistsError.default_message


def test_insufficient_roles_error_preserves_role_names_without_runtime_validation() -> None:
    """Role-denial context is stored verbatim instead of filtering blank role names in ``__init__``."""
    error = InsufficientRolesError(
        required_roles=frozenset({"admin", ""}),
        user_roles=frozenset({" \t "}),
        require_all=False,
    )

    assert error.required_roles == frozenset({"admin", ""})
    assert error.user_roles == frozenset({" \t "})
    assert error.require_all is False
    assert str(error) == "The authenticated user does not have any of the required roles."
