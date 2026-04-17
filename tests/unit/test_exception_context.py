"""Focused contract tests for structured exception context."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from litestar_auth.exceptions import (
    ErrorCode,
    InsufficientRolesError,
    OAuthAccountAlreadyLinkedError,
    UserAlreadyExistsError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

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
    """Duplicate-user errors expose identifier context and derive the default message from it."""
    error = UserAlreadyExistsError(
        identifier_type="email",
        identifier_value="user@example.com",
    )

    assert error.identifier_type == "email"
    assert error.identifier_value == "user@example.com"
    assert str(error) == "User with email='user@example.com' already exists"
    assert error.code == ErrorCode.REGISTER_USER_ALREADY_EXISTS


@pytest.mark.parametrize(
    ("require_all", "expected_message"),
    [
        (
            False,
            (
                "The authenticated user does not have any of the required roles. "
                "required_roles=['admin', 'billing']; user_roles=['viewer']"
            ),
        ),
        (
            True,
            (
                "The authenticated user does not have all of the required roles. "
                "required_roles=['admin', 'billing']; user_roles=['viewer']"
            ),
        ),
    ],
)
def test_insufficient_roles_error_context_contract(*, require_all: bool, expected_message: str) -> None:
    """Role-denial errors expose structured role context and include it in the generated message."""
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


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (
            lambda: OAuthAccountAlreadyLinkedError(
                provider=" \t ",
                account_id="provider-user",
                existing_user_id="user-123",
            ),
            "provider cannot be empty or whitespace-only",
        ),
        (
            lambda: OAuthAccountAlreadyLinkedError(
                provider="github",
                account_id="",
                existing_user_id="user-123",
            ),
            "account_id cannot be empty or whitespace-only",
        ),
        (
            lambda: OAuthAccountAlreadyLinkedError(
                provider="github",
                account_id="provider-user",
                existing_user_id=None,
            ),
            "existing_user_id cannot be None",
        ),
        (
            lambda: UserAlreadyExistsError(
                identifier_type="email",
                identifier_value=" \n ",
            ),
            "identifier_value cannot be empty or whitespace-only",
        ),
        (
            lambda: InsufficientRolesError(
                required_roles=frozenset({"admin", ""}),
                user_roles=frozenset({"viewer"}),
                require_all=False,
            ),
            "required_roles cannot contain empty or whitespace-only role names",
        ),
        (
            lambda: InsufficientRolesError(
                required_roles=frozenset({"admin"}),
                user_roles=frozenset({" \t "}),
                require_all=False,
            ),
            "user_roles cannot contain empty or whitespace-only role names",
        ),
    ],
)
def test_exception_context_validation_rejects_empty_context(
    factory: Callable[[], object],
    match: str,
) -> None:
    """Structured exception context fails fast when required values are blank or missing."""
    with pytest.raises(ValueError, match=match):
        factory()
