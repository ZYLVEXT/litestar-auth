"""Centralised account-policy logic extracted from BaseUserManager."""
# ruff: noqa: ANN401

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING, Any

from litestar_auth._manager._coercions import _account_state_user
from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.exceptions import InactiveUserError, InvalidPasswordError, UnverifiedUserError
from litestar_auth.password import PasswordHelper

if TYPE_CHECKING:
    from collections.abc import Callable

EMAIL_MAX_LENGTH = 320
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class UserPolicy:
    """Stateless account-policy object shared by the manager and its services.

    Centralises email normalisation, password validation, password hashing,
    and account-state checks so that ``UserLifecycleService`` and other
    internal services no longer call back into private methods on the manager.
    """

    def __init__(
        self,
        *,
        password_helper: PasswordHelper | None = None,
        password_validator: Callable[[str], None] | None = None,
    ) -> None:
        self.password_helper = password_helper or PasswordHelper()
        self.password_validator = password_validator

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize and validate an email address.

        Returns:
            A normalized email address (stripped and lowercased).

        Raises:
            ValueError: If ``email`` is not a valid email address or exceeds 320 characters.
        """
        normalized = unicodedata.normalize("NFKC", email.strip()).lower()
        if len(normalized) > EMAIL_MAX_LENGTH or not _EMAIL_RE.fullmatch(normalized):
            msg = "Invalid email address."
            raise ValueError(msg)
        return normalized

    @staticmethod
    def normalize_username_lookup(username: str) -> str:
        """Normalize a username for database lookup (strip + lowercase).

        Returns:
            Stripped, lowercased username string (may be empty).
        """
        return username.strip().lower()

    @staticmethod
    def normalize_roles(roles: object) -> list[str]:
        """Normalize a flat role collection into a deterministic persisted form.

        Returns:
            Sorted, deduplicated, lowercased role names.
        """
        return _normalize_roles(roles)

    def validate_password(self, password: str) -> None:
        """Validate a plain-text password and normalize errors.

        The baseline length check uses ``DEFAULT_MINIMUM_PASSWORD_LENGTH`` (12
        characters) to enforce a safe default even without the plugin facade.
        When a ``password_validator`` is configured, it runs in addition to the
        baseline check and may impose stricter requirements.

        Raises:
            InvalidPasswordError: If the configured validator rejects ``password``.
        """
        try:
            require_password_length(password, minimum_length=DEFAULT_MINIMUM_PASSWORD_LENGTH)
        except ValueError as exc:
            raise InvalidPasswordError(str(exc)) from exc

        if self.password_validator is None:
            return

        try:
            self.password_validator(password)
        except InvalidPasswordError:
            raise
        except ValueError as exc:
            raise InvalidPasswordError(str(exc)) from exc

    @staticmethod
    def require_account_state(user: Any, *, require_verified: bool = False) -> None:
        """Validate active and optionally verified account state.

        Args:
            user: User to validate.
            require_verified: When ``True``, also enforce ``is_verified``.

        Raises:
            InactiveUserError: If ``user.is_active`` is false.
            UnverifiedUserError: If ``require_verified`` is true and ``user.is_verified`` is false.
        """
        account_user = _account_state_user(user)
        if not account_user.is_active:
            raise InactiveUserError
        if require_verified and not account_user.is_verified:
            raise UnverifiedUserError
