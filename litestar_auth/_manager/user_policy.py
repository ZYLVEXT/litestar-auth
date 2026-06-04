"""Centralised account-policy logic extracted from BaseUserManager."""
# ruff: noqa: ANN401

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar_auth._email import EMAIL_MAX_LENGTH as _EMAIL_MAX_LENGTH
from litestar_auth._email import normalize_email as _normalize_email
from litestar_auth._manager._coercions import _account_state_user
from litestar_auth._roles import normalize_roles as _normalize_roles
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.exceptions import AuthorizationError, InactiveUserError, InvalidPasswordError, UnverifiedUserError
from litestar_auth.password import PasswordHelper

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

EMAIL_MAX_LENGTH = _EMAIL_MAX_LENGTH
DEFAULT_CREATABLE_FIELDS = frozenset({"email", "password"})
DEFAULT_UPDATABLE_FIELDS = frozenset({"email", "password"})
PRIVILEGED_FIELDS = frozenset({"is_active", "is_verified", "roles"})


@dataclass(frozen=True, slots=True)
class UserFieldPolicy:
    """Explicit create/update field policy for manager-owned user payloads."""

    creatable_fields: frozenset[str] = DEFAULT_CREATABLE_FIELDS
    updatable_fields: frozenset[str] = DEFAULT_UPDATABLE_FIELDS
    privileged_fields: frozenset[str] = PRIVILEGED_FIELDS

    def filter_create_payload(
        self,
        user_dict: Mapping[str, Any],
        *,
        safe: bool,
        allow_privileged: bool,
    ) -> dict[str, Any]:
        """Return a create payload filtered or validated by the explicit policy."""
        if safe:
            return {field_name: value for field_name, value in user_dict.items() if field_name in self.creatable_fields}

        create_dict = dict(user_dict)
        if not allow_privileged:
            create_dict = {
                field_name: value
                for field_name, value in create_dict.items()
                if field_name not in self.privileged_fields
            }
        self._raise_for_undeclared_fields(
            create_dict,
            allowed_fields=self._creatable_fields(allow_privileged=allow_privileged),
            operation="create",
        )
        return create_dict

    def validate_update_payload(self, update_dict: Mapping[str, Any], *, allow_privileged: bool) -> None:
        """Raise when an update payload contains fields outside the explicit policy.

        Raises:
            AuthorizationError: If the payload includes undeclared fields, or privileged fields without opt-in.
        """
        privileged_fields = sorted(set(update_dict) & self.privileged_fields)
        if privileged_fields and not allow_privileged:
            msg = f"Privileged user fields require allow_privileged=True on manager.update(): {privileged_fields}."
            raise AuthorizationError(msg)

        self._raise_for_undeclared_fields(
            update_dict,
            allowed_fields=self._updatable_fields(allow_privileged=allow_privileged),
            operation="update",
        )

    def _creatable_fields(self, *, allow_privileged: bool) -> frozenset[str]:
        if allow_privileged:
            return self.creatable_fields | self.privileged_fields
        return self.creatable_fields

    def _updatable_fields(self, *, allow_privileged: bool) -> frozenset[str]:
        if allow_privileged:
            return self.updatable_fields | self.privileged_fields
        return self.updatable_fields

    @staticmethod
    def _raise_for_undeclared_fields(
        payload: Mapping[str, Any],
        *,
        allowed_fields: frozenset[str],
        operation: str,
    ) -> None:
        undeclared_fields = sorted(set(payload) - allowed_fields)
        if not undeclared_fields:
            return

        msg = f"Undeclared user fields require an explicit manager {operation} field policy: {undeclared_fields}."
        raise AuthorizationError(msg)


DEFAULT_USER_FIELD_POLICY = UserFieldPolicy()


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
        field_policy: UserFieldPolicy = DEFAULT_USER_FIELD_POLICY,
    ) -> None:
        self.password_helper = password_helper or PasswordHelper()
        self.password_validator = password_validator
        self.field_policy = field_policy

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize and validate an email address.

        Returns:
            A normalized email address (stripped and lowercased).
        """
        return _normalize_email(email)

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
            raise InvalidPasswordError(message=str(exc)) from exc

        if self.password_validator is None:
            return

        try:
            self.password_validator(password)
        except InvalidPasswordError:
            raise
        except ValueError as exc:
            raise InvalidPasswordError(message=str(exc)) from exc

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
