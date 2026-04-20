"""Typed internal boundaries for user-manager construction and secret wiring."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Protocol

from litestar_auth.config import _resolve_token_secret

if TYPE_CHECKING:
    from litestar_auth.manager import UserManagerSecurity
    from litestar_auth.types import LoginIdentifier

type PasswordValidator = Callable[[str], None]


class SecretValueProtocol(Protocol):
    """Structural contract for masked secret wrappers."""

    def get_secret_value(self) -> str: ...  # pragma: no cover


type SecretFactory = Callable[[str], SecretValueProtocol]


@dataclass(frozen=True, slots=True)
class AccountTokenSecrets:
    """Resolved verify/reset secrets consumed by account-token services."""

    verification_token_secret: SecretValueProtocol
    reset_password_token_secret: SecretValueProtocol


def _build_user_manager_security[ID](
    *,
    verification_token_secret: str | None = None,
    reset_password_token_secret: str | None = None,
    totp_secret_key: str | None = None,
    id_parser: Callable[[str], ID] | None = None,
) -> UserManagerSecurity[ID]:
    """Return the concrete manager-security bundle."""
    from litestar_auth.manager import UserManagerSecurity  # noqa: PLC0415

    return UserManagerSecurity(
        verification_token_secret=verification_token_secret,
        reset_password_token_secret=reset_password_token_secret,
        totp_secret_key=totp_secret_key,
        id_parser=id_parser,
    )


def resolve_account_token_secrets[ID](
    manager_security: UserManagerSecurity[ID],
    *,
    secret_factory: SecretFactory,
    warning_stacklevel: int = 2,
    unsafe_testing: bool = False,
) -> AccountTokenSecrets:
    """Resolve verify/reset secrets from the manager-security bundle.

    Returns:
        Wrapped verification/reset token secrets for account-token operations.
    """
    verification_token_secret = _resolve_token_secret(
        manager_security.verification_token_secret,
        label="verification_token_secret",
        warning_stacklevel=warning_stacklevel,
        unsafe_testing=unsafe_testing,
    )
    reset_password_token_secret = _resolve_token_secret(
        manager_security.reset_password_token_secret,
        label="reset_password_token_secret",
        warning_stacklevel=warning_stacklevel,
        unsafe_testing=unsafe_testing,
    )
    return AccountTokenSecrets(
        verification_token_secret=secret_factory(verification_token_secret),
        reset_password_token_secret=secret_factory(reset_password_token_secret),
    )


@dataclass(frozen=True, slots=True)
class ManagerConstructorInputs[ID]:
    """Typed plugin-owned inputs for request-scoped manager construction.

    The constructor contract is now fully driven by ``UserManagerSecurity`` plus the
    remaining top-level plugin-owned manager inputs.
    """

    manager_security: UserManagerSecurity[ID] | None = None
    password_validator: PasswordValidator | None = None
    backends: tuple[object, ...] = ()
    login_identifier: LoginIdentifier | None = None
    id_parser: Callable[[str], ID] | None = None

    @property
    def resolved_security_id_parser(self) -> Callable[[str], ID] | None:
        """Return the parser contributed by the typed contract or top-level config."""
        if self.manager_security is None:
            return None
        return self.manager_security.id_parser if self.manager_security.id_parser is not None else self.id_parser

    @property
    def effective_security(self) -> UserManagerSecurity[ID]:
        """Return the plugin-managed security bundle for the current inputs."""
        if self.manager_security is None:
            return _build_user_manager_security(id_parser=self.id_parser)

        resolved_id_parser = self.resolved_security_id_parser
        if self.manager_security.id_parser is resolved_id_parser:
            return self.manager_security
        return replace(self.manager_security, id_parser=resolved_id_parser)

    def build_manager_security(self) -> UserManagerSecurity[ID] | None:
        """Return the typed security bundle passed through the default builder."""
        if self.manager_security is None:
            return None
        return self.effective_security

    def _materialize_security_for_constructor(self) -> UserManagerSecurity[ID]:
        """Return the ``security=`` bundle for :class:`~litestar_auth.manager.BaseUserManager`."""
        return self.effective_security

    def _build_manager_id_parser_kwargs(self) -> dict[str, Any]:
        """Return the explicit ``id_parser`` kwarg when the default contract needs it."""
        if self.manager_security is not None or self.id_parser is None:
            return {}
        return {"id_parser": self.id_parser}

    def build_kwargs(self) -> dict[str, Any]:
        """Materialize constructor kwargs for the target manager class.

        The default plugin builder now assumes the default ``BaseUserManager``-style
        constructor contract. Custom managers that narrow or rename this surface must
        be built through ``user_manager_factory`` instead of relying on compatibility
        probing in the plugin path.

        Returns:
            A concrete kwargs dictionary ready for ``user_manager_class(...)``.
        """
        constructor_kwargs: dict[str, Any] = {
            "security": self._materialize_security_for_constructor(),
            "backends": self.backends,
        }
        if self.password_validator is not None:
            constructor_kwargs["password_validator"] = self.password_validator
        if self.login_identifier is not None:
            constructor_kwargs["login_identifier"] = self.login_identifier
        return constructor_kwargs
