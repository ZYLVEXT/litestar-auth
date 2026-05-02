"""Typed internal boundaries for user-manager construction and secret wiring."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Protocol, TypedDict

from litestar_auth._manager.security import validate_user_manager_security_secret_roles_are_distinct
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME
from litestar_auth.config import _resolve_token_secret, validate_secret_length
from litestar_auth.db.base import BaseOAuthAccountStore
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from litestar_auth._manager.security import UserManagerSecurity
    from litestar_auth.db.base import BaseUserStore
    from litestar_auth.password import PasswordHelper

type PasswordValidator = Callable[[str], None]

DEFAULT_VERIFY_TOKEN_LIFETIME = timedelta(hours=1)
DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME = timedelta(hours=1)
LOGIN_IDENTIFIER_DIGEST_SIZE = 16


class SecretValueProtocol(Protocol):
    """Structural contract for masked secret wrappers."""

    def get_secret_value(self) -> str:  # pragma: no cover
        """Return the underlying plaintext secret for cryptographic use."""


type SecretFactory = Callable[[str], SecretValueProtocol]


@dataclass(frozen=True, slots=True)
class AccountTokenSecrets:
    """Resolved verify/reset secrets consumed by account-token services."""

    verification_token_secret: SecretValueProtocol
    reset_password_token_secret: SecretValueProtocol


@dataclass(frozen=True, slots=True)
class ResolvedSecretInputs[ID]:
    """Resolved user-manager secret inputs used during construction."""

    security: UserManagerSecurity[ID]
    account_token_secrets: AccountTokenSecrets
    login_identifier_telemetry_secret: str | None


@dataclass(frozen=True, slots=True)
class ConstructorAttributes[UP: UserProtocol[Any], ID]:
    """Constructor values assigned directly to manager instance attributes."""

    user_db: BaseUserStore[UP, ID]
    oauth_account_store: BaseOAuthAccountStore[UP, ID] | None
    resolved_secret_inputs: ResolvedSecretInputs[ID]
    verification_token_lifetime: timedelta
    reset_password_token_lifetime: timedelta
    password_validator: Callable[[str], None] | None
    reset_verification_on_email_change: bool
    backends: tuple[object, ...]
    login_identifier: LoginIdentifier
    superuser_role_name: str
    unsafe_testing: bool


@dataclass(frozen=True, slots=True)
class BaseUserManagerConfig[UP: UserProtocol[Any], ID]:
    """Configuration for :class:`~litestar_auth.manager.BaseUserManager`."""

    user_db: BaseUserStore[UP, ID]
    oauth_account_store: BaseOAuthAccountStore[UP, ID] | None = None
    password_helper: PasswordHelper | None = None
    security: UserManagerSecurity[ID] | None = None
    verification_token_lifetime: timedelta = DEFAULT_VERIFY_TOKEN_LIFETIME
    reset_password_token_lifetime: timedelta = DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME
    password_validator: Callable[[str], None] | None = None
    reset_verification_on_email_change: bool = True
    backends: tuple[object, ...] = ()
    login_identifier: LoginIdentifier = "email"
    superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME
    unsafe_testing: bool = False


class BaseUserManagerOptions[UP: UserProtocol[Any], ID](TypedDict, total=False):
    """Keyword options accepted by :class:`~litestar_auth.manager.BaseUserManager`."""

    oauth_account_store: BaseOAuthAccountStore[UP, ID] | None
    password_helper: PasswordHelper | None
    security: UserManagerSecurity[ID] | None
    verification_token_lifetime: timedelta
    reset_password_token_lifetime: timedelta
    password_validator: Callable[[str], None] | None
    reset_verification_on_email_change: bool
    backends: tuple[object, ...]
    login_identifier: LoginIdentifier
    superuser_role_name: str
    unsafe_testing: bool


def resolve_oauth_account_store[UP: UserProtocol[Any], ID](
    user_db: object,
) -> BaseOAuthAccountStore[UP, ID] | None:
    """Return an OAuth-account store when the user store also exposes that boundary."""
    if isinstance(user_db, BaseOAuthAccountStore):
        return user_db

    return None


def get_dummy_hash(password_helper: PasswordHelper) -> str:
    """Return a freshly computed dummy password hash for the provided helper."""
    return password_helper.hash(secrets.token_urlsafe(32))


def login_identifier_digest(identifier: str, *, key: str) -> str:
    """Return a keyed, non-reversible digest for login-failure correlation."""
    normalized_identifier = identifier.strip().casefold()
    digest_key = hashlib.sha256(key.encode()).digest()
    return hashlib.blake2b(
        normalized_identifier.encode(),
        digest_size=LOGIN_IDENTIFIER_DIGEST_SIZE,
        key=digest_key,
    ).hexdigest()


def _build_user_manager_security[ID](
    *,
    verification_token_secret: str | None = None,
    reset_password_token_secret: str | None = None,
    totp_secret_key: str | None = None,
    id_parser: Callable[[str], ID] | None = None,
) -> UserManagerSecurity[ID]:
    """Return the concrete manager-security bundle."""
    from litestar_auth._manager.security import UserManagerSecurity  # noqa: PLC0415

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


def resolve_secret_inputs[ID](
    security: UserManagerSecurity[ID] | None,
    *,
    secret_factory: SecretFactory,
    unsafe_testing: bool,
) -> ResolvedSecretInputs[ID]:
    """Resolve secret inputs and validate standalone secret lengths.

    Returns:
        The resolved security bundle, account-token secrets, and telemetry secret.
    """
    from litestar_auth._manager.security import UserManagerSecurity  # noqa: PLC0415

    resolved_security = security if security is not None else UserManagerSecurity()
    account_token_secrets = resolve_account_token_secrets(
        resolved_security,
        secret_factory=secret_factory,
        warning_stacklevel=5,
        unsafe_testing=unsafe_testing,
    )
    resolved_login_identifier_telemetry_secret = resolved_security.login_identifier_telemetry_secret
    if resolved_login_identifier_telemetry_secret is not None and not unsafe_testing:
        validate_secret_length(
            resolved_login_identifier_telemetry_secret,
            label="login_identifier_telemetry_secret",
        )

    return ResolvedSecretInputs(
        security=resolved_security,
        account_token_secrets=account_token_secrets,
        login_identifier_telemetry_secret=resolved_login_identifier_telemetry_secret,
    )


def validate_secret_distinctness[ID](
    resolved_secret_inputs: ResolvedSecretInputs[ID],
    *,
    unsafe_testing: bool,
) -> None:
    """Validate that manager secret roles do not reuse secret values."""
    if unsafe_testing:
        return

    resolved_security = resolved_secret_inputs.security
    account_token_secrets = resolved_secret_inputs.account_token_secrets
    resolved_verification_token_secret = account_token_secrets.verification_token_secret.get_secret_value()
    resolved_reset_password_token_secret = account_token_secrets.reset_password_token_secret.get_secret_value()
    validate_user_manager_security_secret_roles_are_distinct(
        replace(
            resolved_security,
            verification_token_secret=resolved_verification_token_secret,
            reset_password_token_secret=resolved_reset_password_token_secret,
        ),
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
