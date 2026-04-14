"""Typed internal boundaries for user-manager construction and secret wiring."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Protocol, cast

from litestar_auth.config import _resolve_token_secret

if TYPE_CHECKING:
    from litestar_auth.manager import UserManagerSecurity
    from litestar_auth.types import LoginIdentifier

type PasswordValidator = Callable[[str], None]


class SecretValueProtocol(Protocol):
    """Structural contract for masked secret wrappers."""

    def get_secret_value(self) -> str: ...  # pragma: no cover


type SecretFactory = Callable[[str], SecretValueProtocol]

_MANAGED_SECURITY_KEYS = frozenset(
    {
        "verification_token_secret",
        "reset_password_token_secret",
        "totp_secret_key",
        "id_parser",
    },
)


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
    """Return the canonical concrete manager-security bundle."""
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
    """Resolve verify/reset secrets from the canonical manager-security bundle.

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
    """Typed plugin-owned inputs for request-scoped manager construction."""

    manager_kwargs: Mapping[str, Any]
    manager_security: UserManagerSecurity[ID] | None = None
    password_validator: PasswordValidator | None = None
    backends: tuple[object, ...] = ()
    login_identifier: LoginIdentifier | None = None
    id_parser: Callable[[str], ID] | None = None

    @property
    def has_explicit_password_validator(self) -> bool:
        """Return whether ``user_manager_kwargs`` declares ``password_validator``."""
        return "password_validator" in self.manager_kwargs

    @property
    def explicit_password_validator(self) -> PasswordValidator | None:
        """Return the explicit validator declared through ``user_manager_kwargs``."""
        return cast("PasswordValidator | None", self.manager_kwargs.get("password_validator"))

    @property
    def managed_security_keys(self) -> tuple[str, ...]:
        """Return legacy plugin-managed security keys present in ``user_manager_kwargs``."""
        return tuple(sorted(set(self.manager_kwargs).intersection(_MANAGED_SECURITY_KEYS)))

    @property
    def resolved_security_id_parser(self) -> Callable[[str], ID] | None:
        """Return the parser contributed by the typed contract or top-level config."""
        if self.manager_security is None:
            return None
        return self.manager_security.id_parser if self.manager_security.id_parser is not None else self.id_parser

    @property
    def security_overlap_keys(self) -> tuple[str, ...]:
        """Return managed security keys present in legacy kwargs alongside the typed contract."""
        if self.manager_security is None:
            return ()
        return self.managed_security_keys

    @property
    def effective_security(self) -> UserManagerSecurity[ID]:
        """Return the canonical plugin-managed security bundle for the current inputs."""
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
        """Return the ``security=`` bundle for :class:`~litestar_auth.manager.BaseUserManager`.

        When ``manager_security`` is unset, managed keys may still appear in ``manager_kwargs``
        (factory-owned wiring). Fold those into a concrete
        :class:`~litestar_auth.manager.UserManagerSecurity` so the manager receives a single
        ``security=`` argument.
        """
        base = self.effective_security
        if self.manager_security is not None:
            return base
        merge = {key: self.manager_kwargs[key] for key in _MANAGED_SECURITY_KEYS if key in self.manager_kwargs}
        if not merge:
            return base
        return replace(base, **merge)

    def _build_manager_id_parser_kwargs(self) -> dict[str, Any]:
        """Return the explicit ``id_parser`` kwarg when the default contract needs it."""
        if self.manager_security is not None or self.id_parser is None or "id_parser" in self.manager_kwargs:
            return {}
        return {"id_parser": self.id_parser}

    def build_kwargs(self) -> dict[str, Any]:
        """Materialize constructor kwargs for the target manager class.

        The default plugin builder now assumes the canonical ``BaseUserManager``-style
        constructor contract. Custom managers that narrow or rename this surface must
        be built through ``user_manager_factory`` instead of relying on compatibility
        probing in the plugin path.

        Returns:
            A concrete kwargs dictionary ready for ``user_manager_class(...)``.
        """
        manager_kwargs = dict(self.manager_kwargs)
        if self.manager_security is not None:
            for key in _MANAGED_SECURITY_KEYS:
                manager_kwargs.pop(key, None)
        for key in _MANAGED_SECURITY_KEYS:
            manager_kwargs.pop(key, None)
        manager_kwargs.pop("security", None)
        manager_kwargs["security"] = self._materialize_security_for_constructor()
        if self.password_validator is not None and not self.has_explicit_password_validator:
            manager_kwargs["password_validator"] = self.password_validator
        manager_kwargs["backends"] = self.backends
        if "login_identifier" not in manager_kwargs and self.login_identifier is not None:
            manager_kwargs["login_identifier"] = self.login_identifier
        return manager_kwargs
