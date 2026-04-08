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


def user_manager_security_from_mapping[ID](
    manager_kwargs: Mapping[str, Any],
    *,
    id_parser: Callable[[str], ID] | None = None,
) -> UserManagerSecurity[ID]:
    """Build the canonical manager-security bundle from legacy kwargs.

    Returns:
        Concrete ``UserManagerSecurity`` synthesized from the provided mapping.
    """
    explicit_id_parser = cast("Callable[[str], ID] | None", manager_kwargs.get("id_parser"))
    return _build_user_manager_security(
        verification_token_secret=cast("str | None", manager_kwargs.get("verification_token_secret")),
        reset_password_token_secret=cast("str | None", manager_kwargs.get("reset_password_token_secret")),
        totp_secret_key=cast("str | None", manager_kwargs.get("totp_secret_key")),
        id_parser=explicit_id_parser if explicit_id_parser is not None else id_parser,
    )


def resolve_account_token_secrets[ID](
    manager_security: UserManagerSecurity[ID],
    *,
    secret_factory: SecretFactory,
    warning_stacklevel: int = 2,
) -> AccountTokenSecrets:
    """Resolve verify/reset secrets from the canonical manager-security bundle.

    Returns:
        Wrapped verification/reset token secrets for account-token operations.
    """
    verification_token_secret = _resolve_token_secret(
        manager_security.verification_token_secret,
        label="verification_token_secret",
        warning_stacklevel=warning_stacklevel,
    )
    reset_password_token_secret = _resolve_token_secret(
        manager_security.reset_password_token_secret,
        label="reset_password_token_secret",
        warning_stacklevel=warning_stacklevel,
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
    def has_explicit_id_parser(self) -> bool:
        """Return whether ``user_manager_kwargs`` declares ``id_parser``."""
        return "id_parser" in self.manager_kwargs

    @property
    def explicit_id_parser(self) -> Callable[[str], ID] | None:
        """Return the explicit ID parser declared through ``user_manager_kwargs``."""
        return cast("Callable[[str], ID] | None", self.manager_kwargs.get("id_parser"))

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
        return tuple(sorted(set(self.manager_kwargs).intersection(_MANAGED_SECURITY_KEYS)))

    @property
    def effective_security(self) -> UserManagerSecurity[ID]:
        """Return the canonical manager-security bundle for the current constructor inputs."""
        if self.manager_security is None:
            resolved_id_parser = self.explicit_id_parser if self.has_explicit_id_parser else self.id_parser
            return user_manager_security_from_mapping(self.manager_kwargs, id_parser=resolved_id_parser)

        resolved_id_parser = self.resolved_security_id_parser
        if self.manager_security.id_parser is resolved_id_parser:
            return self.manager_security
        return replace(self.manager_security, id_parser=resolved_id_parser)

    def build_manager_security(self) -> UserManagerSecurity[ID] | None:
        """Return the typed security bundle passed to security-aware managers."""
        if self.manager_security is None:
            return None
        return self.effective_security

    def _build_manager_id_parser_kwargs(
        self,
        *,
        accepts_security: bool,
        accepts_id_parser: bool,
    ) -> dict[str, Any]:
        """Return the manager-specific ``id_parser`` kwargs for this constructor."""
        if not accepts_id_parser:
            return {}

        if self.manager_security is None:
            resolved_id_parser = self.explicit_id_parser if self.has_explicit_id_parser else self.id_parser
            if resolved_id_parser is None or self.has_explicit_id_parser:
                return {}
            return {"id_parser": resolved_id_parser}

        if accepts_security:
            return {}

        resolved_id_parser = self.resolved_security_id_parser
        if resolved_id_parser is None:
            return {}
        return {"id_parser": resolved_id_parser}

    def _build_manager_security_kwargs(self, *, accepts_security: bool) -> dict[str, Any]:
        """Return security-related kwargs for the target manager constructor."""
        if self.manager_security is None:
            return {}

        if accepts_security:
            manager_security = self.build_manager_security()
            return {"security": manager_security} if manager_security is not None else {}

        manager_kwargs: dict[str, Any] = {}
        if self.manager_security.verification_token_secret is not None:
            manager_kwargs["verification_token_secret"] = self.manager_security.verification_token_secret
        if self.manager_security.reset_password_token_secret is not None:
            manager_kwargs["reset_password_token_secret"] = self.manager_security.reset_password_token_secret
        if self.manager_security.totp_secret_key is not None:
            manager_kwargs["totp_secret_key"] = self.manager_security.totp_secret_key
        return manager_kwargs

    def build_kwargs(
        self,
        *,
        accepts_security: bool,
        accepts_id_parser: bool,
        accepts_login_identifier: bool,
    ) -> dict[str, Any]:
        """Materialize constructor kwargs for the target manager class.

        The typed ``user_manager_security`` bundle is passed through as ``security=...``
        when the target constructor supports it. Otherwise the builder falls back to
        the legacy explicit secret kwargs while preserving the documented top-level
        ``id_parser`` compatibility path.

        Returns:
            A concrete kwargs dictionary ready for ``user_manager_class(...)``.
        """
        manager_kwargs = dict(self.manager_kwargs)
        if self.manager_security is not None:
            for key in _MANAGED_SECURITY_KEYS:
                manager_kwargs.pop(key, None)
        manager_kwargs.update(self._build_manager_security_kwargs(accepts_security=accepts_security))
        if self.password_validator is not None and not self.has_explicit_password_validator:
            manager_kwargs["password_validator"] = self.password_validator
        manager_kwargs["backends"] = self.backends
        manager_kwargs.update(
            self._build_manager_id_parser_kwargs(
                accepts_security=accepts_security,
                accepts_id_parser=accepts_id_parser,
            ),
        )
        if accepts_login_identifier and "login_identifier" not in manager_kwargs and self.login_identifier is not None:
            manager_kwargs["login_identifier"] = self.login_identifier
        return manager_kwargs
