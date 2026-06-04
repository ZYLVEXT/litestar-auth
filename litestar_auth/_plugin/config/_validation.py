"""Validation mixin for plugin configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Protocol

from litestar_auth._permissions import StaticRolePermissionResolver
from litestar_auth._plugin.config._resolvers import _normalize_config_superuser_role_name
from litestar_auth.config import UnsetType
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import LoginIdentifier, _valid_python_identifier_validator

_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset(("email", "username"))

if TYPE_CHECKING:
    from litestar_auth._plugin.features import OrganizationConfig
    from litestar_auth.manager import UserManagerSecurity


class _OrganizationConfigCarrier(Protocol):
    organization_config: OrganizationConfig
    user_manager_security: UserManagerSecurity[Any] | None


def validate_organization_configuration(config: _OrganizationConfigCarrier) -> None:
    """Validate organization feature prerequisites during plugin startup."""
    organization_config = config.organization_config
    _validate_disabled_organization_policy(organization_config)
    if not organization_config.enabled:
        return
    _validate_enabled_organization_store(organization_config)
    _validate_enabled_organization_tenant_policy(organization_config)
    _validate_enabled_organization_invitation_policy(config)
    _validate_enabled_organization_authorization_policy(organization_config)
    _validate_enabled_organization_slug_policy(organization_config)


def _validate_disabled_organization_policy(organization_config: OrganizationConfig) -> None:
    if organization_config.enabled:
        return
    if organization_config.include_switch_organization:
        msg = (
            "organization_config.include_switch_organization cannot be True when organization_config.enabled is False."
        )
        raise ConfigurationError(msg)
    if organization_config.include_organization_admin:
        msg = "organization_config.include_organization_admin cannot be True when organization_config.enabled is False."
        raise ConfigurationError(msg)
    if organization_config.include_organization_invitations:
        msg = (
            "organization_config.include_organization_invitations cannot be True when "
            "organization_config.enabled is False."
        )
        raise ConfigurationError(msg)
    if not organization_config.require_authorization_context:
        return
    msg = "organization_config.require_authorization_context cannot be True when organization_config.enabled is False."
    raise ConfigurationError(msg)


def _validate_enabled_organization_store(organization_config: OrganizationConfig) -> None:
    if organization_config.store_factory is None:
        msg = "organization_config.store_factory is required when organization_config.enabled is True."
        raise ConfigurationError(msg)
    if not callable(organization_config.store_factory):
        msg = "organization_config.store_factory must be callable when organization_config.enabled is True."
        raise ConfigurationError(msg)


def _validate_enabled_organization_tenant_policy(organization_config: OrganizationConfig) -> None:
    if (
        not isinstance(organization_config.tenant_header_name, str)
        or not organization_config.tenant_header_name.strip()
    ):
        msg = "organization_config.tenant_header_name must be a non-empty string when organization_config.enabled is True."
        raise ConfigurationError(msg)
    if not callable(organization_config.tenant_resolver):
        msg = "organization_config.tenant_resolver must be callable when organization_config.enabled is True."
        raise ConfigurationError(msg)
    if not isinstance(organization_config.include_switch_organization, bool):
        msg = "organization_config.include_switch_organization must be a boolean when organization_config.enabled is True."
        raise ConfigurationError(msg)
    if not isinstance(organization_config.include_organization_admin, bool):
        msg = (
            "organization_config.include_organization_admin must be a boolean when organization_config.enabled is True."
        )
        raise ConfigurationError(msg)
    if not isinstance(organization_config.include_organization_invitations, bool):
        msg = (
            "organization_config.include_organization_invitations must be a boolean when "
            "organization_config.enabled is True."
        )
        raise ConfigurationError(msg)


def _validate_enabled_organization_invitation_policy(config: _OrganizationConfigCarrier) -> None:
    organization_config = config.organization_config
    if not organization_config.include_organization_invitations:
        return
    manager_security = config.user_manager_security
    if manager_security is not None and manager_security.organization_invitation_token_secret is not None:
        return
    msg = (
        "organization_config.include_organization_invitations requires "
        "user_manager_security.organization_invitation_token_secret."
    )
    raise ConfigurationError(msg)


def _validate_enabled_organization_authorization_policy(organization_config: OrganizationConfig) -> None:
    if organization_config.role_precedence not in {"replace", "merge"}:
        msg = "organization_config.role_precedence must be 'replace' or 'merge'."
        raise ConfigurationError(msg)
    if not isinstance(organization_config.require_authorization_context, bool):
        msg = "organization_config.require_authorization_context must be a boolean when organization_config.enabled is True."
        raise ConfigurationError(msg)


def _validate_enabled_organization_slug_policy(organization_config: OrganizationConfig) -> None:
    if organization_config.slug_min_length < 1:
        msg = "organization_config.slug_min_length must be greater than 0."
        raise ConfigurationError(msg)
    if organization_config.slug_max_length < organization_config.slug_min_length:
        msg = "organization_config.slug_max_length must be greater than or equal to slug_min_length."
        raise ConfigurationError(msg)


class _ConfigValidationMixin:
    """Validation helpers for ``LitestarAuthConfig`` dataclass construction."""

    def __post_init__(self: Any) -> None:
        """Validate configuration fields and build defaults that depend on other fields."""
        self.superuser_role_name = _normalize_config_superuser_role_name(self.superuser_role_name)
        self._validate_user_manager_configuration()
        self._inherit_user_manager_id_parser()
        self._validate_backend_configuration()
        self._validate_timing_configuration()
        self._validate_totp_stepup_configuration()
        self._validate_login_identifier()
        self._validate_db_session_dependency_key()
        self._validate_permission_configuration()

    def _validate_user_manager_configuration(self: Any) -> None:
        """Reject conflicting or invalid user-manager construction options.

        Raises:
            ConfigurationError: If manager construction paths conflict or a custom factory is not callable.
        """
        if self.user_manager_class is not None and self.user_manager_factory is not None:
            msg = (
                "user_manager_class and user_manager_factory are mutually exclusive. "
                "Set user_manager_class for the default manager path or "
                "user_manager_factory for a custom factory."
            )
            raise ConfigurationError(msg)
        if self.user_manager_factory is not None and not callable(self.user_manager_factory):
            msg = "user_manager_factory must be callable when provided."
            raise ConfigurationError(msg)

    def _inherit_user_manager_id_parser(self: Any) -> None:
        """Use the manager security ID parser when the config did not set one."""
        defaults = self.resolve_defaults()
        if not isinstance(defaults.id_parser, UnsetType):
            self.id_parser = defaults.id_parser

    def _validate_backend_configuration(self: Any) -> None:
        """Reject invalid mixed preset/manual backend configuration.

        Raises:
            ValueError: If both ``backends`` and ``database_token_auth`` are configured.
        """
        if self.database_token_auth is not None and self.backends:
            msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
            raise ValueError(msg)

    def _validate_timing_configuration(self: Any) -> None:
        """Validate endpoint timing floors and deployment worker settings.

        Raises:
            ConfigurationError: If timing or worker-count settings are invalid.
        """
        for field_name in (
            "login_minimum_response_seconds",
            "register_minimum_response_seconds",
            "verify_minimum_response_seconds",
            "request_verify_minimum_response_seconds",
        ):
            if getattr(self, field_name) < 0:
                msg = f"{field_name} must be non-negative."
                raise ConfigurationError(msg)
        if self.deployment_worker_count is None:
            return
        if not isinstance(self.deployment_worker_count, int) or isinstance(self.deployment_worker_count, bool):
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)
        if self.deployment_worker_count < 1:
            msg = "deployment_worker_count must be a positive integer or None."
            raise ConfigurationError(msg)

    def _validate_login_identifier(self: Any) -> None:
        """Validate runtime login identifier values accepted by dataclass construction.

        Raises:
            ConfigurationError: If the login identifier is not supported.
        """
        # Static typing covers ordinary callers, but dataclass construction still receives runtime values.
        if self.login_identifier not in _VALID_LOGIN_IDENTIFIERS:
            msg = f"Invalid login_identifier {self.login_identifier!r}. Expected 'email' or 'username'."
            raise ConfigurationError(msg)

    def _validate_totp_stepup_configuration(self: Any) -> None:
        """Validate top-level TOTP step-up settings.

        Raises:
            ConfigurationError: If the TTL is not a non-negative integer.
        """
        if (
            not isinstance(self.totp_stepup_ttl_seconds, int)
            or isinstance(self.totp_stepup_ttl_seconds, bool)
            or self.totp_stepup_ttl_seconds < 0
        ):
            msg = "totp_stepup_ttl_seconds must be a non-negative integer."
            raise ConfigurationError(msg)

    def _validate_db_session_dependency_key(self: Any) -> None:
        """Validate Litestar dependency key syntax.

        Raises:
            ValueError: If the dependency key is not a valid Python identifier.
        """
        try:
            _valid_python_identifier_validator(self.db_session_dependency_key)
        except ValueError as exc:
            raise ValueError(*exc.args) from None

    def _validate_permission_configuration(self: Any) -> None:
        """Validate permission resolver configuration at startup.

        Raises:
            ConfigurationError: If the static role map is malformed or an explicit
                resolver does not expose the expected ``resolve`` callable.
        """
        if not isinstance(self.role_permissions, Mapping):
            msg = "role_permissions must be a mapping of role names to permission iterables."
            raise ConfigurationError(msg)
        try:
            StaticRolePermissionResolver(
                self.role_permissions,
                superuser_role_name=self.superuser_role_name,
            )
        except (TypeError, ValueError) as exc:
            msg = f"role_permissions is invalid: {exc}"
            raise ConfigurationError(msg) from exc

        if self.permission_resolver is not None and not callable(getattr(self.permission_resolver, "resolve", None)):
            msg = "permission_resolver must expose a callable resolve(user, *, context=None) method."
            raise ConfigurationError(msg)
