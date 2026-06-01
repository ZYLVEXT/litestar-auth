"""Validation mixin for plugin configuration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from litestar_auth._permissions import StaticRolePermissionResolver
from litestar_auth._plugin.config._resolvers import _normalize_config_superuser_role_name
from litestar_auth.config import UnsetType
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import LoginIdentifier, _valid_python_identifier_validator

_VALID_LOGIN_IDENTIFIERS: frozenset[LoginIdentifier] = frozenset(("email", "username"))


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
