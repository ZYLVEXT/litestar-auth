"""Role-surface validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.config import _normalize_config_superuser_role_name
from litestar_auth._plugin.validation._core import format_configuration_message
from litestar_auth._plugin.validation._predicates import schema_declares_field, user_model_defines_field
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.schemas import UserRead, UserUpdate
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def _role_schema_surfaces_requiring_role_capability[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> tuple[str, ...]:
    """Return plugin-owned schema surfaces that require ``user_model.roles``."""
    read_schema = config.user_read_schema or UserRead
    update_schema = config.user_update_schema or UserUpdate
    required_surfaces: list[str] = []

    if schema_declares_field(read_schema, "roles"):
        if config.include_register:
            required_surfaces.append("register responses")
        if config.include_verify:
            required_surfaces.append("verify responses")
        if config.include_reset_password:
            required_surfaces.append("reset-password responses")
        if config.include_users:
            required_surfaces.append("users responses")

    if config.include_users and schema_declares_field(update_schema, "roles"):
        required_surfaces.append("users update requests")

    return tuple(required_surfaces)


def validate_role_capable_user_model_surfaces[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Fail fast when plugin-owned schemas require ``roles`` but ``user_model`` does not expose it.

    Raises:
        ConfigurationError: If an enabled plugin-owned route surface uses a schema that includes
            ``roles`` while ``user_model`` has no matching mapped field or attribute.
    """
    if user_model_defines_field(config.user_model, "roles"):
        return

    required_surfaces = _role_schema_surfaces_requiring_role_capability(config)
    if not required_surfaces:
        return

    user_model_name = getattr(config.user_model, "__name__", config.user_model)
    msg = (
        f"user_model {user_model_name!r} has no 'roles' mapped field or attribute, but "
        f"{', '.join(required_surfaces)} use schema fields that include 'roles'. "
        "Compose UserRoleRelationshipMixin (or an equivalent normalized roles attribute), "
        "or provide user_read_schema/user_update_schema types that omit 'roles'."
    )
    raise ConfigurationError(format_configuration_message(msg))


def validate_superuser_role_name_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate and normalize the configured superuser role name."""
    config.superuser_role_name = _normalize_config_superuser_role_name(config.superuser_role_name)
