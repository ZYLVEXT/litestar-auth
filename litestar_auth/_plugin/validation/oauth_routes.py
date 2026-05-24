"""OAuth route registration validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.validation.oauth import validate_oauth_route_registration_config as _validate_oauth_routes
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_oauth_route_registration_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the deterministic plugin OAuth route-registration contract."""
    _validate_oauth_routes(config.oauth_config, auth_path=config.auth_path)
