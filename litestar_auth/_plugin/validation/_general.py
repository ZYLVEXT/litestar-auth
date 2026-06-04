"""Constructor-time validation orchestrator for the auth plugin."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.config._validation import validate_organization_configuration
from litestar_auth._plugin.validation import api_key as _api_key_validation
from litestar_auth._plugin.validation.credentials import validate_credential_config
from litestar_auth._plugin.validation.oauth_routes import validate_oauth_route_registration_config
from litestar_auth._plugin.validation.request_security import (
    validate_backend_security_config,
    validate_request_security_config,
)
from litestar_auth._plugin.validation.session import validate_core_session_config
from litestar_auth._plugin.validation.totp import validate_totp_encryption_config, validate_totp_secret_config
from litestar_auth._plugin.validation.totp_domain import validate_totp_domain_config
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth.authentication.strategy.jwt import JWTStrategy


validate_api_key_config = _api_key_validation.validate_api_key_config


def _current_jwt_strategy_type() -> type[JWTStrategy]:
    """Return the live JWT strategy class."""
    jwt_module = import_module("litestar_auth.authentication.strategy.jwt")
    return cast("type[JWTStrategy]", jwt_module.JWTStrategy)


def validate_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the requested plugin configuration during plugin construction."""
    for validator in (
        validate_api_key_config,
        validate_organization_configuration,
        validate_core_session_config,
        validate_credential_config,
        validate_totp_secret_config,
        validate_totp_domain_config,
        validate_request_security_config,
        validate_oauth_route_registration_config,
        validate_backend_security_config,
        validate_totp_encryption_config,
    ):
        validator(config)
