"""Constructor-time validation orchestrator for the auth plugin."""

from __future__ import annotations

from collections.abc import Hashable
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.config._validation import validate_organization_configuration
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


def validate_config[UP: UserProtocol[Any], ID: Hashable](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the requested plugin configuration during plugin construction."""
    for validator in (
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
