"""Constructor-time validation helpers for the auth plugin."""

from __future__ import annotations

import inspect

from litestar_auth._plugin.validation import api_key as _api_key_validation
from litestar_auth._plugin.validation._general import (
    validate_api_key_config,
    validate_config,
)
from litestar_auth._plugin.validation.credentials import (
    resolve_user_manager_account_state_validator,
    validate_credential_config,
    validate_default_user_manager_constructor_contract,
    validate_password_validator_config,
    validate_user_manager_security_config,
)
from litestar_auth._plugin.validation.login_identifier import validate_user_model_login_identifier_fields
from litestar_auth._plugin.validation.oauth_routes import validate_oauth_route_registration_config
from litestar_auth._plugin.validation.request_security import (
    _validate_backend_strategy_security,
    validate_backend_security_config,
    validate_cookie_auth_config,
    validate_rate_limit_config,
    validate_request_security_config,
)
from litestar_auth._plugin.validation.roles import (
    validate_role_capable_user_model_surfaces,
    validate_superuser_role_name_config,
)
from litestar_auth._plugin.validation.session import (
    validate_core_session_config,
    validate_session_maker_or_external_db_session,
)
from litestar_auth._plugin.validation.totp import (
    _validate_totp_encryption_key,
    _validate_totp_pending_secret_config,
    validate_totp_config,
    validate_totp_encryption_config,
    validate_totp_secret_config,
    validate_totp_sub_config,
)
from litestar_auth._plugin.validation.totp_domain import (
    validate_totp_domain_config,
    validate_totp_stepup_policy_config,
    validate_totp_user_model_protocol,
)
from litestar_auth.exceptions import ConfigurationError, SecurityWarning

__all__ = (
    "ConfigurationError",
    "SecurityWarning",
    "_api_key_validation",
    "_validate_backend_strategy_security",
    "_validate_totp_encryption_key",
    "_validate_totp_pending_secret_config",
    "inspect",
    "resolve_user_manager_account_state_validator",
    "validate_api_key_config",
    "validate_backend_security_config",
    "validate_config",
    "validate_cookie_auth_config",
    "validate_core_session_config",
    "validate_credential_config",
    "validate_default_user_manager_constructor_contract",
    "validate_oauth_route_registration_config",
    "validate_password_validator_config",
    "validate_rate_limit_config",
    "validate_request_security_config",
    "validate_role_capable_user_model_surfaces",
    "validate_session_maker_or_external_db_session",
    "validate_superuser_role_name_config",
    "validate_totp_config",
    "validate_totp_domain_config",
    "validate_totp_encryption_config",
    "validate_totp_secret_config",
    "validate_totp_stepup_policy_config",
    "validate_totp_sub_config",
    "validate_totp_user_model_protocol",
    "validate_user_manager_security_config",
    "validate_user_model_login_identifier_fields",
)
