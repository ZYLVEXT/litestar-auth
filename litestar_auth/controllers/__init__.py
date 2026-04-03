"""Public controller exports.

This module is the stable import location for controller factories and their
request/response payload types. ``litestar_auth.payloads`` is the authoritative
payload boundary; root-package and controller-module re-exports remain
available for compatibility.
"""

from litestar_auth.controllers.auth import create_auth_controller
from litestar_auth.controllers.oauth import (
    create_oauth_associate_controller,
    create_oauth_controller,
)
from litestar_auth.controllers.register import create_register_controller
from litestar_auth.controllers.reset import create_reset_password_controller
from litestar_auth.controllers.totp import TotpUserManagerProtocol, create_totp_controller
from litestar_auth.controllers.users import create_users_controller
from litestar_auth.controllers.verify import create_verify_controller
from litestar_auth.payloads import (
    ForgotPassword,
    LoginCredentials,
    RefreshTokenRequest,
    RequestVerifyToken,
    ResetPassword,
    TotpConfirmEnableRequest,
    TotpConfirmEnableResponse,
    TotpDisableRequest,
    TotpEnableResponse,
    TotpVerifyRequest,
    VerifyToken,
)

__all__ = (
    "ForgotPassword",
    "LoginCredentials",
    "RefreshTokenRequest",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpUserManagerProtocol",
    "TotpVerifyRequest",
    "VerifyToken",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
)
