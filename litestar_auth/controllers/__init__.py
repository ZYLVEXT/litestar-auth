"""Public controller factory exports.

Use ``litestar_auth.payloads`` for built-in request and response payload types.
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

__all__ = (
    "TotpUserManagerProtocol",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
)
