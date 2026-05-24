"""Login-identifier validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.validation._core import format_configuration_message
from litestar_auth._plugin.validation._predicates import user_model_defines_field
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_user_model_login_identifier_fields[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure ``user_model`` defines the attribute implied by ``login_identifier``.

    Raises:
        ConfigurationError: When the model lacks ``email`` or ``username`` as required by
            ``login_identifier``.
    """
    field_name = config.login_identifier
    model_cls = config.user_model
    if not user_model_defines_field(model_cls, field_name):
        msg = (
            f"LitestarAuthConfig.login_identifier is {field_name!r}, but user_model "
            f"{getattr(model_cls, '__name__', model_cls)!r} has no {field_name!r} mapped field or attribute."
        )
        raise ConfigurationError(format_configuration_message(msg))
