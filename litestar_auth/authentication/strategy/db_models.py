"""Database-backed authentication strategy models and model contracts.

The concrete token ORM classes still live here because ``DatabaseTokenStrategy`` persists them, but
the public bootstrap helper lives at
``litestar_auth.models.import_token_orm_models()`` so explicit mapper registration stays with the
models boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from inspect import getattr_static
from typing import Any

from advanced_alchemy.base import DefaultBase

from litestar_auth._auth_model_mixins import AccessTokenMixin, RefreshTokenMixin
from litestar_auth.exceptions import ConfigurationError

_MISSING = object()
_REQUIRED_TOKEN_MODEL_ATTRIBUTES = ("token", "created_at", "user_id", "user")


def _validate_token_model_contract(model: type[Any], *, field_name: str) -> None:
    """Validate that a token model exposes the minimum strategy contract.

    Args:
        model: Access-token or refresh-token ORM class supplied to the public contract.
        field_name: Dataclass field name used in error messages.

    Raises:
        ConfigurationError: If the supplied model does not expose the required attributes.
    """
    missing_attributes = [
        attribute_name
        for attribute_name in _REQUIRED_TOKEN_MODEL_ATTRIBUTES
        if getattr_static(model, attribute_name, _MISSING) is _MISSING
    ]
    if not missing_attributes:
        return

    missing_display = ", ".join(missing_attributes)
    required_display = ", ".join(_REQUIRED_TOKEN_MODEL_ATTRIBUTES)
    msg = (
        f"DatabaseTokenModels.{field_name} must define mapped attributes {required_display}; "
        f"missing: {missing_display}."
    )
    raise ConfigurationError(msg)


class AccessToken(AccessTokenMixin, DefaultBase):
    """Persistent access token linked to a user via the shared auth relationship contract."""

    __tablename__ = "access_token"


class RefreshToken(RefreshTokenMixin, DefaultBase):
    """Persistent refresh token linked to a user via the shared auth relationship contract."""

    __tablename__ = "refresh_token"


@dataclass(frozen=True, slots=True)
class DatabaseTokenModels:
    """Explicit access-token and refresh-token ORM contract for ``DatabaseTokenStrategy``.

    The supplied models must expose mapped ``token``, ``created_at``, ``user_id``, and ``user``
    attributes compatible with the persistence operations performed by the DB token strategy.
    Defaults preserve the bundled ``AccessToken`` / ``RefreshToken`` behavior.
    """

    access_token_model: type[Any] = AccessToken
    refresh_token_model: type[Any] = RefreshToken

    def __post_init__(self) -> None:
        """Validate the supplied token-model classes eagerly."""
        _validate_token_model_contract(self.access_token_model, field_name="access_token_model")
        _validate_token_model_contract(self.refresh_token_model, field_name="refresh_token_model")


def import_token_orm_models() -> tuple[type[AccessToken], type[RefreshToken]]:
    """Return the bundled token ORM models for low-level module imports.

    Prefer ``litestar_auth.models.import_token_orm_models()`` for public explicit mapper
    registration and application code.
    """
    return AccessToken, RefreshToken
