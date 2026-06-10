"""Database-backed authentication strategy models and model contracts.

The concrete token ORM classes still live here because ``DatabaseTokenStrategy`` persists them, but
the public bootstrap helper lives at
``litestar_auth.models.import_token_orm_models()`` so explicit mapper registration stays with the
models boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 - SQLAlchemy resolves Mapped annotations during mapper setup.
from inspect import getattr_static
from typing import Any

from advanced_alchemy.base import DefaultBase
from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from litestar_auth._auth_model_mixins import AccessTokenMixin, RefreshTokenMixin
from litestar_auth.exceptions import ConfigurationError

_MISSING = object()
_REQUIRED_ACCESS_TOKEN_MODEL_ATTRIBUTES = ("token", "created_at", "user_id", "user")
_REQUIRED_REFRESH_TOKEN_MODEL_ATTRIBUTES = (
    "token",
    "created_at",
    "user_id",
    "user",
    "session_id",
    "last_used_at",
    "client_metadata",
)
_REQUIRED_CONSUMED_DIGEST_MODEL_ATTRIBUTES = ("token_digest", "session_id", "consumed_at")


def _validate_token_model_contract(
    model: type[Any],
    *,
    field_name: str,
    required_attributes: tuple[str, ...],
) -> None:
    """Validate that a token model exposes the minimum strategy contract.

    Args:
        model: Access-token or refresh-token ORM class supplied to the public contract.
        field_name: Dataclass field name used in error messages.
        required_attributes: Mapped attributes the model must expose.

    Raises:
        ConfigurationError: If the supplied model does not expose the required attributes.
    """
    missing_attributes = [
        attribute_name
        for attribute_name in required_attributes
        if getattr_static(model, attribute_name, _MISSING) is _MISSING
    ]
    if not missing_attributes:
        return

    missing_display = ", ".join(missing_attributes)
    required_display = ", ".join(required_attributes)
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


class RefreshTokenConsumedDigest(DefaultBase):
    """Indexed replay-detection entry for a consumed refresh-token digest."""

    __tablename__ = "refresh_token_consumed_digest"

    token_digest: Mapped[str] = mapped_column(String(length=255), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(length=36), index=True, nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


@dataclass(frozen=True, slots=True)
class DatabaseTokenModels:
    """Explicit token ORM contract for ``DatabaseTokenStrategy``.

    The supplied access-token model must expose mapped ``token``, ``created_at``, ``user_id``, and ``user``
    attributes compatible with the persistence operations performed by the DB token strategy. The supplied
    refresh-token model must also expose ``session_id``, ``last_used_at``, and ``client_metadata`` so
    DB-backed refresh sessions have a non-sensitive public session identifier and bounded client metadata.
    The consumed refresh-token digest model must expose mapped ``token_digest``, ``session_id``, and
    ``consumed_at`` attributes for replay detection. Defaults preserve the bundled token-table behavior.
    """

    access_token_model: type[Any] = AccessToken
    refresh_token_model: type[Any] = RefreshToken
    consumed_refresh_token_digest_model: type[Any] = RefreshTokenConsumedDigest

    def __post_init__(self) -> None:
        """Validate the supplied token-model classes eagerly."""
        _validate_token_model_contract(
            self.access_token_model,
            field_name="access_token_model",
            required_attributes=_REQUIRED_ACCESS_TOKEN_MODEL_ATTRIBUTES,
        )
        _validate_token_model_contract(
            self.refresh_token_model,
            field_name="refresh_token_model",
            required_attributes=_REQUIRED_REFRESH_TOKEN_MODEL_ATTRIBUTES,
        )
        _validate_token_model_contract(
            self.consumed_refresh_token_digest_model,
            field_name="consumed_refresh_token_digest_model",
            required_attributes=_REQUIRED_CONSUMED_DIGEST_MODEL_ATTRIBUTES,
        )


def import_token_orm_models() -> tuple[type[AccessToken], type[RefreshToken], type[RefreshTokenConsumedDigest]]:
    """Return all bundled token ORM models for low-level module imports.

    Prefer ``litestar_auth.models.import_token_orm_models()`` for public explicit mapper
    registration and application code.
    """
    return AccessToken, RefreshToken, RefreshTokenConsumedDigest
