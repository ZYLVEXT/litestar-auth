"""Database-backed authentication strategy models."""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from datetime import datetime  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import TYPE_CHECKING

from advanced_alchemy.base import DefaultBase
from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    # Type-only import; forms a static cycle with litestar_auth.models
    # but is intentionally confined to TYPE_CHECKING.
    from litestar_auth.models import User


class AccessToken(DefaultBase):
    """Persistent access token linked to a user."""

    __tablename__ = "access_token"

    token: Mapped[str] = mapped_column(String(length=255), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    user: Mapped[User] = relationship(back_populates="access_tokens")


class RefreshToken(DefaultBase):
    """Persistent refresh token linked to a user."""

    __tablename__ = "refresh_token"

    token: Mapped[str] = mapped_column(String(length=255), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    user: Mapped[User] = relationship(back_populates="refresh_tokens")


def import_token_orm_models() -> tuple[type[AccessToken], type[RefreshToken]]:
    """Return the token ORM models to make mapper registration explicit for consumers."""
    return AccessToken, RefreshToken
