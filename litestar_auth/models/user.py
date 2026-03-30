"""Reference :class:`User` ORM model (loads token relationships and OAuth inverse side)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from advanced_alchemy.base import UUIDBase
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_auth.models.oauth import OAuthAccount

if TYPE_CHECKING:
    # Type-only import; forms a static cycle with authentication.strategy.db_models
    from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken


class User(UUIDBase):
    """Base user model for authentication and authorization flows."""

    __tablename__ = "user"

    email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(length=255))
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(length=255), default=None, nullable=True)
    access_tokens: Mapped[list[AccessToken]] = relationship(back_populates="user")
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(back_populates="user")
    oauth_accounts: Mapped[list[OAuthAccount]] = relationship(back_populates="user")
