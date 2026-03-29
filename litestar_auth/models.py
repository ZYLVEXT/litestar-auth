"""Database models for litestar-auth."""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from collections.abc import Callable  # noqa: TC003
from typing import TYPE_CHECKING, cast

from advanced_alchemy.base import UUIDBase
from advanced_alchemy.types import EncryptedString
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_auth.oauth_encryption import (
    _RawFernetBackend,
    get_oauth_encryption_key_callable,
)

_oauth_encryption_key = get_oauth_encryption_key_callable()

if TYPE_CHECKING:
    # Type-only import; forms a static cycle with authentication.strategy.db_models
    # but has no runtime import side effects.
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


class OAuthAccount(UUIDBase):
    """OAuth account linked to a local user.

    Provider identity (oauth_name, account_id) is globally unique: one provider
    identity can only be linked to one local user. Enforced at the persistence
    layer via UniqueConstraint and upsert logic.
    """

    __tablename__ = "oauth_account"
    __table_args__ = (UniqueConstraint("oauth_name", "account_id", name="uq_oauth_account_provider_identity"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    oauth_name: Mapped[str] = mapped_column(String(length=100))
    account_id: Mapped[str] = mapped_column(String(length=255))
    account_email: Mapped[str] = mapped_column(String(length=320))
    access_token: Mapped[str] = mapped_column(
        EncryptedString(
            key=cast("Callable[[], str | bytes]", _oauth_encryption_key),
            backend=_RawFernetBackend,
            length=2048,
        ),
    )
    """OAuth provider access token. Fernet-encrypted at rest when configured."""
    expires_at: Mapped[int | None] = mapped_column(default=None, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(
        EncryptedString(
            key=cast("Callable[[], str | bytes]", _oauth_encryption_key),
            backend=_RawFernetBackend,
            length=2048,
        ),
        default=None,
        nullable=True,
    )
    """OAuth provider refresh token. Fernet-encrypted at rest when configured."""
    user: Mapped[User] = relationship(back_populates="oauth_accounts")
