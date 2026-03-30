"""OAuth account ORM model (import without loading :class:`~litestar_auth.models.user.User`).

Import :class:`OAuthAccount` from this submodule when you reuse the library OAuth table
contract with a **custom** user model mapped to ``user`` — loading
``litestar_auth.models.user`` would register the reference :class:`~litestar_auth.models.user.User`
mapper and can conflict with your app model on the same table.
"""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import TYPE_CHECKING

from advanced_alchemy.base import UUIDBase
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_auth.models._oauth_encrypted_types import oauth_access_token_type, oauth_refresh_token_type

if TYPE_CHECKING:
    from litestar_auth.models.user import User


class OAuthAccount(UUIDBase):
    """OAuth account linked to a local user.

    Provider identity (oauth_name, account_id) is globally unique: one provider
    identity can only be linked to one local user. Enforced at the persistence
    layer via UniqueConstraint and upsert logic.

    The ``user`` relationship targets the declarative class named ``User`` in the
    same registry (the bundled :class:`~litestar_auth.models.user.User` or your
    replacement). Configure ``foreign_keys`` / ``overlaps`` on subclasses if you
    remap relationships (see the custom user + OAuth cookbook).
    """

    __tablename__ = "oauth_account"
    __table_args__ = (UniqueConstraint("oauth_name", "account_id", name="uq_oauth_account_provider_identity"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    oauth_name: Mapped[str] = mapped_column(String(length=100))
    account_id: Mapped[str] = mapped_column(String(length=255))
    account_email: Mapped[str] = mapped_column(String(length=320))
    access_token: Mapped[str] = mapped_column(oauth_access_token_type)
    """OAuth provider access token. Fernet-encrypted at rest when configured."""
    expires_at: Mapped[int | None] = mapped_column(default=None, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(
        oauth_refresh_token_type,
        default=None,
        nullable=True,
    )
    """OAuth provider refresh token. Fernet-encrypted at rest when configured."""
    user: Mapped[User] = relationship(
        "User",
        back_populates="oauth_accounts",
        foreign_keys="OAuthAccount.user_id",
    )
