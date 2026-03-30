"""Example: OAuth account model with audit columns (local copy; pick one mapped class per table).

``UUIDBase`` and ``UUIDAuditBase`` in Advanced Alchemy share metadata; you cannot
register two concrete subclasses with the same ``__tablename__`` in one process.
If your database already has ``created_at`` / ``updated_at`` on ``oauth_account``,
subclass ``UUIDAuditBase`` and mirror the library column set (including encrypted
token fields via ``litestar_auth.models._oauth_encrypted_types``) instead of
importing both the bundled ``OAuthAccount`` and an audit variant.
"""

from __future__ import annotations

import uuid

from advanced_alchemy.base import UUIDAuditBase
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from litestar_auth.models._oauth_encrypted_types import oauth_access_token_type, oauth_refresh_token_type


class OAuthAccountWithAudit(UUIDAuditBase):
    """Example only — adapt names and ``User`` side to your app."""

    __tablename__ = "oauth_account"
    __table_args__ = (UniqueConstraint("oauth_name", "account_id", name="uq_oauth_account_provider_identity"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    oauth_name: Mapped[str] = mapped_column(String(length=100))
    account_id: Mapped[str] = mapped_column(String(length=255))
    account_email: Mapped[str] = mapped_column(String(length=320))
    access_token: Mapped[str] = mapped_column(oauth_access_token_type)
    expires_at: Mapped[int | None] = mapped_column(default=None, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(
        oauth_refresh_token_type,
        default=None,
        nullable=True,
    )
    user: Mapped[object] = relationship(
        "User",
        back_populates="oauth_accounts",
        foreign_keys="OAuthAccountWithAudit.user_id",
    )
