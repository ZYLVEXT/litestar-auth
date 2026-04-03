"""Side-effect-free SQLAlchemy mixins for auth model composition."""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import TYPE_CHECKING, Any, ClassVar, cast

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship

from litestar_auth._auth_model_mixins import (
    AccessTokenMixin,
    RefreshTokenMixin,
    UserAuthRelationshipMixin,
    UserModelMixin,
    _TokenModelMixin,  # noqa: F401
)
from litestar_auth.models._oauth_encrypted_types import oauth_access_token_type, oauth_refresh_token_type

__all__ = (
    "AccessTokenMixin",
    "OAuthAccountMixin",
    "RefreshTokenMixin",
    "UserAuthRelationshipMixin",
    "UserModelMixin",
)


class OAuthAccountMixin:
    """Shared columns and relationship wiring for OAuth account models."""

    if TYPE_CHECKING:
        __tablename__: ClassVar[str]

    auth_user_model: ClassVar[str] = "User"
    auth_user_table: ClassVar[str] = "user"
    auth_user_back_populates: ClassVar[str] = "oauth_accounts"
    auth_provider_identity_constraint_name: ClassVar[str | None] = None
    user_id: Mapped[uuid.UUID]
    user: Mapped[Any]

    @declared_attr.directive
    def __table_args__(cls) -> tuple[UniqueConstraint]:  # noqa: N805, PLW3201
        """Create the provider-identity uniqueness constraint for each subclass.

        Returns:
            The unique constraint tuple for ``(oauth_name, account_id)``.
        """
        constraint_name = cls.auth_provider_identity_constraint_name
        if constraint_name is None:
            constraint_name = f"uq_{cls.__tablename__}_provider_identity"
        return (UniqueConstraint("oauth_name", "account_id", name=constraint_name),)

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        """Map the foreign key to the configured user table.

        Returns:
            The mapped ``user_id`` foreign-key column.
        """
        return mapped_column(ForeignKey(f"{cls.auth_user_table}.id"), nullable=False)

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

    @declared_attr
    def user(cls) -> Mapped[Any]:  # noqa: N805
        """Map the relationship back to the configured user model.

        Returns:
            The relationship descriptor for the configured user model.
        """
        return relationship(
            cls.auth_user_model,
            back_populates=cls.auth_user_back_populates,
            foreign_keys=lambda: [cast("Mapped[Any]", cls.user_id)],
        )
