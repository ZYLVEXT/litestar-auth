"""Internal SQLAlchemy mixins shared by the auth ORM models."""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from datetime import datetime  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import Any, ClassVar

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship

__all__ = (
    "AccessTokenMixin",
    "RefreshTokenMixin",
    "UserAuthRelationshipMixin",
    "UserModelMixin",
    "_TokenModelMixin",
)

_USER_RELATIONSHIP_NAME = "user"


class UserModelMixin:
    """Shared non-primary-key columns used by the bundled ``User`` model."""

    email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(length=255))
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(length=255), default=None, nullable=True)


class UserAuthRelationshipMixin:
    """Declare the inverse relationships expected by the auth ORM model families.

    Override the ``auth_*_model`` class variables when a custom user model needs
    to point at custom token or OAuth classes instead of the bundled defaults.
    Set a hook to ``None`` when the custom user only composes part of the auth
    model family and should omit that inverse relationship entirely.
    """

    auth_access_token_model: ClassVar[str | None] = "AccessToken"  # noqa: S105
    auth_refresh_token_model: ClassVar[str | None] = "RefreshToken"  # noqa: S105
    auth_oauth_account_model: ClassVar[str | None] = "OAuthAccount"

    @declared_attr
    def access_tokens(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured access-token model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when access-token integration is disabled.
        """
        if cls.auth_access_token_model is None:
            return None

        return relationship(cls.auth_access_token_model, back_populates=_USER_RELATIONSHIP_NAME)

    @declared_attr
    def refresh_tokens(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured refresh-token model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when refresh-token integration is disabled.
        """
        if cls.auth_refresh_token_model is None:
            return None

        return relationship(cls.auth_refresh_token_model, back_populates=_USER_RELATIONSHIP_NAME)

    @declared_attr
    def oauth_accounts(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured OAuth-account model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when OAuth-account integration is disabled.
        """
        if cls.auth_oauth_account_model is None:
            return None

        return relationship(cls.auth_oauth_account_model, back_populates=_USER_RELATIONSHIP_NAME)


class _TokenModelMixin:
    """Shared mapped attributes for token models that belong to a user."""

    auth_user_model: ClassVar[str] = "User"
    auth_user_table: ClassVar[str] = "user"
    auth_user_back_populates: ClassVar[str]
    user_id: Mapped[uuid.UUID]
    user: Mapped[Any]

    token: Mapped[str] = mapped_column(String(length=255), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        """Map the foreign key to the configured user table.

        Returns:
            The mapped ``user_id`` foreign-key column.
        """
        return mapped_column(ForeignKey(f"{cls.auth_user_table}.id"), nullable=False)

    @declared_attr
    def user(cls) -> Mapped[Any]:  # noqa: N805
        """Map the relationship back to the configured user model.

        Returns:
            The relationship descriptor for the configured user model.
        """
        return relationship(cls.auth_user_model, back_populates=cls.auth_user_back_populates)


class AccessTokenMixin(_TokenModelMixin):
    """Shared mapped attributes for access-token models."""

    auth_user_back_populates: ClassVar[str] = "access_tokens"


class RefreshTokenMixin(_TokenModelMixin):
    """Shared mapped attributes for refresh-token models."""

    auth_user_back_populates: ClassVar[str] = "refresh_tokens"
