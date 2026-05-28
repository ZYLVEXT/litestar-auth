"""Side-effect-free SQLAlchemy mixins for auth model composition."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from litestar_auth._auth_model_mixins import (
    AccessTokenMixin,
    ApiKeyMixin,
    RefreshTokenMixin,
    RoleMixin,
    UserAuthRelationshipMixin,
    UserModelMixin,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
    _UserOwnedMixin,
)
from litestar_auth.models._oauth_encrypted_types import oauth_access_token_type, oauth_refresh_token_type
from litestar_auth.oauth_encryption import register_oauth_model_encryption_events

__all__ = (
    "AccessTokenMixin",
    "ApiKeyMixin",
    "OAuthAccountMixin",
    "RefreshTokenMixin",
    "RoleMixin",
    "UserAuthRelationshipMixin",
    "UserModelMixin",
    "UserRoleAssociationMixin",
    "UserRoleRelationshipMixin",
)

_OAUTH_EVENTS_REGISTERED_ATTR = "_litestar_auth_oauth_events_registered"


class OAuthAccountMixin(_UserOwnedMixin):
    """Shared columns and relationship wiring for OAuth account models."""

    if TYPE_CHECKING:
        __tablename__: ClassVar[str]

    auth_user_back_populates: ClassVar[str] = "oauth_accounts"
    auth_user_relationship_foreign_keys: ClassVar[bool] = True
    auth_provider_identity_constraint_name: ClassVar[str | None] = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Register OAuth token encryption hooks when an OAuth model family is declared."""
        super().__init_subclass__(**kwargs)
        if _inherits_registered_oauth_hooks(cls):
            return
        register_oauth_model_encryption_events(cls)
        setattr(cls, _OAUTH_EVENTS_REGISTERED_ATTR, True)

    @declared_attr.directive
    @classmethod
    def __table_args__(cls) -> tuple[UniqueConstraint]:  # noqa: PLW3201
        """Create the provider-identity uniqueness constraint for each subclass.

        Returns:
            The unique constraint tuple for ``(oauth_name, account_id)``.
        """
        constraint_name = cls.auth_provider_identity_constraint_name
        if constraint_name is None:
            constraint_name = f"uq_{cls.__tablename__}_provider_identity"
        return (UniqueConstraint("oauth_name", "account_id", name=constraint_name),)

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


def _inherits_registered_oauth_hooks(model_class: type[OAuthAccountMixin]) -> bool:
    """Return whether a parent class already owns propagated OAuth encryption hooks."""
    return any(
        bool(base_class.__dict__.get(_OAUTH_EVENTS_REGISTERED_ATTR, False)) for base_class in model_class.__mro__[1:]
    )
