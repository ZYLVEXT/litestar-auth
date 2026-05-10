"""SQLAlchemy mixin for API-key credential rows."""

from __future__ import annotations

import re
from datetime import datetime  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import Any, ClassVar
from uuid import UUID  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.

from sqlalchemy import JSON, DateTime, ForeignKey, LargeBinary, String, func
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship, validates

_API_KEY_ID_LENGTH = 64
_API_KEY_PREFIX_ENV_LENGTH = 32
_API_KEY_NAME_LENGTH = 255
_API_KEY_CREATED_VIA_LENGTH = 64
_CLIENT_METADATA_KEY_MAX_LENGTH = 64
_CLIENT_METADATA_VALUE_MAX_LENGTH = 255
_CLIENT_METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


class ApiKeyMixin:
    """Shared mapped attributes for API-key credential rows."""

    auth_user_model: ClassVar[str] = "User"
    auth_user_table: ClassVar[str] = "user"
    auth_user_back_populates: ClassVar[str] = "api_keys"
    user_id: Mapped[UUID]
    user: Mapped[Any]

    key_id: Mapped[str] = mapped_column(
        String(length=_API_KEY_ID_LENGTH),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_secret: Mapped[bytes] = mapped_column(LargeBinary(length=64), nullable=False)
    encrypted_secret: Mapped[bytes | None] = mapped_column(LargeBinary(length=4096), default=None, nullable=True)
    name: Mapped[str] = mapped_column(String(length=_API_KEY_NAME_LENGTH), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    prefix_env: Mapped[str] = mapped_column(String(length=_API_KEY_PREFIX_ENV_LENGTH), nullable=False)
    signing_required: Mapped[bool] = mapped_column(default=False, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, nullable=True)
    created_via: Mapped[str] = mapped_column(String(length=_API_KEY_CREATED_VIA_LENGTH), nullable=False)
    client_metadata: Mapped[dict[str, str] | None] = mapped_column(JSON, default=None, nullable=True)

    @declared_attr
    @classmethod
    def user_id(cls) -> Mapped[UUID]:
        """Map the foreign key to the configured user table.

        Returns:
            The mapped ``user_id`` foreign-key column.
        """
        return mapped_column(ForeignKey(f"{cls.auth_user_table}.id"), index=True, nullable=False)

    @declared_attr
    @classmethod
    def user(cls) -> Mapped[Any]:
        """Map the relationship back to the configured user model.

        Returns:
            The relationship descriptor for the configured user model.
        """
        return relationship(cls.auth_user_model, back_populates=cls.auth_user_back_populates)

    @validates("client_metadata")
    def _validate_client_metadata(  # noqa: PLR6301
        self,
        key: str,
        value: dict[str, str] | None,
    ) -> dict[str, str] | None:
        """Validate bounded API-key client metadata before persistence.

        Returns:
            The validated metadata mapping.

        Raises:
            ValueError: If metadata keys or values exceed the public session metadata bounds.
        """
        del key
        if value is None:
            return None
        invalid_keys = [
            metadata_key
            for metadata_key in value
            if (
                not metadata_key
                or len(metadata_key) > _CLIENT_METADATA_KEY_MAX_LENGTH
                or _CLIENT_METADATA_KEY_PATTERN.fullmatch(metadata_key) is None
            )
        ]
        invalid_values = [
            metadata_value
            for metadata_value in value.values()
            if not metadata_value or len(metadata_value) > _CLIENT_METADATA_VALUE_MAX_LENGTH
        ]
        if invalid_keys or invalid_values:
            msg = "API-key client_metadata keys must be 1-64 chars and values must be 1-255 chars."
            raise ValueError(msg)
        return value
