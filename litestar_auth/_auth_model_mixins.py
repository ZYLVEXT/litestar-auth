"""Internal SQLAlchemy mixins shared by the auth ORM models."""

from __future__ import annotations

import uuid  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from datetime import datetime  # noqa: TC003 - SQLAlchemy resolves mapped annotations at runtime.
from typing import TYPE_CHECKING, Any, ClassVar, cast

from sqlalchemy import JSON, DateTime, ForeignKey, String, event, func, insert, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship, validates
from sqlalchemy.orm import Session as ORMSession

from litestar_auth._roles import normalize_role_name, normalize_roles

__all__ = (
    "AccessTokenMixin",
    "RefreshTokenMixin",
    "RoleMixin",
    "UserAuthRelationshipMixin",
    "UserModelMixin",
    "UserRoleAssociationMixin",
    "UserRoleRelationshipMixin",
    "_TokenModelMixin",
)

_USER_RELATIONSHIP_NAME = "user"
_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME = "role_assignments"
_ROLE_NAME_LENGTH = 255


class UserModelMixin:
    """Shared non-primary-key columns used by the bundled ``User`` model.

    Provides ``email``, ``hashed_password``, ``is_active``, ``is_verified``,
    ``totp_secret``, and hashed TOTP recovery codes. Superuser status is
    determined by role membership, not by a persisted column on this mixin.

    Set ``auth_hashed_password_column_name`` on a subclass when the app keeps
    the public ``hashed_password`` attribute but stores it under a different
    SQL column name such as ``password_hash``.
    """

    if TYPE_CHECKING:
        auth_hashed_password_column_name: ClassVar[str]

    auth_hashed_password_column_name = "hashed_password"

    email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True)
    hashed_password: Mapped[str]
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(length=255), default=None, nullable=True)
    # JSON keeps custom user-model composition simple; verification still walks every hash.
    recovery_codes_hashes: Mapped[list[str] | None] = mapped_column(JSON, default=None, nullable=True)

    @declared_attr
    def hashed_password(cls) -> Mapped[str]:  # noqa: N805
        """Map the password-hash attribute to the configured SQL column name.

        Returns:
            The mapped ``hashed_password`` column.
        """
        column_name = cls.auth_hashed_password_column_name
        if column_name == "hashed_password":
            return mapped_column(String(length=255))
        return mapped_column(column_name, String(length=255))


class UserRoleRelationshipMixin:
    """Expose normalized flat roles through relational assignment rows.

    The returned ``roles`` value is a normalized snapshot. Persist changes by
    assigning a new iterable to ``user.roles`` instead of mutating the returned
    list in place.
    """

    auth_user_role_model: ClassVar[str] = "UserRole"
    auth_user_role_relationship_lazy: ClassVar[str] = "selectin"

    if TYPE_CHECKING:
        role_assignments: Mapped[list[Any]]

    @declared_attr
    def role_assignments(cls) -> Mapped[list[Any]]:  # noqa: N805
        """Map the user-side role-assignment collection.

        Returns:
            The relationship descriptor for role-assignment rows.
        """
        relationship_kwargs: dict[str, Any] = {
            "back_populates": _USER_RELATIONSHIP_NAME,
            "cascade": "all, delete-orphan",
        }
        if cls.auth_user_role_relationship_lazy:
            relationship_kwargs["lazy"] = cls.auth_user_role_relationship_lazy
        return relationship(cls.auth_user_role_model, **relationship_kwargs)

    def _role_assignment_model(self) -> type[Any]:
        """Return the mapped role-assignment class for this user instance."""
        return cast("type[Any]", inspect(type(self)).relationships[_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME].mapper.class_)

    def _set_normalized_roles(self, role_names: list[str]) -> None:
        """Replace the role-assignment collection with normalized names."""
        assignment_model = self._role_assignment_model()
        self.role_assignments = [assignment_model(role_name=role_name) for role_name in role_names]

    @property
    def roles(self) -> list[str]:
        """Return normalized flat role membership for the current user."""
        return normalize_roles([assignment.role_name for assignment in self.role_assignments])

    @roles.setter
    def roles(self, value: object) -> None:
        """Persist normalized role membership through assignment rows."""
        self._set_normalized_roles(normalize_roles(value))


class RoleMixin:
    """Shared columns and inverse relationship for relational roles."""

    auth_user_role_model: ClassVar[str] = "UserRole"
    auth_user_role_relationship_lazy: ClassVar[str | None] = None

    name: Mapped[str] = mapped_column(String(length=_ROLE_NAME_LENGTH), primary_key=True)

    @validates("name")
    def _normalize_name(self, key: str, value: str) -> str:  # noqa: PLR6301
        """Normalize role names before persisting them.

        Returns:
            The normalized role name.
        """
        del key
        return normalize_role_name(value)

    @declared_attr
    def user_assignments(cls) -> Mapped[list[Any]]:  # noqa: N805
        """Map the inverse collection of user-role association rows.

        Returns:
            The relationship descriptor for user-role association rows.
        """
        relationship_kwargs: dict[str, Any] = {
            "back_populates": "role",
            "cascade": "all, delete-orphan",
        }
        if cls.auth_user_role_relationship_lazy is not None:
            relationship_kwargs["lazy"] = cls.auth_user_role_relationship_lazy
        return relationship(cls.auth_user_role_model, **relationship_kwargs)


class UserRoleAssociationMixin:
    """Map one normalized role assignment for one user."""

    auth_user_model: ClassVar[str] = "User"
    auth_user_table: ClassVar[str] = "user"
    auth_user_back_populates: ClassVar[str] = _ROLE_ASSIGNMENTS_RELATIONSHIP_NAME
    auth_role_model: ClassVar[str] = "Role"
    auth_role_table: ClassVar[str] = "role"
    auth_role_back_populates: ClassVar[str] = "user_assignments"

    if TYPE_CHECKING:
        user_id: Mapped[uuid.UUID]
        role_name: Mapped[str]
        user: Mapped[Any]
        role: Mapped[Any]

    @declared_attr
    def user_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        """Map the user foreign key for the association row.

        Returns:
            The mapped user foreign-key column.
        """
        return mapped_column(ForeignKey(f"{cls.auth_user_table}.id"), primary_key=True)

    @declared_attr
    def role_name(cls) -> Mapped[str]:  # noqa: N805
        """Map the normalized role-name foreign key for the association row.

        Returns:
            The mapped role-name foreign-key column.
        """
        return mapped_column(
            String(length=_ROLE_NAME_LENGTH),
            ForeignKey(f"{cls.auth_role_table}.name"),
            primary_key=True,
        )

    @validates("role_name")
    def _normalize_role_name(self, key: str, value: str) -> str:  # noqa: PLR6301
        """Normalize role names before persisting the association row.

        Returns:
            The normalized role name.
        """
        del key
        return normalize_role_name(value)

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

    @declared_attr
    def role(cls) -> Mapped[Any]:  # noqa: N805
        """Map the relationship back to the configured role model.

        Returns:
            The relationship descriptor for the configured role model.
        """
        return relationship(
            cls.auth_role_model,
            back_populates=cls.auth_role_back_populates,
            foreign_keys=lambda: [cast("Mapped[Any]", cls.role_name)],
        )


@event.listens_for(ORMSession, "before_flush")
def _materialize_missing_role_rows(
    session: ORMSession,
    flush_context: object,
    instances: object,
) -> None:
    """Create missing role catalog rows before association rows are flushed."""
    del flush_context, instances

    role_names_by_model: dict[type[Any], set[str]] = {}
    for candidate in [*session.new, *session.dirty]:
        if not isinstance(candidate, UserRoleAssociationMixin):
            continue
        role_model = cast("type[Any]", inspect(type(candidate)).relationships["role"].mapper.class_)
        role_names_by_model.setdefault(role_model, set()).add(candidate.role_name)

    if not role_names_by_model:
        return

    for role_model, requested_role_names in role_names_by_model.items():
        pending_role_names = {
            cast("str", pending_role.name) for pending_role in session.new if isinstance(pending_role, role_model)
        }
        unresolved_role_names = requested_role_names - pending_role_names
        if not unresolved_role_names:
            continue

        role_name_column = role_model.name
        existing_role_names = set(
            session.scalars(
                select(role_name_column).where(role_name_column.in_(sorted(unresolved_role_names))),
            ),
        )
        for role_name in sorted(unresolved_role_names - existing_role_names):
            _insert_missing_role_row(
                session,
                role_model=role_model,
                role_name_column=role_name_column,
                role_name=role_name,
            )


def _insert_missing_role_row(
    session: ORMSession,
    *,
    role_model: type[Any],
    role_name_column: object,
    role_name: str,
) -> None:
    """Insert one missing role row, tolerating duplicate-key races from concurrent sessions.

    When another transaction creates the same role name first, the savepoint-scoped insert
    raises ``IntegrityError`` after the winning transaction commits. In that case the role row
    now exists and the association-row flush can continue safely.

    Raises:
        IntegrityError: When the insert fails for any reason other than a concurrent duplicate
            creation of the same normalized role name.
    """
    connection = session.connection()
    try:
        with connection.begin_nested():
            connection.execute(insert(role_model).values(name=role_name))
    except IntegrityError:
        role_name_expr = cast("Any", role_name_column)
        existing_role_name = session.scalar(select(role_name_expr).where(role_name_expr == role_name))
        if existing_role_name != role_name:
            raise


class UserAuthRelationshipMixin:
    """Declare the inverse relationships expected by the auth ORM model families.

    Override the ``auth_*_model`` class variables when a custom user model needs
    to point at custom token or OAuth classes instead of the bundled defaults.
    Configure the supported relationship-option hooks when a custom user model
    needs non-default loader strategies or an explicit OAuth ``foreign_keys``
    setting without redefining the ``declared_attr`` methods. Set a model hook
    to ``None`` when the custom user only composes part of the auth model family
    and should omit that inverse relationship entirely.
    """

    auth_access_token_model: ClassVar[str | None] = "AccessToken"
    auth_refresh_token_model: ClassVar[str | None] = "RefreshToken"
    auth_oauth_account_model: ClassVar[str | None] = "OAuthAccount"
    auth_token_relationship_lazy: ClassVar[str | None] = None
    auth_oauth_account_relationship_lazy: ClassVar[str | None] = None
    auth_oauth_account_relationship_foreign_keys: ClassVar[str | None] = None

    @staticmethod
    def _relationship(
        target: str | None,
        *,
        lazy: str | None = None,
        foreign_keys: str | None = None,
    ) -> object | None:
        """Build a configured user-side relationship when the target is enabled.

        Returns:
            The relationship descriptor, or ``None`` when the target is disabled.
        """
        if target is None:
            return None

        relationship_kwargs: dict[str, Any] = {"back_populates": _USER_RELATIONSHIP_NAME}
        if lazy is not None:
            relationship_kwargs["lazy"] = lazy
        if foreign_keys is not None:
            relationship_kwargs["foreign_keys"] = foreign_keys
        return relationship(target, **relationship_kwargs)

    @declared_attr
    def access_tokens(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured access-token model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when access-token integration is disabled.
        """
        return cls._relationship(
            cls.auth_access_token_model,
            lazy=cls.auth_token_relationship_lazy,
        )

    @declared_attr
    def refresh_tokens(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured refresh-token model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when refresh-token integration is disabled.
        """
        return cls._relationship(
            cls.auth_refresh_token_model,
            lazy=cls.auth_token_relationship_lazy,
        )

    @declared_attr
    def oauth_accounts(cls):  # noqa: ANN202, N805
        """Map the inverse side of the configured OAuth-account model when enabled.

        Returns:
            The relationship descriptor, or ``None`` when OAuth-account integration is disabled.
        """
        return cls._relationship(
            cls.auth_oauth_account_model,
            lazy=cls.auth_oauth_account_relationship_lazy,
            foreign_keys=cls.auth_oauth_account_relationship_foreign_keys,
        )


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
