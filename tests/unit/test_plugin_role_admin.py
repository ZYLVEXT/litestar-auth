"""Unit tests for the internal SQLAlchemy-backed role-admin helper."""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, Self, cast
from uuid import UUID

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy import ForeignKey, String, select
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.orm import Session as SASession

import litestar_auth._plugin.role_admin as role_admin_module
from litestar_auth._plugin.role_admin import (
    SQLAlchemyRoleAdmin,
    _ManagerLifecycleRoleUpdater,
    _RoleLifecycleManager,
    resolve_role_model_family,
)
from litestar_auth._roles import normalize_roles
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.models import (
    Role,
    RoleMixin,
    User,
    UserModelMixin,
    UserRole,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
)
from litestar_auth.plugin import LitestarAuthConfig, OAuthConfig
from tests.integration.test_orchestrator import PluginUserManager

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

pytestmark = pytest.mark.unit


class TrackingAsyncSession:
    """Minimal AsyncSession-compatible stub for role-admin session tests."""

    def __init__(self) -> None:
        """Initialize entry/exit counters."""
        self.enter_count = 0
        self.exit_count = 0
        self.commit_count = 0
        self.rollback_count = 0
        self.executed_statements: list[object] = []

    async def __aenter__(self) -> Self:
        """Enter the async session context.

        Returns:
            This session instance.
        """
        self.enter_count += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the async session context."""
        del exc_type, exc, traceback
        self.exit_count += 1

    def add(self, instance: object) -> None:
        """Match ``AsyncSession.add()`` for contract validation."""
        del instance

    async def execute(self, statement: object) -> None:
        """Match ``AsyncSession.execute()`` for contract validation."""
        self.executed_statements.append(statement)

    async def scalar(self, statement: object) -> None:
        """Match ``AsyncSession.scalar()`` for contract validation."""
        del statement

    async def scalars(self, statement: object) -> None:
        """Match ``AsyncSession.scalars()`` for contract validation."""
        del statement

    async def flush(self) -> None:
        """Match ``AsyncSession.flush()`` for contract validation."""

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Match ``AsyncSession.merge()`` for contract validation.

        Returns:
            One placeholder merged instance.
        """
        del instance, load
        return object()

    async def commit(self) -> None:
        """Match ``AsyncSession.commit()`` for contract validation."""
        self.commit_count += 1

    async def rollback(self) -> None:
        """Match ``AsyncSession.rollback()`` for contract validation."""
        self.rollback_count += 1

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: object | None = None,
        with_for_update: object | None = None,
    ) -> None:
        """Match ``AsyncSession.refresh()`` for contract validation."""
        del instance, attribute_names, with_for_update

    @property
    def no_autoflush(self) -> object:
        """Expose a sync context manager matching ``AsyncSession.no_autoflush``."""
        return nullcontext()


class TrackingSessionMaker:
    """Return one tracked AsyncSession-compatible object."""

    def __init__(self, session: TrackingAsyncSession | None = None) -> None:
        """Store the tracked session instance."""
        self.session = TrackingAsyncSession() if session is None else session
        self.call_count = 0

    def __call__(self) -> TrackingAsyncSession:
        """Return the tracked session instance."""
        self.call_count += 1
        return self.session


class MissingMethodsAsyncSession:
    """Async context manager missing AsyncSession methods for fail-closed coverage."""

    async def __aenter__(self) -> Self:
        """Enter the async context.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit the async context."""
        del exc_type, exc, traceback


class MissingMethodsSessionMaker:
    """Return an async context manager that is not AsyncSession-compatible."""

    def __call__(self) -> MissingMethodsAsyncSession:
        """Return the missing-methods session stub."""
        return MissingMethodsAsyncSession()


class NonContextSessionMaker:
    """Return a non-context-manager object for fail-closed coverage."""

    def __call__(self) -> object:
        """Return a plain object."""
        return object()


def _minimal_config(
    *,
    user_model: type[Any],
    session_maker: object | None,
    db_session_dependency_provided_externally: bool = False,
) -> LitestarAuthConfig[Any, UUID]:
    """Build the smallest plugin config needed by the internal role-admin helper.

    Returns:
        A plugin config suitable for the internal role-admin helper.
    """
    return LitestarAuthConfig[Any, UUID](
        user_model=cast("Any", user_model),
        user_manager_class=cast("Any", PluginUserManager),
        session_maker=cast("Any", session_maker),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verification-secret-123456789012",
            reset_password_token_secret="reset-password-secret-1234567890",
            id_parser=UUID,
        ),
        db_session_dependency_provided_externally=db_session_dependency_provided_externally,
    )


def _build_custom_role_models(
    *,
    user_role_relationship_lazy: str = "selectin",
) -> tuple[type[Any], type[Any], type[Any]]:
    """Create one custom SQLAlchemy role-capable model family.

    Returns:
        The custom user, role, and association models.
    """

    class CustomBase(DeclarativeBase):
        """Dedicated registry for custom role-admin tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class CustomUUIDBase(UUIDPrimaryKey, CustomBase):
        """UUID base for custom role-admin tests."""

        __abstract__ = True

    class CustomUser(UserModelMixin, UserRoleRelationshipMixin, CustomUUIDBase):
        """Custom user model using the shared relational role facade."""

        __tablename__ = "custom_role_admin_user"
        auth_user_role_model = "CustomUserRole"
        auth_user_role_relationship_lazy = user_role_relationship_lazy

    class CustomRole(RoleMixin, CustomBase):
        """Custom role model using the shared relational role facade."""

        __tablename__ = "custom_role_admin_role"
        auth_user_role_model = "CustomUserRole"

    class CustomUserRole(UserRoleAssociationMixin, CustomBase):
        """Custom user-role association model using the shared relational role facade."""

        __tablename__ = "custom_role_admin_user_role"
        auth_user_model = "CustomUser"
        auth_user_table = "custom_role_admin_user"
        auth_role_model = "CustomRole"
        auth_role_table = "custom_role_admin_role"

    return CustomUser, CustomRole, CustomUserRole


def _build_missing_roles_attribute_user_model() -> type[Any]:
    """Create one mapped user model missing the flat ``roles`` contract.

    Returns:
        The mapped user model without the documented ``roles`` attribute.
    """

    class MissingRolesBase(DeclarativeBase):
        """Dedicated registry for missing-roles-attribute tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class MissingRolesUUIDBase(UUIDPrimaryKey, MissingRolesBase):
        """UUID base for missing-roles-attribute tests."""

        __abstract__ = True

    class MissingRolesUser(UserModelMixin, MissingRolesUUIDBase):
        """Mapped user model missing the flat ``roles`` facade."""

        __tablename__ = "missing_roles_attribute_user"

    return MissingRolesUser


def _build_relationshipless_role_user_model() -> type[Any]:
    """Create one mapped user model that exposes ``roles`` without relational backing.

    Returns:
        The mapped user model missing ``role_assignments``.
    """

    class RelationshiplessBase(DeclarativeBase):
        """Dedicated registry for roleless-contract tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class RelationshiplessUUIDBase(UUIDPrimaryKey, RelationshiplessBase):
        """UUID base for roleless-contract tests."""

        __abstract__ = True

    class RelationshiplessUser(UserModelMixin, RelationshiplessUUIDBase):
        """Mapped user model missing ``role_assignments``."""

        __tablename__ = "relationshipless_role_user"

        @property
        def roles(self) -> list[str]:
            """Expose a flat facade without relational persistence."""
            return normalize_roles(getattr(self, "_roles", ()))

        @roles.setter
        def roles(self, value: object) -> None:
            """Store a normalized local snapshot only."""
            self._roles = normalize_roles(value)

    return RelationshiplessUser


def _build_missing_role_name_user_model() -> type[Any]:
    """Create one mapped role family missing ``user_role.role_name``.

    Returns:
        The mapped user model missing the documented association-column name.
    """

    class MissingRoleNameBase(DeclarativeBase):
        """Dedicated registry for missing-role-name tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class MissingRoleNameUUIDBase(UUIDPrimaryKey, MissingRoleNameBase):
        """UUID base for missing-role-name tests."""

        __abstract__ = True

    class MissingRoleNameUser(UserModelMixin, MissingRoleNameUUIDBase):
        """Mapped user model with relational roles missing the required FK name."""

        __tablename__ = "missing_role_name_user"

        role_assignments: Mapped[list[MissingRoleNameUserRole]] = relationship(
            back_populates="user",
            cascade="all, delete-orphan",
        )

        @property
        def roles(self) -> list[str]:
            """Expose normalized flat role membership."""
            return normalize_roles([assignment.role_key for assignment in self.role_assignments])

        @roles.setter
        def roles(self, value: object) -> None:
            """Persist one normalized snapshot for coverage only."""
            normalized_roles = normalize_roles(value)
            self.role_assignments = [MissingRoleNameUserRole(role_key=role_name) for role_name in normalized_roles]

    class MissingRoleNameRole(MissingRoleNameBase):
        """Role catalog row with the expected ``name`` column."""

        __tablename__ = "missing_role_name_role"

        name: Mapped[str] = mapped_column(String(length=255), primary_key=True)

    class MissingRoleNameUserRole(MissingRoleNameBase):
        """Association row missing the required ``role_name`` attribute."""

        __tablename__ = "missing_role_name_user_role"

        user_id: Mapped[UUID] = mapped_column(ForeignKey("missing_role_name_user.id"), primary_key=True)
        role_key: Mapped[str] = mapped_column(ForeignKey("missing_role_name_role.name"), primary_key=True)
        user: Mapped[MissingRoleNameUser] = relationship(back_populates="role_assignments")
        role: Mapped[MissingRoleNameRole] = relationship()

    return MissingRoleNameUser


def _build_missing_role_relationship_user_model() -> type[Any]:
    """Create one mapped role family missing ``user_role.role``.

    Returns:
        The mapped user model missing the documented association relationship.
    """

    class MissingRoleRelationshipBase(DeclarativeBase):
        """Dedicated registry for missing-role-relationship tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class MissingRoleRelationshipUUIDBase(UUIDPrimaryKey, MissingRoleRelationshipBase):
        """UUID base for missing-role-relationship tests."""

        __abstract__ = True

    class MissingRoleRelationshipUser(UserModelMixin, MissingRoleRelationshipUUIDBase):
        """Mapped user model with relational roles missing the role relationship."""

        __tablename__ = "missing_role_relationship_user"

        role_assignments: Mapped[list[MissingRoleRelationshipUserRole]] = relationship(
            back_populates="user",
            cascade="all, delete-orphan",
        )

        @property
        def roles(self) -> list[str]:
            """Expose normalized flat role membership."""
            return normalize_roles([assignment.role_name for assignment in self.role_assignments])

        @roles.setter
        def roles(self, value: object) -> None:
            """Persist one normalized snapshot for coverage only."""
            normalized_roles = normalize_roles(value)
            self.role_assignments = [
                MissingRoleRelationshipUserRole(role_name=role_name) for role_name in normalized_roles
            ]

    class MissingRoleRelationshipRole(MissingRoleRelationshipBase):
        """Role catalog row with the expected ``name`` column."""

        __tablename__ = "missing_role_relationship_role"

        name: Mapped[str] = mapped_column(String(length=255), primary_key=True)

    class MissingRoleRelationshipUserRole(MissingRoleRelationshipBase):
        """Association row missing the required ``role`` relationship."""

        __tablename__ = "missing_role_relationship_user_role"

        user_id: Mapped[UUID] = mapped_column(ForeignKey("missing_role_relationship_user.id"), primary_key=True)
        role_name: Mapped[str] = mapped_column(
            ForeignKey("missing_role_relationship_role.name"),
            primary_key=True,
        )
        user: Mapped[MissingRoleRelationshipUser] = relationship(back_populates="role_assignments")

    return MissingRoleRelationshipUser


def _build_missing_role_catalog_name_user_model() -> type[Any]:
    """Create one mapped role family missing ``role.name``.

    Returns:
        The mapped user model missing the documented role-name column.
    """

    class MissingCatalogNameBase(DeclarativeBase):
        """Dedicated registry for missing-role-catalog-name tests."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class MissingCatalogNameUUIDBase(UUIDPrimaryKey, MissingCatalogNameBase):
        """UUID base for missing-role-catalog-name tests."""

        __abstract__ = True

    class MissingCatalogNameUser(UserModelMixin, MissingCatalogNameUUIDBase):
        """Mapped user model with relational roles missing the role name column."""

        __tablename__ = "missing_catalog_name_user"

        role_assignments: Mapped[list[MissingCatalogNameUserRole]] = relationship(
            back_populates="user",
            cascade="all, delete-orphan",
        )

        @property
        def roles(self) -> list[str]:
            """Expose normalized flat role membership."""
            return normalize_roles([assignment.role_name for assignment in self.role_assignments])

        @roles.setter
        def roles(self, value: object) -> None:
            """Persist one normalized snapshot for coverage only."""
            normalized_roles = normalize_roles(value)
            self.role_assignments = [MissingCatalogNameUserRole(role_name=role_name) for role_name in normalized_roles]

    class MissingCatalogNameRole(MissingCatalogNameBase):
        """Role catalog row missing the documented ``name`` column."""

        __tablename__ = "missing_catalog_name_role"

        slug: Mapped[str] = mapped_column(String(length=255), primary_key=True)

    class MissingCatalogNameUserRole(MissingCatalogNameBase):
        """Association row pointing at the custom ``slug`` primary key."""

        __tablename__ = "missing_catalog_name_user_role"

        user_id: Mapped[UUID] = mapped_column(ForeignKey("missing_catalog_name_user.id"), primary_key=True)
        role_name: Mapped[str] = mapped_column(ForeignKey("missing_catalog_name_role.slug"), primary_key=True)
        user: Mapped[MissingCatalogNameUser] = relationship(back_populates="role_assignments")
        role: Mapped[MissingCatalogNameRole] = relationship()

    return MissingCatalogNameUser


def test_resolve_role_model_family_supports_bundled_models() -> None:
    """Bundled SQLAlchemy models resolve the role catalog and assignment rows from relationships."""
    model_family = resolve_role_model_family(User)

    assert model_family.user_model is User
    assert model_family.role_model is Role
    assert model_family.user_role_model is UserRole


def test_sqlalchemy_role_admin_supports_custom_role_model_families() -> None:
    """Custom role-capable SQLAlchemy model families resolve without hard-coded bundled classes."""
    custom_user_model, custom_role_model, custom_user_role_model = _build_custom_role_models()
    role_admin = SQLAlchemyRoleAdmin.from_config(
        _minimal_config(user_model=custom_user_model, session_maker=TrackingSessionMaker()),
    )

    assert role_admin.user_model is custom_user_model
    assert role_admin.role_model is custom_role_model
    assert role_admin.user_role_model is custom_user_role_model


def test_sqlalchemy_role_admin_with_role_membership_preloads_lazy_select_assignments(session: SASession) -> None:
    """Role-admin membership queries preload lazy-select assignments before CLI code reads ``user.roles``."""
    custom_user_model, _custom_role_model, _custom_user_role_model = _build_custom_role_models(
        user_role_relationship_lazy="",
    )
    bind = session.get_bind()
    custom_user_model.metadata.create_all(bind)
    session.add(
        custom_user_model(
            email="lazy-select@example.com",
            hashed_password="hashed-password",
            roles=[" Billing ", "admin", "ADMIN"],
        ),
    )
    session.commit()
    session.expunge_all()

    role_admin = SQLAlchemyRoleAdmin.from_config(
        _minimal_config(user_model=custom_user_model, session_maker=TrackingSessionMaker()),
    )
    statement = role_admin._with_role_membership(
        select(custom_user_model).where(cast("Any", custom_user_model).email == "lazy-select@example.com"),
    )
    loaded_user = session.scalar(statement)

    assert loaded_user is not None
    session.expunge(loaded_user)
    assert cast("Any", loaded_user).roles == ["admin", "billing"]


def test_sqlalchemy_role_admin_rejects_missing_role_assignments_before_session_use() -> None:
    """Role-admin setup fails closed before touching ``session_maker()`` when the role contract is incomplete."""
    relationshipless_user_model = _build_relationshipless_role_user_model()
    session_maker = TrackingSessionMaker()

    with pytest.raises(ConfigurationError, match="role_assignments"):
        SQLAlchemyRoleAdmin.from_config(
            _minimal_config(user_model=relationshipless_user_model, session_maker=session_maker),
        )

    assert session_maker.call_count == 0


def test_resolve_role_model_family_rejects_mapped_user_models_without_roles() -> None:
    """Role-admin setup fails closed when ``user_model`` lacks the flat ``roles`` contract."""
    missing_roles_user_model = _build_missing_roles_attribute_user_model()

    with pytest.raises(ConfigurationError, match="flat 'roles' attribute"):
        resolve_role_model_family(missing_roles_user_model)


def test_resolve_role_model_family_rejects_non_sqlalchemy_user_models() -> None:
    """Role-admin setup fails closed for non-mapped user classes even if they expose ``roles``."""

    class PlainRoleUser:
        """Plain user class that is not a SQLAlchemy model."""

        roles: ClassVar[tuple[str, ...]] = ("admin",)

    with pytest.raises(ConfigurationError, match="SQLAlchemy mapped class"):
        resolve_role_model_family(cast("type[Any]", PlainRoleUser))


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (_build_missing_role_name_user_model, "role_name"),
        (_build_missing_role_relationship_user_model, "mapped 'role' relationship"),
        (_build_missing_role_catalog_name_user_model, "normalized 'name'"),
    ],
)
def test_resolve_role_model_family_rejects_incomplete_relational_role_contracts(
    builder: object,
    match: str,
) -> None:
    """Role-admin setup fails closed when any documented relational role component is missing."""
    user_model_builder = cast("Any", builder)

    with pytest.raises(ConfigurationError, match=match):
        resolve_role_model_family(user_model_builder())


def test_sqlalchemy_role_admin_requires_session_maker_for_cli_work() -> None:
    """Role-admin setup rejects configs that only rely on external request-scoped session DI."""
    config = _minimal_config(
        user_model=User,
        session_maker=None,
        db_session_dependency_provided_externally=True,
    )

    with pytest.raises(ConfigurationError, match="session_maker"):
        SQLAlchemyRoleAdmin.from_config(config)


async def test_sqlalchemy_role_admin_session_uses_configured_session_maker() -> None:
    """The session helper opens and closes AsyncSession work through the configured session maker."""
    session_maker = TrackingSessionMaker()
    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=session_maker))

    async with role_admin.session() as session:
        assert session is session_maker.session
        assert session_maker.call_count == 1
        assert session_maker.session.enter_count == 1

    assert session_maker.session.exit_count == 1


async def test_sqlalchemy_role_admin_session_rejects_non_context_manager_factories() -> None:
    """The session helper fails closed when ``session_maker()`` does not return an async context manager."""
    role_admin = SQLAlchemyRoleAdmin.from_config(
        _minimal_config(user_model=User, session_maker=NonContextSessionMaker()),
    )

    with pytest.raises(ConfigurationError, match="async context manager"):
        async with role_admin.session():
            pytest.fail("session() should not yield for non-context-manager factories")


async def test_sqlalchemy_role_admin_session_rejects_non_async_session_objects() -> None:
    """The session helper fails closed when the yielded object is not AsyncSession-compatible."""
    role_admin = SQLAlchemyRoleAdmin.from_config(
        _minimal_config(user_model=User, session_maker=MissingMethodsSessionMaker()),
    )

    with pytest.raises(ConfigurationError, match="AsyncSession-compatible"):
        async with role_admin.session():
            pytest.fail("session() should not yield for incompatible session objects")


def test_sqlalchemy_role_admin_replace_user_roles_matches_flat_contract(session: SASession) -> None:
    """Replacing roles reuses the existing normalized flat ``user.roles`` contract and relational persistence."""
    user = User(
        email="role-admin@example.com",
        hashed_password="hashed-password",
        roles=["member"],
    )
    session.add(user)
    session.commit()
    user_id = user.id

    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=TrackingSessionMaker()))

    normalized_roles = role_admin.replace_user_roles(user, [" Billing ", "admin", "ADMIN"])
    session.commit()
    session.expunge_all()

    refreshed_user = session.get(User, user_id)

    assert refreshed_user is not None
    assert normalized_roles == ["admin", "billing"]
    assert refreshed_user.roles == ["admin", "billing"]
    assert list(
        session.execute(
            select(UserRole.role_name).where(UserRole.user_id == user_id).order_by(UserRole.role_name),
        ).scalars(),
    ) == ["admin", "billing"]
    assert list(session.execute(select(Role.name).order_by(Role.name)).scalars()) == ["admin", "billing", "member"]


def test_sqlalchemy_role_admin_replace_user_roles_rejects_wrong_model_instances() -> None:
    """Role-admin mutation helpers reject user instances outside the configured SQLAlchemy model family."""
    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=TrackingSessionMaker()))

    class OtherUser:
        """Plain object that is not an instance of the configured user model."""

    with pytest.raises(TypeError, match="configured user_model"):
        role_admin.replace_user_roles(cast("Any", OtherUser()), ["admin"])


def test_sqlalchemy_role_admin_parse_user_id_covers_uuid_and_fallback_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-id parsing preserves the UUID-first contract and the model-introspection fallbacks."""
    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=TrackingSessionMaker()))

    assert role_admin.parse_user_id("not-a-uuid") == "not-a-uuid"

    def _inspect_raises(_: object) -> object:
        msg = "no inspection"
        raise NoInspectionAvailable(msg)

    monkeypatch.setattr(role_admin_module, "inspect", _inspect_raises)
    assert role_admin.parse_user_id("still-a-string") == "still-a-string"

    class _TypeWithoutPythonType:
        @property
        def python_type(self) -> object:
            raise NotImplementedError

    class _PrimaryKeyColumn:
        type = _TypeWithoutPythonType()

    class _InspectionResult:
        primary_key: ClassVar[list[object]] = [_PrimaryKeyColumn()]

    monkeypatch.setattr(role_admin_module, "inspect", lambda _: _InspectionResult())
    assert role_admin.parse_user_id("opaque-id") == "opaque-id"

    class _IntegerPrimaryKeyColumn:
        type = SimpleNamespace(python_type=int)

    class _IntegerInspectionResult:
        primary_key: ClassVar[list[object]] = [_IntegerPrimaryKeyColumn()]

    monkeypatch.setattr(role_admin_module, "inspect", lambda _: _IntegerInspectionResult())
    assert role_admin.parse_user_id("not-an-int") == "not-an-int"


def test_manager_lifecycle_role_updater_builds_manager_from_plugin_config() -> None:
    """CLI role mutations build a session-bound manager through the plugin factory contract."""
    session = cast("Any", object())
    manager = cast("Any", object())
    captured: dict[str, object] = {}

    def _user_db_factory(_: object) -> object:
        return object()

    def _manager_factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return manager

    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    config.user_db_factory = cast("Any", _user_db_factory)
    config.user_manager_factory = cast("Any", _manager_factory)

    updater = _ManagerLifecycleRoleUpdater.from_config(config)

    assert updater.build_manager(session) is manager
    assert captured["session"] is session
    assert captured["config"] is config
    assert captured["backends"] == ()
    assert captured["user_db"].__class__.__name__ == "_ScopedUserDatabaseProxy"


def test_manager_lifecycle_role_updater_builds_oauth_token_policy_when_configured() -> None:
    """CLI role lifecycle updates preserve the plugin's explicit OAuth token policy wiring."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    config.oauth_config = OAuthConfig()

    updater = _ManagerLifecycleRoleUpdater.from_config(config)

    assert updater._oauth_token_encryption is not None
    assert updater._oauth_token_encryption.key is None
    assert updater._oauth_token_encryption.unsafe_testing is config.unsafe_testing


async def test_sqlalchemy_role_admin_update_user_roles_uses_manager_lifecycle_payload() -> None:
    """Role updates normalize the payload before dispatching through the manager lifecycle."""
    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=TrackingSessionMaker()))
    user = User(
        email="lifecycle@example.com",
        hashed_password="hashed-password",
        roles=["member"],
    )
    update_calls: list[tuple[User, Mapping[str, Any]]] = []

    class FakeManager:
        """Minimal manager stub capturing normalized update payloads."""

        async def update(self, user_update: Mapping[str, Any], current_user: User) -> User:
            update_calls.append((current_user, user_update))
            current_user.roles = user_update["roles"]
            return current_user

    fake_manager = cast("_RoleLifecycleManager[User]", FakeManager())

    updated_user = await role_admin._update_user_roles(
        manager=fake_manager,
        user=user,
        roles=[" Billing ", "admin", "ADMIN"],
    )

    assert updated_user.roles == ["admin", "billing"]
    assert update_calls == [(user, {"roles": ["admin", "billing"]})]


async def test_sqlalchemy_role_admin_unassign_user_roles_checks_role_catalog_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional role-catalog validation runs before unassigning user roles."""
    session = TrackingAsyncSession()
    role_admin = SQLAlchemyRoleAdmin.from_config(
        _minimal_config(user_model=User, session_maker=TrackingSessionMaker(session)),
    )
    user = User(
        email="member@example.com",
        hashed_password="hashed-password",
        roles=["billing"],
    )
    required_roles: list[str] = []
    update_calls: list[list[str]] = []

    async def _fake_require_role_by_name(self: SQLAlchemyRoleAdmin[User], session: object, *, role_name: str) -> object:
        del self, session
        await asyncio.sleep(0)
        required_roles.append(role_name)
        return object()

    async def _fake_require_user(
        self: SQLAlchemyRoleAdmin[User],
        session: object,
        *,
        email: str | None = None,
        user_id: object | None = None,
    ) -> User:
        del self, session, email, user_id
        await asyncio.sleep(0)
        return user

    async def _fake_update_user_roles(
        self: SQLAlchemyRoleAdmin[User],
        *,
        manager: _RoleLifecycleManager[User],
        user: User,
        roles: object,
    ) -> User:
        del self, manager, user
        await asyncio.sleep(0)
        normalized_roles = normalize_roles(roles)
        update_calls.append(normalized_roles)
        return User(email="updated@example.com", hashed_password="hash", roles=normalized_roles)

    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_require_role_by_name", _fake_require_role_by_name)
    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_require_user", _fake_require_user)
    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_update_user_roles", _fake_update_user_roles)

    await role_admin.unassign_user_roles(user_id=UUID(int=1), roles=["billing"], require_existing_roles=True)

    assert required_roles == ["billing"]
    assert update_calls == [[]]


async def test_sqlalchemy_role_admin_require_user_rejects_invalid_selector_combinations() -> None:
    """User lookup requires exactly one selector."""
    role_admin = SQLAlchemyRoleAdmin.from_config(_minimal_config(user_model=User, session_maker=TrackingSessionMaker()))

    with pytest.raises(TypeError, match="exactly one of email or user_id"):
        await role_admin._require_user(cast("Any", TrackingAsyncSession()))

    with pytest.raises(TypeError, match="exactly one of email or user_id"):
        await role_admin._require_user(
            cast("Any", TrackingAsyncSession()),
            email="member@example.com",
            user_id=UUID(int=1),
        )


async def test_sqlalchemy_role_admin_delete_role_force_uses_manager_updates_before_role_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forced deletion updates each user through the lifecycle path before deleting the role row."""
    session = TrackingAsyncSession()
    session_maker = TrackingSessionMaker(session)
    manager = cast("_RoleLifecycleManager[User]", object())
    captured_role_names: list[tuple[str, str]] = []
    update_calls: list[tuple[str, list[str]]] = []

    class FakeLifecycleUpdater:
        """Minimal lifecycle updater that records the bound session."""

        def __init__(self) -> None:
            """Initialize the captured session log."""
            self.sessions: list[TrackingAsyncSession] = []

        def build_manager(self, bound_session: object) -> _RoleLifecycleManager[User]:
            """Return the fixed manager sentinel for delete-role orchestration."""
            self.sessions.append(cast("TrackingAsyncSession", bound_session))
            return manager

    fake_lifecycle_updater = FakeLifecycleUpdater()
    role_admin = SQLAlchemyRoleAdmin(
        model_family=resolve_role_model_family(User),
        _session_maker=cast("Any", session_maker),
        _role_lifecycle_updater=cast("Any", fake_lifecycle_updater),
    )
    users = [
        User(email="auditor@example.com", hashed_password="hashed-password", roles=["admin"]),
        User(email="member@example.com", hashed_password="hashed-password", roles=["admin", "billing"]),
    ]

    async def _fake_require_role_by_name(self: SQLAlchemyRoleAdmin[User], session: object, *, role_name: str) -> object:
        del self, session
        await asyncio.sleep(0)
        captured_role_names.append(("require", role_name))
        return object()

    async def _fake_load_users_with_role(
        self: SQLAlchemyRoleAdmin[User],
        session: object,
        *,
        role_name: str,
    ) -> list[User]:
        del self, session
        await asyncio.sleep(0)
        captured_role_names.append(("load", role_name))
        return users

    async def _fake_update_user_roles(
        self: SQLAlchemyRoleAdmin[User],
        *,
        manager: _RoleLifecycleManager[User],
        user: User,
        roles: object,
    ) -> User:
        del manager
        await asyncio.sleep(0)
        normalized_roles = self.normalized_role_names(roles)
        update_calls.append((user.email, normalized_roles))
        user.roles = normalized_roles
        return user

    async def _fake_list_role_names(self: SQLAlchemyRoleAdmin[User], session: object) -> list[str]:
        del self, session
        await asyncio.sleep(0)
        return ["billing"]

    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_require_role_by_name", _fake_require_role_by_name)
    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_load_users_with_role", _fake_load_users_with_role)
    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_update_user_roles", _fake_update_user_roles)
    monkeypatch.setattr(SQLAlchemyRoleAdmin, "_list_role_names", _fake_list_role_names)

    remaining_roles = await role_admin.delete_role(role=" Admin ", force=True)

    assert remaining_roles == ["billing"]
    assert captured_role_names == [("require", "admin"), ("load", "admin")]
    assert fake_lifecycle_updater.sessions == [session]
    assert update_calls == [
        ("auditor@example.com", []),
        ("member@example.com", ["billing"]),
    ]
    assert session.commit_count == 1
    assert len(session.executed_statements) == 1
    delete_statement = session.executed_statements[0]
    assert cast("Any", delete_statement).table.name == Role.__tablename__
    assert cast("Any", delete_statement).table.name != UserRole.__tablename__
