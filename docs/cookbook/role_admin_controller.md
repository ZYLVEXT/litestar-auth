# Cookbook: Role catalog administration API

Add HTTP endpoints for creating, reading, updating, and deleting roles, plus
assigning and revoking roles on users.  This cookbook provides a complete,
copy-paste-ready Litestar controller built on
**Advanced Alchemy Repository / Service** for **superuser-guarded role
management** in applications that use the library's relational role support.

## When to use

Use this controller when your application:

- Uses `RoleMixin`, `UserRoleRelationshipMixin`, and `UserRoleAssociationMixin`
  from litestar-auth.
- Needs HTTP CRUD for your global role catalog (not multi-tenant per-app role
  namespaces).
- Wants superuser-only administration of roles and user assignments.
- Expects role names to be normalized (lowercase, trimmed, deduplicated) like
  the CLI.

## The controller

Save this as a module in your app (e.g. `myapp/auth/roles.py`).
The example uses **async** SQLAlchemy (`AsyncSession`) — the standard
Litestar + litestar-auth stack.

```python
"""Role administration controller — cookbook example.

Uses Advanced Alchemy Repository / Service for all persistence and
AsyncSession for async SQLAlchemy.
"""

from __future__ import annotations

import unicodedata
from contextlib import asynccontextmanager
from typing import Any, cast
from uuid import UUID

from advanced_alchemy.exceptions import NotFoundError
from advanced_alchemy.filters import CollectionFilter, LimitOffset
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from advanced_alchemy.service import SQLAlchemyAsyncRepositoryService
from litestar import Controller, delete, get, patch, post
from litestar.exceptions import HTTPException, NotFoundException
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_409_CONFLICT
from msgspec import Struct
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth.guards import is_superuser


def normalize_role_name(role: str) -> str:
    normalized = unicodedata.normalize("NFKC", role.strip()).lower()
    if not normalized:
        msg = "Role name must not be empty."
        raise ValueError(msg)
    return normalized


# ============================================================================
# Schemas
# ============================================================================


class RoleCreate(Struct):
    """Role creation payload."""

    name: str
    description: str | None = None


class RoleUpdate(Struct):
    """Role update payload (name is immutable)."""

    description: str | None = None


class RoleRead(Struct):
    """Role read response."""

    name: str
    description: str | None = None


class UserBrief(Struct):
    """Minimal user representation for role-user listings."""

    id: str
    email: str | None = None
    is_active: bool = True
    is_superuser: bool = False


# ============================================================================
# Repository / Service
# ============================================================================


def _build_role_repository(role_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository bound to the role model with ``name`` as PK."""
    return type(
        f"{role_model.__name__}Repository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": role_model, "id_attribute": "name"},
    )


def _build_user_role_repository(user_role_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository bound to the user-role association model."""
    return type(
        f"{user_role_model.__name__}Repository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": user_role_model},
    )


def _build_role_service(
    role_repo_type: type[SQLAlchemyAsyncRepository[Any]],
) -> type[SQLAlchemyAsyncRepositoryService[Any, Any]]:
    """Create a Service class bound to the role repository."""
    return type(
        "RoleService",
        (SQLAlchemyAsyncRepositoryService,),
        {"repository_type": role_repo_type},
    )


# ============================================================================
# Factory
# ============================================================================


def create_role_admin_controller(
    *,
    user_model: type[Any],
    role_model: type[Any],
    user_role_model: type[Any],
    route_prefix: str = "roles",
) -> type[Controller]:
    """Return a Controller **class** wired for role catalog CRUD.

    The controller receives ``db_session: AsyncSession`` via Litestar DI and
    builds Advanced Alchemy Repository / Service instances per request.

    Args:
        user_model: SQLAlchemy user model (must have ``id``, ``email``).
        role_model: SQLAlchemy role model (``name`` primary key).
        user_role_model: Association model (``user_id`` + ``role_name``).
        route_prefix: URL prefix for all role routes (default ``"roles"``).

    Returns:
        A Controller subclass ready to pass to ``Litestar(route_handlers=[...])``.
    """

    RoleRepo = _build_role_repository(role_model)
    UserRoleRepo = _build_user_role_repository(user_role_model)
    RoleService = _build_role_service(RoleRepo)
    UserRepo = type("_UserRepo", (SQLAlchemyAsyncRepository,), {"model_type": user_model})

    # -- helpers -------------------------------------------------------------

    def _role_read(role: Any) -> RoleRead:
        return RoleRead(
            name=role.name,
            description=getattr(role, "description", None),
        )

    def _user_brief(user: Any) -> UserBrief:
        return UserBrief(
            id=str(user.id),
            email=getattr(user, "email", None),
            is_active=getattr(user, "is_active", True),
            is_superuser=getattr(user, "is_superuser", False),
        )

    def _parse_user_id(raw: str) -> UUID | str:
        """Try UUID first; fall back to the raw string for int-PK models."""
        try:
            return UUID(raw)
        except ValueError:
            return raw

    @asynccontextmanager
    async def _repos(session: AsyncSession):
        """Yield (role_service, user_role_repo) sharing one session."""
        async with RoleService.new(session=session) as svc:
            ur_repo = UserRoleRepo(session=session, auto_commit=False)
            yield svc, ur_repo

    # -- controller ----------------------------------------------------------

    class RoleAdminController(Controller):
        path = f"/{route_prefix}"
        guards = [is_superuser]

        # -- role CRUD -------------------------------------------------------

        @get()
        async def list_roles(
            self,
            db_session: AsyncSession,
            limit: int = 100,
            offset: int = 0,
        ) -> list[RoleRead]:
            """List all roles with pagination."""
            async with RoleService.new(session=db_session) as svc:
                roles, _total = await svc.list_and_count(
                    LimitOffset(limit=limit, offset=offset),
                )
                return [_role_read(r) for r in roles]

        @post(status_code=HTTP_201_CREATED)
        async def create_role(
            self,
            db_session: AsyncSession,
            data: RoleCreate,
        ) -> RoleRead:
            """Create a new role.  The name is normalized on input."""
            normalized = normalize_role_name(data.name)
            async with RoleService.new(session=db_session) as svc:
                try:
                    role = await svc.create(
                        {
                            "name": normalized,
                            **({"description": data.description} if data.description is not None else {}),
                        },
                        auto_commit=True,
                    )
                except IntegrityError:
                    raise HTTPException(
                        status_code=HTTP_409_CONFLICT,
                        detail=f"Role '{normalized}' already exists",
                    ) from None
                return _role_read(role)

        @get(path="/{role_name:str}")
        async def get_role(
            self,
            db_session: AsyncSession,
            role_name: str,
        ) -> RoleRead:
            """Fetch a single role by its name."""
            normalized = normalize_role_name(role_name)
            async with RoleService.new(session=db_session) as svc:
                try:
                    role = await svc.get(normalized)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"Role '{normalized}' not found",
                    ) from None
                return _role_read(role)

        @patch(path="/{role_name:str}")
        async def update_role(
            self,
            db_session: AsyncSession,
            role_name: str,
            data: RoleUpdate,
        ) -> RoleRead:
            """Update role metadata (description only; name is immutable)."""
            normalized = normalize_role_name(role_name)
            async with RoleService.new(session=db_session) as svc:
                try:
                    role = await svc.get(normalized)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"Role '{normalized}' not found",
                    ) from None
                if data.description is not None:
                    role.description = data.description
                role = await svc.update(role, auto_commit=True)
                return _role_read(role)

        @delete(path="/{role_name:str}", status_code=HTTP_204_NO_CONTENT)
        async def delete_role(
            self,
            db_session: AsyncSession,
            role_name: str,
        ) -> None:
            """Delete a role.  Returns 409 if users are still assigned."""
            normalized = normalize_role_name(role_name)
            async with _repos(db_session) as (svc, ur_repo):
                try:
                    await svc.get(normalized)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"Role '{normalized}' not found",
                    ) from None

                if await ur_repo.exists(
                    cast("Any", user_role_model).role_name == normalized,
                ):
                    raise HTTPException(
                        status_code=HTTP_409_CONFLICT,
                        detail=(
                            f"Cannot delete role '{normalized}': "
                            "users are still assigned to it. "
                            "Unassign users first."
                        ),
                    )
                await svc.delete(normalized, auto_commit=True)

        # -- user ↔ role assignment ------------------------------------------

        @post(path="/{role_name:str}/users/{user_id:str}")
        async def assign_role(
            self,
            db_session: AsyncSession,
            role_name: str,
            user_id: str,
        ) -> RoleRead:
            """Assign a role to a user (idempotent)."""
            normalized = normalize_role_name(role_name)
            parsed_id = _parse_user_id(user_id)

            async with _repos(db_session) as (svc, ur_repo):
                try:
                    role = await svc.get(normalized)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"Role '{normalized}' not found",
                    ) from None

                u_repo = UserRepo(session=db_session)
                try:
                    await u_repo.get(parsed_id)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"User '{user_id}' not found",
                    ) from None

                already = await ur_repo.exists(
                    (cast("Any", user_role_model).user_id == parsed_id)
                    & (cast("Any", user_role_model).role_name == normalized),
                )
                if not already:
                    await ur_repo.add(
                        user_role_model(user_id=parsed_id, role_name=normalized),
                        auto_commit=True,
                    )
                return _role_read(role)

        @delete(
            path="/{role_name:str}/users/{user_id:str}",
            status_code=HTTP_204_NO_CONTENT,
        )
        async def unassign_role(
            self,
            db_session: AsyncSession,
            role_name: str,
            user_id: str,
        ) -> None:
            """Revoke a role from a user (idempotent — returns 204 even if absent)."""
            normalized = normalize_role_name(role_name)
            parsed_id = _parse_user_id(user_id)

            async with _repos(db_session) as (_svc, ur_repo):
                assignment = await ur_repo.get_one_or_none(
                    (cast("Any", user_role_model).user_id == parsed_id)
                    & (cast("Any", user_role_model).role_name == normalized),
                )
                if assignment is not None:
                    await ur_repo.delete(
                        ur_repo.get_id_attribute_value(assignment),
                        auto_commit=True,
                    )

        @get(path="/{role_name:str}/users")
        async def list_role_users(
            self,
            db_session: AsyncSession,
            role_name: str,
            limit: int = 100,
            offset: int = 0,
        ) -> list[UserBrief]:
            """List users assigned to a specific role."""
            normalized = normalize_role_name(role_name)
            async with _repos(db_session) as (svc, ur_repo):
                try:
                    await svc.get(normalized)
                except NotFoundError:
                    raise NotFoundException(
                        detail=f"Role '{normalized}' not found",
                    ) from None

                assignments, _ = await ur_repo.list_and_count(
                    cast("Any", user_role_model).role_name == normalized,
                    LimitOffset(limit=limit, offset=offset),
                )
                if not assignments:
                    return []

                user_ids = [a.user_id for a in assignments]
                u_repo = UserRepo(session=db_session)
                users = await u_repo.list(
                    CollectionFilter(field_name="id", values=user_ids),
                )
                return [_user_brief(u) for u in users]

    return RoleAdminController
```

## Integration

### Step 1: Provide `db_session` via DI

The controller handlers receive `db_session: AsyncSession` as a parameter.
Set up the dependency in your Litestar app — either through the
Advanced Alchemy Litestar plugin or manually:

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from litestar import Litestar
from litestar_auth import LitestarAuth, LitestarAuthConfig
from litestar_auth.models import User, Role, UserRole

from myapp.auth.roles import create_role_admin_controller

engine = create_async_engine("sqlite+aiosqlite:///app.db")
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def provide_db_session() -> AsyncSession:
    async with session_factory() as session:
        yield session


RoleAdmin = create_role_admin_controller(
    user_model=User,
    role_model=Role,
    user_role_model=UserRole,
    route_prefix="roles",  # → /roles, /roles/{name}, …
)

auth = LitestarAuth(config=LitestarAuthConfig(...))  # see Quickstart for full config

app = Litestar(
    route_handlers=[RoleAdmin],
    plugins=[auth],
    dependencies={"db_session": provide_db_session},
)
```

If you already use the **Advanced Alchemy Litestar plugin**
(`SQLAlchemyPlugin` / `SQLAlchemyAsyncConfig`), it provides `db_session`
automatically — no extra dependency needed.

### Step 2: Verify the models

The controller expects:

- **User model**: Has `id` (UUID or int) and `is_superuser` field (for the guard).
- **Role model**: Has `name` as primary key.
  The bundled `Role` model already includes an optional `description` column.
- **UserRole model**: Has `user_id` and `role_name` foreign keys.

The bundled models (`litestar_auth.models.User`, `Role`, `UserRole`) satisfy
all requirements out of the box.

## Example requests

### List roles

```bash
curl -X GET http://localhost:8000/roles \
  -H "Authorization: Bearer <token>"

# Response (200):
[
  {"name": "admin", "description": "Administrator role"},
  {"name": "editor", "description": "Content editor"}
]
```

### Create role

```bash
curl -X POST http://localhost:8000/roles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "viewer", "description": "Read-only access"}'

# Response (201 Created):
{"name": "viewer", "description": "Read-only access"}
```

### Get single role

```bash
curl -X GET http://localhost:8000/roles/admin \
  -H "Authorization: Bearer <token>"

# Response (200):
{"name": "admin", "description": "Administrator role"}
```

### Update role description

```bash
curl -X PATCH http://localhost:8000/roles/viewer \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"description": "Read-only viewer access"}'

# Response (200):
{"name": "viewer", "description": "Read-only viewer access"}
```

### Assign role to user

```bash
curl -X POST \
  http://localhost:8000/roles/editor/users/123e4567-e89b-12d3-a456-426614174000 \
  -H "Authorization: Bearer <token>"

# Response (200):
{"name": "editor", "description": "Content editor"}
```

### Revoke role from user

```bash
curl -X DELETE \
  http://localhost:8000/roles/editor/users/123e4567-e89b-12d3-a456-426614174000 \
  -H "Authorization: Bearer <token>"

# Response: 204 No Content
```

### List users with role

```bash
curl -X GET http://localhost:8000/roles/editor/users \
  -H "Authorization: Bearer <token>"

# Response (200):
[
  {"id": "123e4567-…-426614174000", "email": "alice@example.com", "is_active": true, "is_superuser": false},
  {"id": "223e4567-…-426614174001", "email": "bob@example.com",   "is_active": true, "is_superuser": false}
]
```

### Delete role (fails if assigned)

```bash
curl -X DELETE http://localhost:8000/roles/viewer \
  -H "Authorization: Bearer <token>"

# If no users have the role → 204 No Content

# If users are still assigned → 409 Conflict:
{"detail": "Cannot delete role 'viewer': users are still assigned to it. Unassign users first."}
```

## Error handling

| Status | Meaning |
|--------|---------|
| 200 | Successful GET, POST, or PATCH |
| 201 | Role created |
| 204 | Successful DELETE or unassign |
| 403 | Not authenticated as superuser |
| 404 | Role or user does not exist |
| 409 | Duplicate role name, or role still has assignments |
| 422 | Invalid request body |

## Customization

### Change the route prefix

```python
RoleAdmin = create_role_admin_controller(
    route_prefix="admin/roles",  # → /admin/roles, /admin/roles/{name}, …
    user_model=User,
    role_model=Role,
    user_role_model=UserRole,
)
```

### Override the guard

Subclass the returned controller and replace the class-level `guards` list:

```python
from litestar_auth.guards import has_any_role

_Base = create_role_admin_controller(
    user_model=User,
    role_model=Role,
    user_role_model=UserRole,
)


class CustomRoleAdmin(_Base):
    guards = [has_any_role("role_admin", "superuser")]
```

### Extend the schema

If you want more fields on roles (color, icon, …), extend the `Role` model
and update the request/response structs in your copy of the controller:

```python
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from litestar_auth.models import Role as BaseRole


class Role(BaseRole):
    color: Mapped[str | None] = mapped_column(String, nullable=True)
    icon: Mapped[str | None] = mapped_column(String, nullable=True)
```

## Known behaviors

- **Role normalization**: All role names are normalized on input (NFKC,
  lowercase, trimmed).  `"  ADMIN  "` becomes `"admin"`.
- **Immutable names**: Role names are primary keys and cannot be changed.
  Delete and recreate if renaming is needed.
- **CLI consistency**: Roles created via HTTP appear in `litestar roles list`
  and vice versa — both paths share the same database tables.
- **User.roles property**: Assign/unassign operations mutate the ORM
  association table directly; the user's `roles` property reflects the change
  on the next read.
- **UUID vs integer PK**: The `user_id` path parameter is parsed as UUID
  first; if that fails it is passed as-is.  Adapt `_parse_user_id` if your PK
  type needs different handling.
- **Repository error mapping**: Advanced Alchemy's `NotFoundError` is caught
  and re-raised as Litestar `NotFoundException` (HTTP 404).

## See also

- [Role management CLI guide](../guides/roles_cli.md)
- [Guards API](../api/guards.md)
- [Models API](../api/models.md)
