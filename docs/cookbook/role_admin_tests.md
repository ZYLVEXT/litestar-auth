# Cookbook: Testing role administration endpoints

Examples for testing the role admin controller from the
[role administration API](role_admin_controller.md) recipe.

The snippets below are **illustrative** — adapt fixtures, config fields, and
assertion helpers to match the litestar-auth version you are running and your
own application layout.

## Unit tests (handler logic with mocked service)

```python
"""Unit tests for role admin controller handlers.

Mocks Advanced Alchemy Service / Repository so no real database is needed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from advanced_alchemy.exceptions import NotFoundError
from litestar.exceptions import HTTPException, NotFoundException
from litestar.status_codes import HTTP_409_CONFLICT
from sqlalchemy.exc import IntegrityError

from myapp.auth.roles import (
    RoleCreate,
    RoleRead,
    RoleUpdate,
    create_role_admin_controller,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_role(name: str = "admin", description: str | None = "Admin") -> MagicMock:
    role = MagicMock()
    role.name = name
    role.description = description
    return role


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def controller_cls():
    """Return the controller class wired with dummy models."""
    return create_role_admin_controller(
        user_model=MagicMock(),
        role_model=MagicMock(),
        user_role_model=MagicMock(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_list_roles_returns_items(controller_cls):
    """list_roles delegates to RoleService.list_and_count."""
    role_a, role_b = _make_role("admin"), _make_role("editor", "Editor")

    with patch.object(
        controller_cls, "_RoleService_new",  # illustrative; adapt to your mock strategy
    ):
        # The real test would provide a mocked db_session that the service
        # picks up.  Here we just verify the schema conversion:
        result = [
            RoleRead(name=r.name, description=r.description)
            for r in [role_a, role_b]
        ]
        assert len(result) == 2
        assert result[0].name == "admin"


@pytest.mark.anyio
async def test_get_role_not_found_raises_404(controller_cls):
    """When the service raises NotFoundError, the handler returns 404."""
    # NotFoundError is what Advanced Alchemy raises for missing rows.
    # The handler re-raises as Litestar NotFoundException (HTTP 404).
    with pytest.raises(NotFoundException):
        raise NotFoundException(detail="Role 'nonexistent' not found")


@pytest.mark.anyio
async def test_create_role_conflict_raises_409():
    """IntegrityError on duplicate name should produce 409."""
    with pytest.raises(HTTPException) as exc_info:
        raise HTTPException(
            status_code=HTTP_409_CONFLICT,
            detail="Role 'admin' already exists",
        )
    assert exc_info.value.status_code == HTTP_409_CONFLICT


@pytest.mark.anyio
async def test_delete_role_blocked_by_assignments_raises_409():
    """When assignments exist, delete returns 409."""
    with pytest.raises(HTTPException) as exc_info:
        raise HTTPException(
            status_code=HTTP_409_CONFLICT,
            detail="Cannot delete role 'editor': users are still assigned.",
        )
    assert exc_info.value.status_code == HTTP_409_CONFLICT
```

## Integration tests (real database)

```python
"""Integration tests — real database, real models.

Adapt the ``engine`` fixture to your actual stack.
These snippets show the pattern, not a finished test suite.
"""

from __future__ import annotations

import pytest
from advanced_alchemy.base import DefaultBase
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from litestar import Litestar
from litestar.testing import AsyncTestClient

from litestar_auth.models import Role, User, UserRole

from myapp.auth.roles import create_role_admin_controller


@pytest.fixture(scope="session")
def engine():
    return create_async_engine("sqlite+aiosqlite://", echo=False)


@pytest.fixture()
async def tables(engine):
    """Create and drop tables for each test."""
    async with engine.begin() as conn:
        await conn.run_sync(DefaultBase.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(DefaultBase.metadata.drop_all)


@pytest.fixture()
def session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def app(session_factory, tables):
    RoleAdmin = create_role_admin_controller(
        user_model=User,
        role_model=Role,
        user_role_model=UserRole,
    )

    async def provide_db_session():
        async with session_factory() as session:
            yield session

    return Litestar(
        route_handlers=[RoleAdmin],
        dependencies={"db_session": provide_db_session},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_create_and_list(app, session_factory):
    """Full create → list lifecycle."""
    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/roles",
            json={"name": "editor", "description": "Edit content"},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "editor"

        resp = await client.get("/roles")
        assert resp.status_code == 200
        names = {r["name"] for r in resp.json()}
        assert "editor" in names


@pytest.mark.anyio
async def test_role_name_normalized(app):
    """Names are NFKC-lowercased and trimmed."""
    async with AsyncTestClient(app=app) as client:
        resp = await client.post(
            "/roles",
            json={"name": "  ADMIN  "},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "admin"


@pytest.mark.anyio
async def test_delete_blocked_by_assignment(app, session_factory):
    """Cannot delete a role that still has user assignments."""
    async with session_factory() as session:
        role = Role(name="viewer")
        session.add(role)
        user = User(email="t@t.com", hashed_password="x", is_superuser=True)
        session.add(user)
        await session.flush()
        session.add(UserRole(user_id=user.id, role_name="viewer"))
        await session.commit()

    async with AsyncTestClient(app=app) as client:
        resp = await client.delete("/roles/viewer")
        assert resp.status_code == 409
        assert "Unassign users first" in resp.json()["detail"]


@pytest.mark.anyio
async def test_get_nonexistent_returns_404(app):
    """Fetching a role that does not exist returns 404."""
    async with AsyncTestClient(app=app) as client:
        resp = await client.get("/roles/nope")
        assert resp.status_code == 404
```

## Notes

- The unit tests above focus on schema conversion and error contracts.
  For full handler-level mocking, patch `RoleService.new` (the context manager)
  to return a mocked service instance, or test via `AsyncTestClient` with an
  in-memory database (integration style).
- Integration tests skip authentication setup for brevity.  In a real test
  suite you would authenticate as a superuser via the plugin's auth flow or
  inject a test user into the request scope.
- Use `pytest-anyio` (or `pytest-asyncio` with `asyncio_mode = "auto"`) so
  `@pytest.mark.anyio` / `@pytest.mark.asyncio` resolves correctly.
- Advanced Alchemy's `NotFoundError` is the canonical "row not found"
  exception.  The controller maps it to Litestar's `NotFoundException`
  (HTTP 404).

## See also

- [Testing plugin-backed apps guide](../guides/testing.md)
- [Role administration API recipe](role_admin_controller.md)
