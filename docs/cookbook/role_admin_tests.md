# Cookbook: Testing a custom role administration controller

The supported HTTP role-management surface is documented in
[HTTP role administration](../guides/role_admin_http.md). These examples are
for applications that keep an app-owned controller from the
[custom role administration controller](role_admin_controller.md) cookbook.

The snippets below are **illustrative** — adapt fixtures, config fields, and
assertion helpers to match the litestar-auth version you are running and your
own application layout.

## Unit tests (handler logic with mocked service)

Unit tests for an app-owned role controller should execute the controller method
or route handler under test. Keep mocks at the service or repository boundary,
then assert the HTTP exception or response produced by that handler. Avoid tests
that raise `NotFoundException` or `HTTPException` directly inside the test body:
those only verify pytest's exception handling and do not exercise your
controller.

Useful unit assertions for a custom role controller:

- list routes call the role service and convert returned role rows into the
  response schema;
- missing rows from the service are mapped to `NotFoundException`;
- duplicate role names from persistence errors are mapped to HTTP 409;
- delete operations reject roles that still have user assignments.

If those mappings live in only a few lines of controller code, an HTTP-level test
with a real app and database is usually clearer than a mock-heavy unit test.

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
        user = User(email="t@t.com", hashed_password="x", roles=["superuser"])
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
- If your custom assign/unassign handlers are meant to preserve
  `BaseUserManager.update(...)` hooks, assert that manager lifecycle explicitly.
  The supported contrib controller already does this.
- Use `pytest-anyio` (or `pytest-asyncio` with `asyncio_mode = "auto"`) so
  `@pytest.mark.anyio` / `@pytest.mark.asyncio` resolves correctly.
- Advanced Alchemy's `NotFoundError` is the standard "row not found"
  exception.  The controller maps it to Litestar's `NotFoundException`
  (HTTP 404).

## See also

- [Testing plugin-backed apps guide](../guides/testing.md)
- [HTTP role administration](../guides/role_admin_http.md)
- [Custom role administration controller](role_admin_controller.md)
