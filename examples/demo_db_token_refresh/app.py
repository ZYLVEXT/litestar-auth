"""Demonstration app: opaque database access tokens with refresh (bearer preset).

Uses :class:`~litestar_auth.DatabaseTokenAuthConfig` so the plugin builds the bearer +
:class:`~litestar_auth.authentication.strategy.db.DatabaseTokenStrategy` backend. Tokens are rows in
the bundled ``access_token`` / ``refresh_token`` tables (see :func:`~litestar_auth.models.import_token_orm_models`).

Environment:

- ``LITESTAR_AUTH_DEMO_DB_TOKEN_INSECURE=1`` — fixed dev-only secrets (**never** in production).
- ``LITESTAR_AUTH_DB_TOKEN_HASH_SECRET`` — HMAC material for opaque token digests (required when not insecure).
- ``LITESTAR_AUTH_VERIFY_TOKEN_SECRET`` / ``LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET`` — account tokens.
- ``LITESTAR_AUTH_DEMO_DB_TOKEN_DATABASE_URL`` — optional SQLite URL (default ``./demo_db_token.db``).

Flow:

1. ``POST /auth/register`` then ``POST /auth/login`` — response includes ``access_token`` and ``refresh_token``.
2. ``GET /demo/db-token-profile`` with ``Authorization: Bearer <access_token>``.
3. When the access token expires, ``POST /auth/refresh`` with JSON ``{"refresh_token": "..."}``.

Unlike JWT examples, revocation and rotation are backed by your database; configure retention and
indexes for production workloads.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from litestar import Litestar, Request, get
from litestar.openapi.config import OpenAPIConfig
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import configure_mappers

from examples._demo_secrets import resolve_demo_secrets
from litestar_auth import (
    BaseUserManager,
    DatabaseTokenAuthConfig,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User, import_token_orm_models

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_DB_TOKEN_INSECURE = (
    "database-token-secret-12345678901234567890-LITESTAR_AUTH_DEMO_DB",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_RESET",
)


@dataclass(slots=True)
class _DemoRuntime:
    """Holds async engine + session factory for one app instance."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


class DemoUserManager(BaseUserManager[User, UUID]):
    """Thin concrete manager for the bundled ``User`` model."""


def _demo_secrets() -> tuple[str, str, str]:
    """Return (db_token_hash, verify, reset) secrets."""
    return resolve_demo_secrets(
        insecure_flag="LITESTAR_AUTH_DEMO_DB_TOKEN_INSECURE",
        insecure_defaults=_DB_TOKEN_INSECURE,
        secret_names=(
            "LITESTAR_AUTH_DB_TOKEN_HASH_SECRET",
            "LITESTAR_AUTH_VERIFY_TOKEN_SECRET",
            "LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET",
        ),
        missing_value_message="Missing {name}. Set strong secrets or {insecure_flag}=1 for local demos only.",
    )


def _demo_runtime() -> _DemoRuntime:
    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_DB_TOKEN_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_db_token.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return _DemoRuntime(session_maker=session_maker, engine=engine)


def _build_litestar_auth_config(
    *,
    hash_secret: str,
    verify_secret: str,
    reset_secret: str,
    runtime: _DemoRuntime,
) -> LitestarAuthConfig[User, UUID]:
    return LitestarAuthConfig[User, UUID](
        database_token_auth=DatabaseTokenAuthConfig(token_hash_secret=hash_secret),
        session_maker=runtime.session_maker,
        user_model=User,
        user_manager_class=DemoUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verify_secret,
            reset_password_token_secret=reset_secret,
        ),
        enable_refresh=True,
        requires_verification=False,
        deployment_worker_count=1,
        include_openapi_security=True,
    )


def _build_lifespan(engine: AsyncEngine) -> AsyncIterator[None]:
    @asynccontextmanager
    async def lifespan(_: Litestar) -> AsyncIterator[None]:
        configure_mappers()
        async with engine.begin() as connection:
            await connection.run_sync(User.metadata.create_all)
        try:
            yield
        finally:
            await engine.dispose()

    return lifespan


@get("/demo/db-token-profile", guards=[is_authenticated], sync_to_thread=False)
def db_token_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Echo the authenticated user when a valid DB-backed access token is presented.

    Returns:
        Minimal profile payload for the caller.
    """
    user = cast("User", request.user)
    return {"transport": "database_token", "user_id": str(user.id), "email": user.email}


def create_app() -> Litestar:
    """Build the demo Litestar application.

    Returns:
        ASGI app with DB-token preset and refresh routes enabled.
    """
    import_token_orm_models()
    hash_s, verify_s, reset_s = _demo_secrets()
    runtime = _demo_runtime()
    config = _build_litestar_auth_config(
        hash_secret=hash_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        runtime=runtime,
    )

    return Litestar(
        route_handlers=[db_token_profile],
        plugins=[LitestarAuth(config)],
        lifespan=[_build_lifespan(runtime.engine)],
        openapi_config=OpenAPIConfig(
            title="litestar-auth demo (database tokens + refresh)",
            version="0.1.0",
        ),
    )


app = create_app()
