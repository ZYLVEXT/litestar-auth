"""Demonstration app for an external-style litestar-auth extension.

The extension itself lives in :mod:`examples.demo_external_extension.extension` and imports only the
public ``litestar_auth.extensions`` authoring facade. The app wires that extension explicitly through
``LitestarAuthConfig(extensions=(... ,))`` so it behaves like an installed third-party package without
registering a real entry point in this repository.

Environment:

- ``LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_INSECURE=1`` — fixed development-only secrets.
- ``LITESTAR_AUTH_JWT_SECRET``, ``LITESTAR_AUTH_VERIFY_TOKEN_SECRET``,
  ``LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET``, ``LITESTAR_AUTH_CSRF_SECRET`` — production inputs.
- ``LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_DATABASE_URL`` — optional SQLite URL.

Typical flow:

1. ``GET /health`` — public liveness check.
2. ``GET /demo/external-extension/status`` — route contributed by the extension.
3. ``POST /auth/register`` and ``POST /auth/login`` — normal generated auth routes.
4. ``GET /demo/external-extension/profile`` with ``Authorization: Bearer <access_token>``.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from litestar import Litestar, Request, get
from litestar.openapi.config import OpenAPIConfig
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import configure_mappers

from examples._demo_secrets import resolve_demo_secrets
from examples.demo_external_extension.extension import extension as demo_external_extension
from litestar_auth import (
    AuthenticationBackend,
    BaseUserManager,
    BearerTransport,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_JWT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_RESET",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_CSRF",
)


def _demo_secrets() -> tuple[str, str, str, str]:
    """Return (jwt, verify, reset, csrf) secrets."""
    return resolve_demo_secrets(
        insecure_flag="LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_INSECURE",
        insecure_defaults=_INSECURE_DEFAULTS,
        secret_names=(
            "LITESTAR_AUTH_JWT_SECRET",
            "LITESTAR_AUTH_VERIFY_TOKEN_SECRET",
            "LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET",
            "LITESTAR_AUTH_CSRF_SECRET",
        ),
    )


@dataclass(slots=True)
class _DemoRuntime:
    """Async SQLAlchemy wiring scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


@dataclass(slots=True, frozen=True)
class _DemoAuthSecrets:
    """Signing secrets for the demo app instance."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    csrf_secret: str


class DemoUserManager(BaseUserManager[User, UUID]):
    """Demo user manager using the default lifecycle hook behavior."""


def _bearer_backend(secret: str) -> AuthenticationBackend[User, UUID]:
    return AuthenticationBackend[User, UUID](
        name="jwt_bearer",
        transport=BearerTransport(),
        strategy=JWTStrategy[User, UUID](
            secret=secret,
            lifetime=timedelta(minutes=30),
            subject_decoder=UUID,
            allow_inmemory_denylist=True,
        ),
    )


def _build_litestar_auth_config(
    *,
    secrets: _DemoAuthSecrets,
    runtime: _DemoRuntime,
) -> LitestarAuthConfig[User, UUID]:
    return LitestarAuthConfig[User, UUID](
        backends=(_bearer_backend(secrets.jwt_secret),),
        session_maker=runtime.session_maker,
        user_model=User,
        user_manager_class=DemoUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=secrets.verify_secret,
            reset_password_token_secret=secrets.reset_secret,
        ),
        csrf_secret=secrets.csrf_secret,
        auth_path="/auth",
        include_register=True,
        include_verify=True,
        include_reset_password=True,
        include_users=False,
        requires_verification=False,
        deployment_worker_count=1,
        include_openapi_security=True,
        extensions=(demo_external_extension,),
    )


@get("/health", sync_to_thread=False)
def health() -> dict[str, str]:
    """Return a minimal liveness payload."""
    return {"status": "ok"}


@get("/demo/external-extension/profile", guards=[is_authenticated], sync_to_thread=False)
def extension_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Requires ``Authorization: Bearer <access_token>`` from ``POST /auth/login``.

    Returns:
        Authenticated user fields for the extension demo.
    """
    user = cast("User", request.user)
    return {"extension": "demo_external_extension", "user_id": str(user.id), "email": user.email}


def create_app() -> Litestar:
    """Construct the demo ASGI application.

    Returns:
        Litestar instance with a public extension contribution registered.
    """
    jwt_s, verify_s, reset_s, csrf_s = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_external_extension.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    runtime = _DemoRuntime(session_maker=session_maker, engine=engine)

    demo_secrets = _DemoAuthSecrets(
        jwt_secret=jwt_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        csrf_secret=csrf_s,
    )
    auth_config = _build_litestar_auth_config(secrets=demo_secrets, runtime=runtime)

    @asynccontextmanager
    async def lifespan(_: Litestar) -> AsyncIterator[None]:
        configure_mappers()
        async with engine.begin() as connection:
            await connection.run_sync(User.metadata.create_all)
        try:
            yield
        finally:
            await engine.dispose()

    return Litestar(
        route_handlers=[health, extension_profile],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(title="litestar-auth demo (external extension)", version="0.1.0"),
    )


app = create_app()
