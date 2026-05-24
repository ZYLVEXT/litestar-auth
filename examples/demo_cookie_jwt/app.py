"""Demonstration app: JWT stored in an HttpOnly cookie with Litestar CSRF protection.

Cookie transports cause :class:`~litestar_auth.LitestarAuth` to register Litestar ``CSRFConfig``.
Unsafe methods on auth routes therefore require the ``X-CSRF-Token`` header to match the
``litestar_auth_csrf`` cookie (see plugin defaults).

Environment:

- ``LITESTAR_AUTH_DEMO_COOKIE_JWT_INSECURE=1`` — fixed dev secrets.
- ``LITESTAR_AUTH_JWT_SECRET``, ``LITESTAR_AUTH_VERIFY_TOKEN_SECRET``,
  ``LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET``, ``LITESTAR_AUTH_CSRF_SECRET`` — production inputs.
- ``LITESTAR_AUTH_DEMO_COOKIE_JWT_DATABASE_URL`` — optional SQLite URL (default ``./demo_cookie_jwt.db``).

Browser-oriented flow:

1. ``GET /health`` — Litestar issues the CSRF cookie.
2. ``POST /auth/register`` — send JSON body **and** ``X-CSRF-Token: <csrf cookie value>``.
3. ``POST /auth/login`` — same CSRF header contract; response sets the auth cookie (JWT).
4. ``GET /demo/cookie-profile`` — uses the auth cookie automatically (no ``Authorization`` header).

HTTP API clients should preserve cookies between calls (same cookie jar).
"""

from __future__ import annotations

import logging
import os
import warnings
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

from litestar_auth import (
    AuthenticationBackend,
    BaseUserManager,
    CookieTransport,
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

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_COOKIE_JWT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_RESET",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_CSRF_COOKIE",
)


def _demo_secrets() -> tuple[str, str, str, str]:
    """Return (jwt, verify, reset, csrf) secrets."""
    if os.environ.get("LITESTAR_AUTH_DEMO_COOKIE_JWT_INSECURE") == "1":
        warnings.warn(
            "LITESTAR_AUTH_DEMO_COOKIE_JWT_INSECURE=1 uses fixed secrets; never enable in production.",
            stacklevel=2,
        )
        return _INSECURE_DEFAULTS

    def _req(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            msg = (
                f"Missing {name}. Export strong secrets or set "
                "LITESTAR_AUTH_DEMO_COOKIE_JWT_INSECURE=1 for local demonstration only."
            )
            raise RuntimeError(msg)
        return value

    return (
        _req("LITESTAR_AUTH_JWT_SECRET"),
        _req("LITESTAR_AUTH_VERIFY_TOKEN_SECRET"),
        _req("LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"),
        _req("LITESTAR_AUTH_CSRF_SECRET"),
    )


@dataclass(slots=True)
class _DemoRuntime:
    """Async SQLAlchemy wiring scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


class DemoUserManager(BaseUserManager[User, UUID]):
    """Demo hooks with optional verification logging."""

    async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
        """Emit a log line when verify-email tokens are minted."""
        await super().on_after_request_verify_token(user, token)
        if user is not None and token is not None:
            logger.info("Verification token issued for %s", user.email)


@dataclass(slots=True, frozen=True)
class _CookieJWTSecrets:
    """Secrets bundle for cookie JWT + CSRF."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    csrf_secret: str


def _build_config(*, secrets: _CookieJWTSecrets, runtime: _DemoRuntime) -> LitestarAuthConfig[User, UUID]:
    backend = AuthenticationBackend[User, UUID](
        name="jwt_cookie",
        transport=CookieTransport(
            cookie_name="demo_cookie_auth",
            secure=False,
            path="/",
            samesite="lax",
        ),
        strategy=JWTStrategy[User, UUID](
            secret=secrets.jwt_secret,
            lifetime=timedelta(minutes=30),
            subject_decoder=UUID,
            allow_inmemory_denylist=True,
        ),
    )
    return LitestarAuthConfig[User, UUID](
        backends=(backend,),
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
    )


@get("/health", sync_to_thread=False)
def health() -> dict[str, str]:
    """Simple route to prime CSRF cookies before unsafe auth requests.

    Returns:
        Liveness payload.
    """
    return {"status": "ok"}


@get("/demo/cookie-profile", guards=[is_authenticated], sync_to_thread=False)
def cookie_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Requires the JWT auth cookie issued by ``POST /auth/login``.

    Returns:
        Authenticated user snapshot.
    """
    user = cast("User", request.user)
    return {"transport": "cookie_jwt", "user_id": str(user.id), "email": user.email}


def create_app() -> Litestar:
    """Construct the demo ASGI application.

    Returns:
        Litestar instance with cookie JWT transport and CSRF middleware enabled.
    """
    jwt_s, verify_s, reset_s, csrf_s = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_COOKIE_JWT_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_cookie_jwt.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    runtime = _DemoRuntime(session_maker=session_maker, engine=engine)
    demo_secrets = _CookieJWTSecrets(
        jwt_secret=jwt_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        csrf_secret=csrf_s,
    )
    auth_config = _build_config(secrets=demo_secrets, runtime=runtime)

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
        route_handlers=[health, cookie_profile],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(
            title="litestar-auth demo (cookie JWT + CSRF)",
            version="0.1.0",
        ),
    )


app = create_app()
