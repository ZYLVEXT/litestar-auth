"""Demonstration Litestar application: JWT bearer login + API-key authentication.

Environment variables:

- ``LITESTAR_AUTH_JWT_SECRET`` — JWT signing secret (HS256).
- ``LITESTAR_AUTH_VERIFY_TOKEN_SECRET`` / ``LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET`` —
  short-lived account-token secrets.
- ``LITESTAR_AUTH_API_KEY_HASH_SECRET`` — pepper for API-key digest verification.
- ``LITESTAR_AUTH_CSRF_SECRET`` — CSRF signing material used by the plugin middleware.
- ``LITESTAR_AUTH_DEMO_INSECURE=1`` — use fixed development-only secrets (**never** in production).
- ``LITESTAR_AUTH_DEMO_DATABASE_URL`` — optional SQLite URL (defaults to ``./demo_litestar_auth.db``).

Security note: JWT revocation uses an in-memory denylist (``allow_inmemory_denylist=True``), which is
only appropriate for single-process demos. Production multi-worker deployments should configure a
shared ``JWTDenylistStore`` (for example ``RedisJWTDenylistStore``).

Typical flow:

1. ``POST /auth/register`` — JSON ``{"email": "...", "password": "..."}``.
2. ``POST /auth/login`` — JSON ``{"identifier": "<email>", "password": "..."}``; read
   ``access_token`` from the response.
3. ``GET /demo/jwt-profile`` with ``Authorization: Bearer <access_token>``.
4. ``POST /api-keys`` — create a key (password step-up by default). Send JSON such as
   ``{"name": "demo", "current_password": "<password>", "scopes": ["read"]}`` with the same Bearer JWT.
5. ``GET /demo/api-key-scope-read`` with ``Authorization: Bearer <full api key value>`` or
   ``X-API-Key: <full api key value>``.

CSRF: Litestar Auth only wires Litestar ``CSRFConfig`` when at least one backend uses
:class:`~litestar_auth.authentication.transport.cookie.CookieTransport`. This demo uses bearer JWT only,
so CSRF cookies are not issued. Add a cookie backend if you need CSRF for browser sessions.

API-key scopes: With ``scope_subset_check=True`` (the default), each key scope must still be covered by
the user's roles. This demo sets ``scope_subset_check=False`` so ``has_scope("read")`` can be exercised
without seeding role rows; enable subset checks and assign roles in real apps.
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
    ApiKeyConfig,
    AuthenticationBackend,
    BaseUserManager,
    BearerTransport,
    LitestarAuth,
    LitestarAuthConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore, SQLAlchemyUserDatabase
from litestar_auth.guards import has_scope, requires_api_key
from litestar_auth.models import ApiKey, User

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_JWT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_RESET",
    "cafebabe0123456789abcdef012345678-LITESTAR_AUTH_DEMO_API_KEY_HASH",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_CSRF",
)


def _demo_secrets() -> tuple[str, str, str, str, str]:
    """Return (jwt, verify, reset, api_key_hash, csrf) secrets."""
    if os.environ.get("LITESTAR_AUTH_DEMO_INSECURE") == "1":
        warnings.warn(
            "LITESTAR_AUTH_DEMO_INSECURE=1 uses fixed secrets; never enable in production.",
            stacklevel=2,
        )
        return _INSECURE_DEFAULTS

    def _req(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            msg = (
                f"Missing {name}. Export strong secrets or set LITESTAR_AUTH_DEMO_INSECURE=1 "
                "for local demonstration only."
            )
            raise RuntimeError(msg)
        return value

    return (
        _req("LITESTAR_AUTH_JWT_SECRET"),
        _req("LITESTAR_AUTH_VERIFY_TOKEN_SECRET"),
        _req("LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"),
        _req("LITESTAR_AUTH_API_KEY_HASH_SECRET"),
        _req("LITESTAR_AUTH_CSRF_SECRET"),
    )


@dataclass(slots=True)
class _DemoRuntime:
    """Factories scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


@dataclass(slots=True, frozen=True)
class _DemoAuthSecrets:
    """Signing and hashing secrets for one demo app instance."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    api_key_hash_secret: str
    csrf_secret: str


def _build_litestar_auth_config(
    *,
    secrets: _DemoAuthSecrets,
    runtime: _DemoRuntime,
) -> LitestarAuthConfig[User, UUID]:
    bearer_backend = AuthenticationBackend[User, UUID](
        name="jwt_bearer",
        transport=BearerTransport(),
        strategy=JWTStrategy[User, UUID](
            secret=secrets.jwt_secret,
            lifetime=timedelta(minutes=30),
            subject_decoder=UUID,
            allow_inmemory_denylist=True,
        ),
    )

    class DemoUserManager(BaseUserManager[User, UUID]):
        """Demo hooks (verification is optional because ``requires_verification=False``)."""

        async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
            await super().on_after_request_verify_token(user, token)
            if user is not None and token is not None:
                logger.info(
                    "Verification token issued for %s — POST /auth/verify with the token payload",
                    user.email,
                )

    return LitestarAuthConfig[User, UUID](
        backends=(bearer_backend,),
        session_maker=runtime.session_maker,
        user_model=User,
        user_manager_class=DemoUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=secrets.verify_secret,
            reset_password_token_secret=secrets.reset_secret,
            api_key_hash_secret=secrets.api_key_hash_secret,
        ),
        csrf_secret=secrets.csrf_secret,
        api_keys=ApiKeyConfig(
            enabled=True,
            allowed_scopes=("read", "write"),
            store_factory=lambda session: SQLAlchemyApiKeyStore(session, api_key_model=ApiKey),
            environment_marker="demo",
            scope_subset_check=False,
        ),
        auth_path="/auth",
        users_path="/users",
        include_register=True,
        include_verify=True,
        include_reset_password=True,
        include_users=True,
        requires_verification=False,
        deployment_worker_count=1,
        include_openapi_security=True,
    )


@get("/health", sync_to_thread=False)
def health() -> dict[str, str]:
    """Public liveness route (no authentication).

    Returns:
        A minimal JSON payload with ``status: ok``.
    """
    return {"status": "ok"}


@get("/demo/jwt-profile", guards=[is_authenticated], sync_to_thread=False)
def demo_jwt_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Requires ``Authorization: Bearer <access_token>`` from ``POST /auth/login``.

    Returns:
        Profile fields for the authenticated user.
    """
    user = cast("User", request.user)
    return {
        "transport": "jwt_bearer",
        "user_id": str(user.id),
        "email": user.email,
        "is_verified": user.is_verified,
    }


@get(
    "/demo/api-key-scope-read",
    guards=[requires_api_key, has_scope("read")],
    sync_to_thread=False,
)
def demo_api_key_scope_read(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Requires an API key that includes the ``read`` scope.

    Returns:
        Profile fields resolved via API-key authentication.
    """
    user = cast("User", request.user)
    return {"transport": "api_key", "user_id": str(user.id), "email": user.email}


def create_app() -> Litestar:
    """Construct the demo ASGI application (SQLite schema created at startup).

    Returns:
        Configured Litestar application with auth plugin and demo routes.
    """
    jwt_s, verify_s, reset_s, ak_hash_s, csrf_s = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_litestar_auth.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    runtime = _DemoRuntime(session_maker=session_maker, engine=engine)

    demo_secrets = _DemoAuthSecrets(
        jwt_secret=jwt_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        api_key_hash_secret=ak_hash_s,
        csrf_secret=csrf_s,
    )
    auth_config = _build_litestar_auth_config(secrets=demo_secrets, runtime=runtime)

    @asynccontextmanager
    async def lifespan(_: Litestar) -> AsyncIterator[None]:
        configure_mappers()
        async with engine.begin() as connection:
            await connection.run_sync(User.metadata.create_all)
        yield
        await engine.dispose()

    return Litestar(
        route_handlers=[health, demo_jwt_profile, demo_api_key_scope_read],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(title="litestar-auth demo (JWT + API keys)", version="0.1.0"),
    )


app = create_app()
