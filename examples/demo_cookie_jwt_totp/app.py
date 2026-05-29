"""Demonstration app: HttpOnly cookie JWT + Litestar CSRF + TOTP.

Extends ``demo_cookie_jwt`` with ``TotpConfig`` and the standard ``/auth/2fa/...`` routes.
**Note.** Enabling TOTP while ``CookieTransport.secure=False`` triggers a
:class:`~litestar_auth.totp.SecurityWarning` at startup — local demos only; production browser flows should
use HTTPS and ``secure=True``.

Environment:

- ``LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_INSECURE=1`` — fixed demo secrets.
- ``LITESTAR_AUTH_JWT_SECRET``, verify/reset/CSRF secrets, plus TOTP secrets when not insecure (same names
  as ``examples.demo_totp.app``).
- ``LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_DATABASE_URL`` — optional SQLite URL.

Browser flow: prime CSRF via ``GET /health``, then unsafe auth requests need ``X-CSRF-Token`` matching the
``litestar_auth_csrf`` cookie (see ``demo_cookie_jwt``). After login, complete TOTP enrollment and pending
login the same way as the bearer TOTP demo, still sending CSRF on POSTs.

See ``docs/guides/totp.md`` for route semantics.
"""

from __future__ import annotations

import logging
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
from litestar_auth import (
    AuthenticationBackend,
    BaseUserManager,
    CookieTransport,
    LitestarAuth,
    LitestarAuthConfig,
    TotpConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User
from litestar_auth.totp import InMemoryTotpEnrollmentStore, InMemoryUsedTotpCodeStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_COOKIE_TOTP_JWT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_COOKIE_TOTP_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_COOKIE_TOTP_RESET",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_COOKIE_TOTP_CSRF",
    "litestar-auth-demo-cookie-totp-pending-secret-32!",
    "litestar-auth-demo-cookie-totp-recovery-lookup-32!",
    "n5541lHAXpEa45cHCdlhYjKGfrOFxpO82UXpabcZ-uQ=",
)


@dataclass(slots=True)
class _DemoRuntime:
    """Async SQLAlchemy wiring scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


@dataclass(slots=True, frozen=True)
class _CookieTotpSecrets:
    """Secrets bundle for cookie JWT + CSRF + TOTP."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    csrf_secret: str
    totp_pending_secret: str
    totp_recovery_lookup_secret: str
    totp_fernet_key: str


def _demo_secrets() -> _CookieTotpSecrets:
    """Return secrets from env or insecure defaults.

    Returns:
        Parsed secrets bundle.
    """
    (
        jwt_s,
        verify_s,
        reset_s,
        csrf_s,
        pending_s,
        recovery_s,
        fernet_s,
    ) = resolve_demo_secrets(
        insecure_flag="LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_INSECURE",
        insecure_defaults=_INSECURE_DEFAULTS,
        secret_names=(
            "LITESTAR_AUTH_JWT_SECRET",
            "LITESTAR_AUTH_VERIFY_TOKEN_SECRET",
            "LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET",
            "LITESTAR_AUTH_CSRF_SECRET",
            "LITESTAR_AUTH_TOTP_PENDING_SECRET",
            "LITESTAR_AUTH_TOTP_RECOVERY_LOOKUP_SECRET",
            "LITESTAR_AUTH_TOTP_FERNET_KEY",
        ),
    )
    return _CookieTotpSecrets(
        jwt_secret=jwt_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        csrf_secret=csrf_s,
        totp_pending_secret=pending_s,
        totp_recovery_lookup_secret=recovery_s,
        totp_fernet_key=fernet_s,
    )


class DemoUserManager(BaseUserManager[User, UUID]):
    """Demo hooks with optional verification logging."""

    async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
        """Emit a log line when verify-email tokens are minted."""
        await super().on_after_request_verify_token(user, token)
        if user is not None and token is not None:
            logger.info("Verification token issued for %s", user.email)


def _build_config(*, secrets: _CookieTotpSecrets, runtime: _DemoRuntime) -> LitestarAuthConfig[User, UUID]:
    backend = AuthenticationBackend[User, UUID](
        name="jwt_cookie",
        transport=CookieTransport(
            cookie_name="demo_cookie_totp_auth",
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
            totp_secret_key=secrets.totp_fernet_key,
            totp_recovery_code_lookup_secret=secrets.totp_recovery_lookup_secret,
            id_parser=UUID,
        ),
        csrf_secret=secrets.csrf_secret,
        totp_config=TotpConfig(
            totp_pending_secret=secrets.totp_pending_secret,
            totp_pending_jti_store=InMemoryJWTDenylistStore(),
            totp_enrollment_store=InMemoryTotpEnrollmentStore(),
            totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
            totp_issuer="litestar-auth-demo-cookie-totp",
        ),
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
    """Prime CSRF cookies before unsafe auth requests.

    Returns:
        Liveness payload.
    """
    return {"status": "ok"}


@get("/demo/cookie-totp-profile", guards=[is_authenticated], sync_to_thread=False)
def cookie_totp_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Requires the JWT auth cookie issued by ``POST /auth/login``.

    Returns:
        Authenticated user snapshot including ``totp_enrolled``.
    """
    user = cast("User", request.user)
    return {
        "transport": "cookie_jwt",
        "user_id": str(user.id),
        "email": user.email,
        "totp_enrolled": user.totp_secret is not None,
    }


def create_app() -> Litestar:
    """Construct the demo ASGI application.

    Returns:
        Litestar instance with cookie JWT, CSRF, and TOTP enabled.
    """
    demo_secrets = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_cookie_jwt_totp.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    runtime = _DemoRuntime(session_maker=session_maker, engine=engine)
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
        route_handlers=[health, cookie_totp_profile],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(
            title="litestar-auth demo (cookie JWT + CSRF + TOTP)",
            version="0.1.0",
        ),
    )


app = create_app()
