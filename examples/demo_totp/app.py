"""Demonstration Litestar application: JWT bearer + TOTP (2FA / authenticator OTP).

In this library, "OTP" for second factor means **TOTP** (RFC 6238): codes from an app such as
Google Authenticator or Bitwarden. There is **no** bundled SMS or email OTP transport.

Plugin-owned HTTP routes (here ``{auth_path}`` is ``/auth``):

- ``POST .../2fa/enable`` — start enrollment (step-up password by default).
- ``POST .../2fa/enable/confirm`` — finish enrollment; response includes one-time ``recovery_codes``.
- ``POST .../2fa/verify`` — complete login after ``202`` / ``pending_token``; ``code`` may be a **TOTP code
  or an unused recovery code** (same JSON field).
- ``POST .../2fa/disable`` — turn off 2FA using a valid TOTP code or unused recovery code (authenticated).
- ``POST .../2fa/recovery-codes/regenerate`` — replace recovery codes; with default
  ``totp_enable_requires_password=True`` send ``{"current_password": "..."}``.

See ``docs/guides/totp.md`` and ``docs/configuration/totp.md`` for enrollment-token behavior, pending-token
client binding, replay stores, and rate limits.

**Authorization nuance:** enrollment, confirm, disable, and recovery-code rotation require a normal
password-backed session. Callers authenticated **only** with an API key receive **403** on those routes.

**Not exercised in this demo** (defaults apply): ``TotpConfig.totp_backend_name`` (which backend mints tokens
after verify when multiple backends exist), ``totp_algorithm`` (``SHA256`` / ``SHA512``),
``totp_pending_require_client_binding``, ``LitestarAuthConfig.rate_limit_config`` TOTP slots, and Fernet
``UserManagerSecurity.totp_secret_keyring`` instead of a single ``totp_secret_key``. Advanced integrations can
use ``create_totp_controller(...)`` manually instead of the plugin wiring.

Environment variables:

- ``LITESTAR_AUTH_JWT_SECRET`` — JWT signing secret (HS256).
- ``LITESTAR_AUTH_VERIFY_TOKEN_SECRET`` / ``LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET`` —
  short-lived account-token secrets.
- ``LITESTAR_AUTH_CSRF_SECRET`` — CSRF signing material used by the plugin middleware.
- ``LITESTAR_AUTH_TOTP_PENDING_SECRET`` — HMAC secret for pending-login tokens between password and TOTP.
- ``LITESTAR_AUTH_TOTP_RECOVERY_LOOKUP_SECRET`` — pepper for recovery-code lookup indexes.
- ``LITESTAR_AUTH_TOTP_FERNET_KEY`` — Fernet key string (from ``Fernet.generate_key().decode()``)
  used to encrypt persisted TOTP secrets.
- ``LITESTAR_AUTH_DEMO_TOTP_INSECURE=1`` — use fixed development-only secrets (**never** in production).
- ``LITESTAR_AUTH_DEMO_TOTP_DATABASE_URL`` — optional SQLite URL (defaults to ``./demo_litestar_auth_totp.db``).

Security note: TOTP pending JWT replay protection, enrollment staging, and used-code replay protection use
**in-memory** stores here. That is only valid for single-process demos; production should use shared Redis
(or equivalent) implementations from ``litestar_auth.totp`` and ``JWTDenylistStore``.

Typical flow:

1. ``POST /auth/register`` — JSON ``{"email": "...", "password": "..."}``.
2. ``POST /auth/login`` — obtain ``access_token``.
3. ``POST /auth/2fa/enable`` — JSON ``{"password": "<password>"}`` with Bearer JWT; response includes
   ``secret``, ``uri`` (``otpauth://totp/...``), and ``enrollment_token``.
4. Enter the secret or scan ``uri`` in your authenticator app; then ``POST /auth/2fa/enable/confirm``
   with ``enrollment_token`` and current ``code``. Save ``recovery_codes`` from the response.
5. ``POST /auth/login`` again — response ``202`` with ``pending_token`` when TOTP is active.
6. ``POST /auth/2fa/verify`` — JSON ``{"pending_token": "...", "code": "<TOTP or recovery>"}`` for tokens.
7. ``GET /demo/totp-profile`` — Bearer JWT; shows whether TOTP is enrolled (``totp_enrolled``).

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
    BearerTransport,
    LitestarAuth,
    LitestarAuthConfig,
    TotpConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore, JWTStrategy
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import User
from litestar_auth.totp import InMemoryTotpEnrollmentStore, InMemoryUsedTotpCodeStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_JWT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_VERIFY",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_RESET",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_CSRF",
    "litestar-auth-demo-totp-pending-secret-32ch!",
    "litestar-auth-demo-totp-recovery-lookup-sec!",
    # Demo-only Fernet key (rotate if you ever reuse outside local demos).
    "n5541lHAXpEa45cHCdlhYjKGfrOFxpO82UXpabcZ-uQ=",
)


@dataclass(slots=True)
class _DemoRuntime:
    """Factories scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


@dataclass(slots=True, frozen=True)
class _DemoTotpSecrets:
    """Secrets for JWT, CSRF, and TOTP flows."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    csrf_secret: str
    totp_pending_secret: str
    totp_recovery_lookup_secret: str
    totp_fernet_key: str


class DemoTotpUserManager(BaseUserManager[User, UUID]):
    """Demo hooks (verification is optional because ``requires_verification=False``)."""

    async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
        """Log issued verification tokens during local demos."""
        await super().on_after_request_verify_token(user, token)
        if user is not None and token is not None:
            logger.info(
                "Verification token issued for %s — POST /auth/verify with the token payload",
                user.email,
            )


def _demo_secrets() -> _DemoTotpSecrets:
    """Load secrets from the environment or fixed insecure defaults.

    Returns:
        Parsed demo secrets bundle for JWT, CSRF, and TOTP flows.
    """
    if os.environ.get("LITESTAR_AUTH_DEMO_TOTP_INSECURE") == "1":
        warnings.warn(
            "LITESTAR_AUTH_DEMO_TOTP_INSECURE=1 uses fixed secrets; never enable in production.",
            stacklevel=2,
        )
        (
            jwt_s,
            verify_s,
            reset_s,
            csrf_s,
            pending_s,
            recovery_s,
            fernet_s,
        ) = _INSECURE_DEFAULTS
        return _DemoTotpSecrets(
            jwt_secret=jwt_s,
            verify_secret=verify_s,
            reset_secret=reset_s,
            csrf_secret=csrf_s,
            totp_pending_secret=pending_s,
            totp_recovery_lookup_secret=recovery_s,
            totp_fernet_key=fernet_s,
        )

    def _req(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            msg = (
                f"Missing {name}. Export strong secrets or set LITESTAR_AUTH_DEMO_TOTP_INSECURE=1 "
                "for local demonstration only."
            )
            raise RuntimeError(msg)
        return value

    return _DemoTotpSecrets(
        jwt_secret=_req("LITESTAR_AUTH_JWT_SECRET"),
        verify_secret=_req("LITESTAR_AUTH_VERIFY_TOKEN_SECRET"),
        reset_secret=_req("LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET"),
        csrf_secret=_req("LITESTAR_AUTH_CSRF_SECRET"),
        totp_pending_secret=_req("LITESTAR_AUTH_TOTP_PENDING_SECRET"),
        totp_recovery_lookup_secret=_req("LITESTAR_AUTH_TOTP_RECOVERY_LOOKUP_SECRET"),
        totp_fernet_key=_req("LITESTAR_AUTH_TOTP_FERNET_KEY"),
    )


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


def _totp_config(secrets: _DemoTotpSecrets) -> TotpConfig:
    return TotpConfig(
        totp_pending_secret=secrets.totp_pending_secret,
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        totp_issuer="litestar-auth-demo",
    )


def _build_litestar_auth_config(
    *,
    secrets: _DemoTotpSecrets,
    runtime: _DemoRuntime,
) -> LitestarAuthConfig[User, UUID]:
    return LitestarAuthConfig[User, UUID](
        backends=(_bearer_backend(secrets.jwt_secret),),
        session_maker=runtime.session_maker,
        user_model=User,
        user_manager_class=DemoTotpUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=secrets.verify_secret,
            reset_password_token_secret=secrets.reset_secret,
            totp_secret_key=secrets.totp_fernet_key,
            totp_recovery_code_lookup_secret=secrets.totp_recovery_lookup_secret,
            id_parser=UUID,
        ),
        csrf_secret=secrets.csrf_secret,
        totp_config=_totp_config(secrets),
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


@get("/demo/totp-profile", guards=[is_authenticated], sync_to_thread=False)
def demo_totp_profile(request: Request[User, UUID, Any]) -> dict[str, Any]:
    """Authenticated snapshot: whether TOTP is enrolled (secret column populated).

    Returns:
        User id, email, and ``totp_enrolled`` (boolean).
    """
    user = cast("User", request.user)
    return {
        "transport": "jwt_bearer",
        "user_id": str(user.id),
        "email": user.email,
        "totp_enrolled": user.totp_secret is not None,
    }


def create_app() -> Litestar:
    """Construct the demo ASGI application (SQLite schema created at startup).

    Returns:
        Configured Litestar application with auth plugin and demo routes.
    """
    demo_secrets = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_TOTP_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_litestar_auth_totp.db'}",
    )
    engine = create_async_engine(db_url, echo=False)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    runtime = _DemoRuntime(session_maker=session_maker, engine=engine)
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
        route_handlers=[health, demo_totp_profile],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(title="litestar-auth demo (JWT + TOTP)", version="0.1.0"),
    )


app = create_app()
