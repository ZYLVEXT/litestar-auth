"""Demonstration app: JWT bearer + API keys + TOTP.

Combines ``demo_jwt_api_keys`` with ``TotpConfig``. Same API-key routes apply; TOTP lives under
``/auth/2fa/...``.

Important: **password-backed JWT sessions** can enroll and manage TOTP. Callers authenticated **only**
with an **API key** receive **403** on ``POST /auth/2fa/enable``, ``/enable/confirm``, ``/disable``, and
``/recovery-codes/regenerate`` (see integration tests). Use ``POST /auth/login`` JWT for 2FA enrollment.

Environment:

- Same as ``demo_jwt_api_keys`` for JWT / API-key / CSRF secrets.
- ``LITESTAR_AUTH_TOTP_PENDING_SECRET``, ``LITESTAR_AUTH_TOTP_RECOVERY_LOOKUP_SECRET``,
  ``LITESTAR_AUTH_TOTP_FERNET_KEY`` when not using insecure mode.
- ``LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_INSECURE=1`` — bundled demo secrets only.
- ``LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_DATABASE_URL`` — optional SQLite URL.

See ``examples.demo_totp.app`` and ``docs/guides/totp.md`` for the full ``/2fa`` route surface.
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
    ApiKeyConfig,
    AuthenticationBackend,
    BaseUserManager,
    BearerTransport,
    LitestarAuth,
    LitestarAuthConfig,
    TotpConfig,
    UserManagerSecurity,
    is_authenticated,
)
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore, SQLAlchemyUserDatabase
from litestar_auth.guards import has_scope, requires_api_key
from litestar_auth.models import ApiKey, User
from litestar_auth.totp import InMemoryTotpEnrollmentStore, InMemoryUsedTotpCodeStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = (
    "b54de919f43f444db66cdaa18db04af8-LITESTAR_AUTH_DEMO_JWT_KT",
    "d8f7f8e6d8c94f8c9e8d7c6b5a493827-LITESTAR_AUTH_DEMO_VERIFY_KT",
    "e9f8a7b6c5d4e3f2019384758695abcd-LITESTAR_AUTH_DEMO_RESET_KT",
    "cafebabe0123456789abcdef012345678-LITESTAR_AUTH_DEMO_API_KEY_KT",
    "0123456789abcdef0123456789abcdef-LITESTAR_AUTH_DEMO_CSRF_KT",
    "litestar-auth-demo-keys-totp-pending-secret-32!",
    "litestar-auth-demo-keys-totp-recovery-lookup-32!",
    "n5541lHAXpEa45cHCdlhYjKGfrOFxpO82UXpabcZ-uQ=",
)


@dataclass(slots=True)
class _DemoRuntime:
    """Factories scoped to one ``create_app`` call."""

    session_maker: async_sessionmaker[AsyncSession]
    engine: AsyncEngine


@dataclass(slots=True, frozen=True)
class _DemoSecrets:
    """Signing, hashing, and TOTP secrets."""

    jwt_secret: str
    verify_secret: str
    reset_secret: str
    api_key_hash_secret: str
    csrf_secret: str
    totp_pending_secret: str
    totp_recovery_lookup_secret: str
    totp_fernet_key: str


class DemoUserManager(BaseUserManager[User, UUID]):
    """Demo hooks (verification is optional because ``requires_verification=False``)."""

    async def on_after_request_verify_token(self, user: User | None, token: str | None) -> None:
        """Log issued verification tokens during local demos."""
        await super().on_after_request_verify_token(user, token)
        if user is not None and token is not None:
            logger.info(
                "Verification token issued for %s — POST /auth/verify with the token payload",
                user.email,
            )


def _demo_secrets() -> _DemoSecrets:
    """Load secrets from the environment or insecure demo defaults.

    Returns:
        Parsed secrets for one app instance.
    """
    (
        jwt_s,
        verify_s,
        reset_s,
        ak_s,
        csrf_s,
        pending_s,
        recovery_s,
        fernet_s,
    ) = resolve_demo_secrets(
        insecure_flag="LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_INSECURE",
        insecure_defaults=_INSECURE_DEFAULTS,
        secret_names=(
            "LITESTAR_AUTH_JWT_SECRET",
            "LITESTAR_AUTH_VERIFY_TOKEN_SECRET",
            "LITESTAR_AUTH_RESET_PASSWORD_TOKEN_SECRET",
            "LITESTAR_AUTH_API_KEY_HASH_SECRET",
            "LITESTAR_AUTH_CSRF_SECRET",
            "LITESTAR_AUTH_TOTP_PENDING_SECRET",
            "LITESTAR_AUTH_TOTP_RECOVERY_LOOKUP_SECRET",
            "LITESTAR_AUTH_TOTP_FERNET_KEY",
        ),
    )
    return _DemoSecrets(
        jwt_secret=jwt_s,
        verify_secret=verify_s,
        reset_secret=reset_s,
        api_key_hash_secret=ak_s,
        csrf_secret=csrf_s,
        totp_pending_secret=pending_s,
        totp_recovery_lookup_secret=recovery_s,
        totp_fernet_key=fernet_s,
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


def _totp_config(secrets: _DemoSecrets) -> TotpConfig:
    return TotpConfig(
        totp_pending_secret=secrets.totp_pending_secret,
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_enrollment_store=InMemoryTotpEnrollmentStore(),
        totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        totp_issuer="litestar-auth-demo-jwt-keys",
    )


def _api_key_config() -> ApiKeyConfig:
    return ApiKeyConfig(
        enabled=True,
        allowed_scopes=("read", "write"),
        store_factory=lambda session: SQLAlchemyApiKeyStore(session, api_key_model=ApiKey),
        environment_marker="demo",
        scope_subset_check=False,
    )


def _build_litestar_auth_config(*, secrets: _DemoSecrets, runtime: _DemoRuntime) -> LitestarAuthConfig[User, UUID]:
    return LitestarAuthConfig[User, UUID](
        backends=(_bearer_backend(secrets.jwt_secret),),
        session_maker=runtime.session_maker,
        user_model=User,
        user_manager_class=DemoUserManager,
        user_db_factory=lambda session: SQLAlchemyUserDatabase(session, user_model=User),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=secrets.verify_secret,
            reset_password_token_secret=secrets.reset_secret,
            api_key_hash_secret=secrets.api_key_hash_secret,
            totp_secret_key=secrets.totp_fernet_key,
            totp_recovery_code_lookup_secret=secrets.totp_recovery_lookup_secret,
            id_parser=UUID,
        ),
        csrf_secret=secrets.csrf_secret,
        totp_config=_totp_config(secrets),
        api_keys=_api_key_config(),
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
    """Requires Bearer JWT from ``POST /auth/login``.

    Returns:
        Profile fields for the authenticated user.
    """
    user = cast("User", request.user)
    return {
        "transport": "jwt_bearer",
        "user_id": str(user.id),
        "email": user.email,
        "totp_enrolled": user.totp_secret is not None,
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
    demo_secrets = _demo_secrets()

    db_url = os.environ.get(
        "LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_DATABASE_URL",
        f"sqlite+aiosqlite:///{Path.cwd() / 'demo_jwt_api_keys_totp.db'}",
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
        route_handlers=[health, demo_jwt_profile, demo_api_key_scope_read],
        plugins=[LitestarAuth(auth_config)],
        lifespan=[lifespan],
        openapi_config=OpenAPIConfig(
            title="litestar-auth demo (JWT + API keys + TOTP)",
            version="0.1.0",
        ),
    )


app = create_app()
