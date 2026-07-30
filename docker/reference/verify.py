"""Real PostgreSQL, Redis, and mock-JWKS checks for the reference stack."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import httpx
import redis.asyncio as redis
from authweave_core import PrincipalRef
from authweave_workload import (
    CredentialStatus,
    LifecycleConflictError,
    StoreConflictError,
    WorkloadLifecycleService,
)
from authweave_workload.jwks import BoundedJWKSClient
from authweave_workload.models import _certificate_metadata  # ruff: ignore[import-private-name]
from authweave_workload.sqlalchemy import SQLAlchemyWorkloadStore
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.sql import text

from litestar_auth.authentication.strategy.redis import RedisTokenStrategy

ROOT = Path(__file__).resolve().parents[2]
POSTGRES_URL = "postgresql+asyncpg://auth:auth@127.0.0.1:15432/auth"
REDIS_URL = "redis://127.0.0.1:16379/0"
MINIMUM_RECORDED_EVENTS = 5
LIFECYCLE_ACTOR = PrincipalRef("urn:reference", "verification", "automation")

if TYPE_CHECKING:
    from authweave_workload.events import SecurityEvent


def _service(store: SQLAlchemyWorkloadStore, **options: object) -> WorkloadLifecycleService:
    async def record_event(event: SecurityEvent) -> None:
        await store.session.execute(
            text(
                "INSERT INTO reference_security_event "
                "(event_type, actor_issuer, actor_subject, correlation_id) "
                "VALUES (:event_type, :actor_issuer, :actor_subject, :correlation_id)"
            ),
            {
                "actor_issuer": event.actor.issuer if event.actor is not None else None,
                "actor_subject": event.actor.subject if event.actor is not None else None,
                "correlation_id": event.correlation_id,
                "event_type": event.type.value,
            },
        )

    return WorkloadLifecycleService(  # ty: ignore[invalid-argument-type]
        store,
        actor=LIFECYCLE_ACTOR,
        correlation_id=str(uuid4()),
        event_recorder=record_event,
        **options,
    )


@dataclass
class User:
    id: UUID


class Users:
    def __init__(self, user: User) -> None:
        self.user = user

    async def get(self, user_id: UUID) -> User | None:
        return self.user if user_id == self.user.id else None


async def verify_redis() -> None:
    client = redis.from_url(REDIS_URL, decode_responses=True)
    await client.flushdb()
    user = User(uuid4())
    strategy = RedisTokenStrategy[User, UUID](
        redis=client,
        token_hash_secret="reference-redis-token-hash-secret-0123456789abcdef",
        subject_decoder=UUID,
    )
    refresh = await strategy.write_refresh_token(user)
    rotated = await strategy.rotate_refresh_token(refresh, Users(user))
    assert rotated is not None and rotated[0] == user
    assert await strategy.rotate_refresh_token(refresh, Users(user)) is None
    sessions = await strategy.list_refresh_sessions(user)
    assert sessions == [], sessions
    await client.aclose()


async def verify_postgres() -> None:
    engine = create_async_engine(POSTGRES_URL)
    async with engine.begin() as connection:
        for statement in (
            (ROOT / "packages/authweave-workload/authweave_workload/migrations/0001_postgresql.sql")
            .read_text()
            .split(";")
        ):
            if statement.strip():
                await connection.exec_driver_sql(statement)
        await connection.exec_driver_sql(
            "CREATE TABLE reference_security_event ("
            "id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
            "event_type varchar(64) NOT NULL, "
            "actor_issuer varchar(2048) NOT NULL, "
            "actor_subject varchar(512) NOT NULL, "
            "correlation_id varchar(512) NOT NULL"
            ")"
        )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)

    async with sessions() as session:
        service = _service(SQLAlchemyWorkloadStore(session), issuer="urn:reference", active_credential_limit=1)
        application, _ = await service.create_application(
            application_id="reference",
            environment="sandbox",
            owner_ref="verification",
        )
        principal, _ = await service.create_principal(
            principal_id="worker",
            application_id=application.id,
            subject="worker",
            kind="workload",
        )
        await session.commit()

    async def register(marker: str) -> bool:
        async with sessions() as session:
            service = _service(
                SQLAlchemyWorkloadStore(session),
                issuer="urn:reference",
                active_credential_limit=1,
            )
            try:
                await service.register_credential(
                    principal_id=principal.id,
                    certificate=_certificate_metadata(
                        thumbprint=marker * 43,
                        trust_anchor="local-ca",
                        not_before=now - timedelta(minutes=1),
                        not_after=now + timedelta(hours=1),
                        subject_dn=f"CN={marker}",
                        issuer_dn="CN=auth-reference-root",
                        serial_number=marker,
                    ),
                    scopes=("read",),
                    audiences=("reference",),
                    environment="sandbox",
                    now=now,
                )
                await session.commit()
                return True
            except StoreConflictError:
                await session.rollback()
                return False

    assert sorted(await asyncio.gather(register("A"), register("B"))) == [False, True]

    async with sessions() as session:
        store = SQLAlchemyWorkloadStore(session)
        service = _service(store, issuer="urn:reference", active_credential_limit=2)
        previous = (await service.list_credentials(principal.id))[0]
        replacement, _ = await service.register_credential(
            principal_id=principal.id,
            certificate=_certificate_metadata(
                thumbprint="C" * 43,
                trust_anchor="local-ca",
                not_before=now - timedelta(minutes=1),
                not_after=now + timedelta(hours=1),
                subject_dn="CN=C",
                issuer_dn="CN=auth-reference-root",
                serial_number="C",
            ),
            scopes=("read",),
            audiences=("reference",),
            environment="sandbox",
            rotation_of=previous.id,
            now=now,
        )
        await session.commit()

    async def revoke_replacement() -> None:
        async with sessions() as session:
            service = _service(SQLAlchemyWorkloadStore(session), issuer="urn:reference")
            await service.revoke_credential(replacement.id, reason="race_verification", now=now)
            await session.commit()

    async def rotate_replacement() -> bool:
        async with sessions() as session:
            service = _service(SQLAlchemyWorkloadStore(session), issuer="urn:reference")
            try:
                await service.complete_rotation(
                    new_credential_id=replacement.id,
                    previous_credential_id=previous.id,
                    now=now,
                )
                await session.commit()
                return True
            except LifecycleConflictError:
                await session.rollback()
                return False

    await asyncio.gather(revoke_replacement(), rotate_replacement())
    async with sessions() as session:
        final_replacement = await SQLAlchemyWorkloadStore(session).get_credential(replacement.id)
        assert final_replacement is not None
        assert final_replacement.status is CredentialStatus.REVOKED
        event_count = await session.scalar(text("SELECT count(*) FROM reference_security_event"))
        assert int(event_count or 0) >= MINIMUM_RECORDED_EVENTS
    await engine.dispose()


async def verify_jwks() -> None:
    async with httpx.AsyncClient(timeout=2) as client:
        response = await client.get("http://127.0.0.1:18080/.well-known/jwks.json")
    response.raise_for_status()
    payload = json.loads(response.content)
    assert isinstance(payload, dict) and len(payload["keys"]) == 1
    assert await BoundedJWKSClient(static_jwks=payload).get_key("reference", "ES256") is not None
    assert response.headers["cache-control"] == "max-age=5"


async def main() -> None:
    await verify_postgres()
    await verify_redis()
    await verify_jwks()


asyncio.run(main())
