"""Smoke-import ASGI factory modules under ``examples/`` with isolated SQLite URLs."""

from __future__ import annotations

import importlib
import sys
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, Mock

import pytest
from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationDecision,
    AuthenticationEvidence,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    InvariantFailure,
    PrincipalRef,
    RequestView,
    TlsPeerEvidence,
    Unavailable,
)
from litestar import Litestar

from examples._demo_secrets import resolve_demo_secrets
from examples.workload_asgi import build_asgi_authenticator
from examples.workload_headless import provision_and_authenticate

if TYPE_CHECKING:
    from pathlib import Path

    from authweave_workload.stores import WorkloadStore


type _Send = Callable[[dict[str, object]], Awaitable[None]]
type _ASGIApp = Callable[[dict[str, object], object, _Send], Awaitable[None]]


def _authenticated() -> Authenticated:
    principal = PrincipalRef("issuer", "subject", "service")
    evidence = AuthenticationEvidence("example", "example", "mtls", "issuer")
    return Authenticated(AuthenticationContext(principal, principal, evidence))


@dataclass
class _ExampleProvider:
    decision: AuthenticationDecision
    match_result: CredentialMatch = CredentialMatch.OWNED
    name: str = "example"
    profile: str = "example"

    def match(self, request: RequestView) -> CredentialMatch:
        return self.match_result

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,
    ) -> AuthenticationDecision:
        return self.decision


_PARAMS = (
    (
        "examples.demo_db_token_refresh.app",
        {"LITESTAR_AUTH_DEMO_DB_TOKEN_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_DB_TOKEN_DATABASE_URL",
    ),
)


@pytest.mark.unit
@pytest.mark.parametrize(("module_qname", "insecure_env", "database_env_var"), _PARAMS)
def test_example_apps_construct_with_isolated_sqlite(
    module_qname: str,
    insecure_env: dict[str, str],
    database_env_var: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each runnable example must build after ``create_app()`` runs at import time."""
    for key, value in insecure_env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv(database_env_var, f"sqlite+aiosqlite:///{tmp_path / 'example.sqlite3'}")

    sys.modules.pop(module_qname, None)
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r".*never enable in production\.",
            category=UserWarning,
        )
        mod = importlib.import_module(module_qname)
    assert isinstance(mod.app, Litestar)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("provider", "expected_status"),
    [
        pytest.param(_ExampleProvider(_authenticated()), 200, id="authenticated"),
        pytest.param(
            _ExampleProvider(_authenticated(), CredentialMatch.NOT_APPLICABLE),
            401,
            id="not-applicable",
        ),
        pytest.param(_ExampleProvider(Invalid(FailureCode.INVALID)), 401, id="invalid"),
        pytest.param(_ExampleProvider(Unavailable()), 503, id="unavailable"),
        pytest.param(_ExampleProvider(InvariantFailure()), 503, id="invariant-failure"),
    ],
)
async def test_workload_asgi_maps_authentication_decisions_to_fail_closed_statuses(
    provider: _ExampleProvider,
    expected_status: int,
) -> None:
    """The portability example must never return success for a failed decision."""
    app = cast("_ASGIApp", build_asgi_authenticator(provider))
    sent: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:  # ruff: ignore[unused-async] - ASGI send is awaitable
        sent.append(message)

    await app({"method": "GET", "headers": ()}, object(), send)

    assert sent[0] == {"type": "http.response.start", "status": expected_status, "headers": []}


@pytest.mark.unit
async def test_workload_headless_uses_the_durable_recorder_for_authentication_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production-shaped provider must deliver terminal events through the supplied recorder."""
    application = SimpleNamespace(id="payments", environment="production")
    principal = SimpleNamespace(id="payments-worker")
    lifecycle = Mock(
        create_application=AsyncMock(return_value=(application, object())),
        create_principal=AsyncMock(return_value=(principal, object())),
        register_credential=AsyncMock(return_value=None),
    )
    expected = object()
    provider = Mock(authenticate=AsyncMock(return_value=expected))
    provider_factory = Mock(return_value=provider)
    monkeypatch.setattr("examples.workload_headless.validate_public_certificate", Mock(return_value=object()))
    monkeypatch.setattr("examples.workload_headless.WorkloadLifecycleService", Mock(return_value=lifecycle))
    monkeypatch.setattr("examples.workload_headless.DirectMTLSProvider", provider_factory)

    def record_event(_event: object) -> None:
        return None

    result = await provision_and_authenticate(
        cast("WorkloadStore", object()),
        certificate_pem=b"certificate",
        ca_pem=b"ca",
        peer=cast("TlsPeerEvidence", object()),
        actor=PrincipalRef("issuer", "operator", "human"),
        correlation_id="correlation-id",
        event_recorder=record_event,
    )

    assert result is expected
    assert provider_factory.call_args.kwargs["event_callback"] is record_event


@pytest.mark.unit
def test_resolve_demo_secrets_uses_insecure_defaults_with_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Insecure demo mode must keep returning the fixed app-specific secrets."""
    monkeypatch.setenv("LITESTAR_AUTH_DEMO_TEST_INSECURE", "1")

    with pytest.warns(
        UserWarning,
        match=r"LITESTAR_AUTH_DEMO_TEST_INSECURE=1 uses fixed secrets; never enable in production\.",
    ):
        secrets = resolve_demo_secrets(
            insecure_flag="LITESTAR_AUTH_DEMO_TEST_INSECURE",
            insecure_defaults=("jwt", "csrf"),
            secret_names=("LITESTAR_AUTH_JWT_SECRET", "LITESTAR_AUTH_CSRF_SECRET"),
        )

    assert secrets == ("jwt", "csrf")


@pytest.mark.unit
def test_resolve_demo_secrets_reads_required_env_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Required env values are returned in the app-provided order."""
    monkeypatch.setenv("LITESTAR_AUTH_JWT_SECRET", "jwt-secret")
    monkeypatch.setenv("LITESTAR_AUTH_CSRF_SECRET", "csrf-secret")

    secrets = resolve_demo_secrets(
        insecure_flag="LITESTAR_AUTH_DEMO_TEST_INSECURE",
        insecure_defaults=("unused", "unused"),
        secret_names=("LITESTAR_AUTH_JWT_SECRET", "LITESTAR_AUTH_CSRF_SECRET"),
    )

    assert secrets == ("jwt-secret", "csrf-secret")


@pytest.mark.unit
def test_resolve_demo_secrets_raises_for_missing_required_env() -> None:
    """Missing required secrets name the env var and the app-specific insecure flag."""
    with pytest.raises(
        RuntimeError,
        match=(
            r"Missing LITESTAR_AUTH_JWT_SECRET\. Export strong secrets or set "
            r"LITESTAR_AUTH_DEMO_TEST_INSECURE=1 for local demonstration only\."
        ),
    ):
        resolve_demo_secrets(
            insecure_flag="LITESTAR_AUTH_DEMO_TEST_INSECURE",
            insecure_defaults=("unused",),
            secret_names=("LITESTAR_AUTH_JWT_SECRET",),
        )
