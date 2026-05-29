"""Smoke-import ASGI factory modules under ``examples/`` with isolated SQLite URLs."""

from __future__ import annotations

import importlib
import sys
import warnings
from typing import TYPE_CHECKING, Final

import pytest
from litestar import Litestar

from examples._demo_secrets import resolve_demo_secrets

if TYPE_CHECKING:
    from pathlib import Path

_PARAMS: Final[tuple[tuple[str, dict[str, str], str], ...]] = (
    (
        "examples.demo_jwt_api_keys.app",
        {"LITESTAR_AUTH_DEMO_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_DATABASE_URL",
    ),
    (
        "examples.demo_db_token_refresh.app",
        {"LITESTAR_AUTH_DEMO_DB_TOKEN_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_DB_TOKEN_DATABASE_URL",
    ),
    (
        "examples.demo_cookie_jwt.app",
        {"LITESTAR_AUTH_DEMO_COOKIE_JWT_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_COOKIE_JWT_DATABASE_URL",
    ),
    (
        "examples.demo_api_keys_role_scopes.app",
        {"LITESTAR_AUTH_DEMO_ROLE_SCOPES_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_ROLE_SCOPES_DATABASE_URL",
    ),
    (
        "examples.demo_totp.app",
        {"LITESTAR_AUTH_DEMO_TOTP_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_TOTP_DATABASE_URL",
    ),
    (
        "examples.demo_jwt_api_keys_totp.app",
        {"LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_JWT_API_KEYS_TOTP_DATABASE_URL",
    ),
    (
        "examples.demo_cookie_jwt_totp.app",
        {"LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_INSECURE": "1"},
        "LITESTAR_AUTH_DEMO_COOKIE_JWT_TOTP_DATABASE_URL",
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
