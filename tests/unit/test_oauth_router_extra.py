"""Extra tests for the OAuth router helpers."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth import router
from litestar_auth.oauth.router import load_httpx_oauth_client

pytestmark = pytest.mark.unit


def test_load_httpx_oauth_client_re_raises_non_httpx_module_not_found() -> None:
    """ModuleNotFoundError for non-httpx_oauth modules should propagate unchanged."""
    with pytest.raises(ModuleNotFoundError):
        load_httpx_oauth_client("nonexistent.module.Class")


def test_load_httpx_oauth_client_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful path instantiates and returns the configured client class."""

    @dataclass
    class FakeClient:
        foo: int

    @dataclass
    class FakeModule:
        """Stand-in module holding an OAuth client type."""

        def __init__(self) -> None:
            self.FakeClient = FakeClient

    def import_module(name: str) -> object:
        if name == "litestar_auth.tests.unit.fake_oauth_module":
            return FakeModule()
        raise ConfigurationError(name)

    monkeypatch.setattr(router, "import_module", import_module)

    foo_value = 123
    client = load_httpx_oauth_client("litestar_auth.tests.unit.fake_oauth_module.FakeClient", foo=foo_value)
    assert isinstance(client, FakeClient)
    assert client.foo == foo_value
