"""Unit tests for shared Redis typing protocols."""

from __future__ import annotations

import pytest

from litestar_auth._redis_protocols import RedisSharedAuthClient

pytestmark = pytest.mark.unit


class _RedisClient:
    async def delete(self, *names: str) -> int:
        return len(names)

    async def eval(self, script: str, numkeys: int, *keys_and_args: object) -> int:
        return len(script) + numkeys + len(keys_and_args)

    async def set(
        self,
        name: str,
        value: str,
        *,
        nx: bool = False,
        px: int | None = None,
        ex: int | None = None,
    ) -> bool:
        return bool(name and value and (nx or px is None or ex is not None))

    async def get(self, name: str, /) -> bytes | None:
        return name.encode()


def test_shared_auth_client_protocol_is_runtime_checkable() -> None:
    """Composite Redis protocol can validate shared auth clients at runtime."""
    assert isinstance(_RedisClient(), RedisSharedAuthClient)
