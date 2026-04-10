"""Unit tests for shared Redis typing protocols."""

from __future__ import annotations

import importlib
import inspect
from typing import get_type_hints

import pytest

import litestar_auth._redis_protocols as redis_protocols_module
import litestar_auth.contrib.redis as redis_contrib_module

pytestmark = pytest.mark.unit


def test_redis_protocol_module_executes_under_coverage_and_keeps_expected_signatures() -> None:
    """Lock internal Redis protocol signatures plus the public contrib typing entrypoint."""
    reloaded_module = importlib.reload(redis_protocols_module)
    preset_hints = get_type_hints(redis_contrib_module.RedisAuthPreset, include_extras=True)

    assert reloaded_module.RedisDeleteClient.__name__ == "RedisDeleteClient"
    assert tuple(inspect.signature(reloaded_module.RedisConditionalSetClient.set).parameters) == (
        "self",
        "name",
        "value",
        "nx",
        "px",
    )
    assert tuple(inspect.signature(reloaded_module.RedisSetMembershipClient.smembers).parameters) == (
        "self",
        "name",
    )
    assert tuple(inspect.signature(reloaded_module.RedisScanClient.scan_iter).parameters) == (
        "self",
        "match",
        "count",
        "_type",
        "kwargs",
    )
    assert redis_contrib_module.RedisAuthClientProtocol.__name__ == "RedisAuthClientProtocol"
    assert tuple(inspect.signature(redis_contrib_module.RedisAuthClientProtocol.eval).parameters) == (
        "self",
        "script",
        "numkeys",
        "keys_and_args",
    )
    assert tuple(inspect.signature(redis_contrib_module.RedisAuthClientProtocol.set).parameters) == (
        "self",
        "name",
        "value",
        "nx",
        "px",
    )
    assert tuple(inspect.signature(redis_contrib_module.RedisAuthClientProtocol.get).parameters) == (
        "self",
        "name",
    )
    assert tuple(inspect.signature(redis_contrib_module.RedisAuthClientProtocol.setex).parameters) == (
        "self",
        "name",
        "time",
        "value",
    )
    assert preset_hints["redis"] is redis_contrib_module.RedisAuthClientProtocol
