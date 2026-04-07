"""Unit tests for shared Redis typing protocols."""

from __future__ import annotations

import importlib
import inspect

import pytest

import litestar_auth._redis_protocols as redis_protocols_module

pytestmark = pytest.mark.unit


def test_redis_protocol_module_executes_under_coverage_and_keeps_expected_signatures() -> None:
    """Reload the shared Redis typing module and lock the documented async method shapes."""
    reloaded_module = importlib.reload(redis_protocols_module)

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
