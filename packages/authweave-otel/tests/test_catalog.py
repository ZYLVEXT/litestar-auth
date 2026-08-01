"""Golden catalog tests guarding the versioned span and metric contract."""

from __future__ import annotations

import pytest
from authweave_otel import (
    ERROR_OUTCOMES,
    EXPECTED_OUTCOMES,
    INSTRUMENTATION_SCOPE,
    METRIC_CATALOG,
    OTHER_REASON_CODE,
    Instrument,
    Operation,
    Outcome,
    normalize_reason_code,
    span_name,
)

pytestmark = pytest.mark.unit


def test_instrumentation_scope_is_stable() -> None:
    assert INSTRUMENTATION_SCOPE == "authweave"


def test_span_names_are_namespaced() -> None:
    assert span_name(Operation.AUTHENTICATE) == "authweave.authenticate"
    assert span_name(Operation.OAUTH_INTROSPECT) == "authweave.oauth.introspect"


def test_metric_catalog_is_frozen() -> None:
    catalog = {spec.name: (spec.instrument.value, spec.unit) for spec in METRIC_CATALOG}

    assert catalog == {
        "authweave.authentication.attempts": ("counter", "{attempt}"),
        "authweave.authentication.duration": ("histogram", "s"),
        "authweave.integrity.verifications": ("counter", "{verification}"),
        "authweave.integrity.duration": ("histogram", "s"),
        "authweave.replay.decisions": ("counter", "{decision}"),
        "authweave.remote.operation.duration": ("histogram", "s"),
        "authweave.remote.operation.attempts": ("counter", "{attempt}"),
        "authweave.cache.requests": ("counter", "{request}"),
        "authweave.key.age": ("observable_gauge", "s"),
        "authweave.webhook.delivery.attempts": ("counter", "{attempt}"),
        "authweave.webhook.delivery.duration": ("histogram", "s"),
    }


def test_metric_names_have_no_prometheus_suffixes() -> None:
    for spec in METRIC_CATALOG:
        assert not spec.name.endswith("_total")
        if spec.instrument is Instrument.HISTOGRAM:
            assert not spec.name.endswith(("_bucket", "_sum", "_count"))


def test_expected_and_error_outcomes_are_disjoint() -> None:
    assert EXPECTED_OUTCOMES.isdisjoint(ERROR_OUTCOMES)
    assert Outcome.UNAVAILABLE in ERROR_OUTCOMES
    assert Outcome.INVALID in EXPECTED_OUTCOMES


@pytest.mark.parametrize(
    ("reason_code", "expected"),
    [
        (None, None),
        ("expired", "expired"),
        ("totally-made-up", OTHER_REASON_CODE),
    ],
)
def test_reason_code_normalization(reason_code: str | None, expected: str | None) -> None:
    assert normalize_reason_code(reason_code) == expected
