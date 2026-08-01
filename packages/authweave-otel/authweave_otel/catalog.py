"""Versioned, immutable telemetry catalog for AuthWeave security instrumentation.

This module is pure data and stdlib only: it never imports ``opentelemetry`` so
that the span/metric contract can be asserted by golden tests without an SDK.
Renames, unit changes, or cardinality growth are breaking changes and must be
caught by :mod:`tests.test_catalog`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from authweave_core import FailureCode, SecurityOperation, SecurityOutcome

#: Instrumentation scope reported for every AuthWeave span and metric.
INSTRUMENTATION_SCOPE = "authweave"

#: Pinned stable OpenTelemetry Semantic Conventions schema URL. Upgrading this is
#: a deliberate, reviewed change gated by the golden catalog test.
SEMANTIC_CONVENTIONS_SCHEMA_URL = "https://opentelemetry.io/schemas/1.30.0"

#: Reason code substituted for any value outside the bounded vocabulary so that a
#: hostile or unknown reason can never grow metric/label cardinality.
OTHER_REASON_CODE = "_OTHER"


Operation = SecurityOperation
Outcome = SecurityOutcome


#: Outcomes that represent an expected negative decision, never a span ``ERROR``.
EXPECTED_OUTCOMES = frozenset(
    {Outcome.NOT_APPLICABLE, Outcome.INVALID, Outcome.REPLAY, Outcome.MISS, Outcome.STALE},
)
#: Outcomes that mark a span status ``ERROR`` because verification could not
#: complete safely or an invariant was violated.
ERROR_OUTCOMES = frozenset({Outcome.UNAVAILABLE, Outcome.INVARIANT_FAILURE, Outcome.ERROR})


class AttributeKey(StrEnum):
    """Namespaced ``authweave.*`` attribute keys shared by spans and metrics."""

    PROFILE = "authweave.profile"
    OPERATION = "authweave.operation"
    OUTCOME = "authweave.outcome"
    REASON_CODE = "authweave.reason_code"
    PRINCIPAL_KIND = "authweave.principal_kind"
    CREDENTIAL_KIND = "authweave.credential_kind"


class Instrument(StrEnum):
    """Supported synchronous instrument kinds in the catalog."""

    COUNTER = "counter"
    HISTOGRAM = "histogram"
    OBSERVABLE_GAUGE = "observable_gauge"


@dataclass(frozen=True, slots=True)
class MetricSpec:
    """One versioned metric definition."""

    name: str
    instrument: Instrument
    unit: str
    description: str


#: The frozen metric catalog. Prometheus/OpenMetrics suffixes (``_total`` and
#: histogram suffixes) are added by the exporter, never encoded here.
METRIC_CATALOG: tuple[MetricSpec, ...] = (
    MetricSpec(
        "authweave.authentication.attempts",
        Instrument.COUNTER,
        "{attempt}",
        "Authentication attempts by profile and outcome.",
    ),
    MetricSpec(
        "authweave.authentication.duration",
        Instrument.HISTOGRAM,
        "s",
        "Coordinator and provider authentication latency.",
    ),
    MetricSpec(
        "authweave.integrity.verifications",
        Instrument.COUNTER,
        "{verification}",
        "DPoP, HTTP signature, and webhook verification outcomes.",
    ),
    MetricSpec(
        "authweave.integrity.duration",
        Instrument.HISTOGRAM,
        "s",
        "Message integrity verification latency.",
    ),
    MetricSpec(
        "authweave.replay.decisions",
        Instrument.COUNTER,
        "{decision}",
        "Replay/nonce store decisions.",
    ),
    MetricSpec(
        "authweave.remote.operation.duration",
        Instrument.HISTOGRAM,
        "s",
        "JWKS, PAR, introspection, and token-exchange latency.",
    ),
    MetricSpec(
        "authweave.remote.operation.attempts",
        Instrument.COUNTER,
        "{attempt}",
        "Remote dependency outcomes without any URL label.",
    ),
    MetricSpec(
        "authweave.cache.requests",
        Instrument.COUNTER,
        "{request}",
        "Cache hit, miss, stale, and error outcomes.",
    ),
    MetricSpec(
        "authweave.key.age",
        Instrument.OBSERVABLE_GAUGE,
        "s",
        "Age of the current trusted key/bundle snapshot.",
    ),
    MetricSpec(
        "authweave.webhook.delivery.attempts",
        Instrument.COUNTER,
        "{attempt}",
        "Webhook delivery outcome and retry class.",
    ),
    MetricSpec(
        "authweave.webhook.delivery.duration",
        Instrument.HISTOGRAM,
        "s",
        "End-to-end webhook sender attempt latency.",
    ),
)

#: Protocol-specific reason codes layered on top of the neutral core failure
#: codes for integrity, nonce, and key-distribution decisions.
_PROTOCOL_REASON_CODES = frozenset(
    {
        "nonce_required",
        "nonce_stale",
        "digest_mismatch",
        "signature_invalid",
        "key_unknown",
        "trust_domain_rejected",
        "store_unavailable",
        "capacity_exceeded",
    },
)

#: Bounded reason-code vocabulary sourced from the neutral core failure codes plus
#: the protocol-specific codes. Any other value collapses to
#: :data:`OTHER_REASON_CODE`.
REASON_CODES: frozenset[str] = frozenset(code.value for code in FailureCode) | _PROTOCOL_REASON_CODES


def span_name(operation: Operation) -> str:
    """Return the fully qualified span name for a logical operation.

    Returns:
        The ``authweave.<operation>`` span name.
    """
    return f"{INSTRUMENTATION_SCOPE}.{operation.value}"


def normalize_reason_code(reason_code: str | None) -> str | None:
    """Collapse any out-of-vocabulary reason code to a safe bounded value.

    Returns:
        ``None`` when no reason code is supplied, the reason code when it is in
        the bounded vocabulary, otherwise :data:`OTHER_REASON_CODE`.
    """
    if reason_code is None:
        return None
    return reason_code if reason_code in REASON_CODES else OTHER_REASON_CODE
