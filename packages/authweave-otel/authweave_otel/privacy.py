"""Privacy, cardinality, and abuse-resistance policy for AuthWeave telemetry.

These limits apply before attributes leave the process. They do not replace
application-owned Trace Context boundary policy, SDK Views, or Collector
attribute filtering — they are the library's last line of defense against
cardinality growth and secret leakage through labels.
"""

from __future__ import annotations

from dataclasses import dataclass

from authweave_otel.catalog import AttributeKey

#: Maximum number of AuthWeave attributes attached to one span or metric point.
MAX_ATTRIBUTE_COUNT = 8

#: Maximum UTF-8 character length of any AuthWeave attribute value.
MAX_ATTRIBUTE_VALUE_LENGTH = 64

#: Attribute keys the facade is allowed to emit. Anything else is dropped.
ALLOWED_ATTRIBUTE_KEYS: frozenset[str] = frozenset(key.value for key in AttributeKey)

#: Baggage key allowlist. Empty by default: baggage is never extracted or
#: forwarded by AuthWeave instrumentation.
DEFAULT_BAGGAGE_KEYS_ALLOWLIST: frozenset[str] = frozenset()

#: Substrings that must never appear in emitted attribute values. Used by
#: secret-canary tests and as documentation of the denial vocabulary.
SECRET_CANARY_FRAGMENTS: frozenset[str] = frozenset({
    "Bearer ",
    "eyJ",  # JWT header prefix
    "cookie=",
    "webhook-signature",
    "dpop ",
    "-----BEGIN",
    "password=",
    "client_secret",
    "authorization_code",
    "account_number",
    "pan=",
    "cvv=",
})


#: Value substituted when a free-form attribute matches a secret canary.
REDACTED_ATTRIBUTE_VALUE = "_REDACTED"


@dataclass(frozen=True, slots=True)
class TraceContextPolicy:
    """Deployer-facing Trace Context and baggage policy defaults.

    AuthWeave never treats a remote parent as trusted identity and never uses
    baggage for authentication, authorization, replay, or idempotency decisions.
    Applications enable W3C Trace Context extraction only on explicitly
    configured boundaries.
    """

    accept_remote_parent: bool = False
    extract_baggage: bool = False
    forward_baggage: bool = False
    baggage_keys_allowlist: frozenset[str] = DEFAULT_BAGGAGE_KEYS_ALLOWLIST


#: Documented library default. Applications may construct a stricter policy;
#: loosening requires an explicit deployer decision outside this package.
DEFAULT_TRACE_CONTEXT_POLICY = TraceContextPolicy()


def truncate_attribute_value(value: str) -> str:
    """Bound one attribute value to :data:`MAX_ATTRIBUTE_VALUE_LENGTH`.

    Returns:
        The original value when it fits, otherwise a truncated prefix.
    """
    if len(value) <= MAX_ATTRIBUTE_VALUE_LENGTH:
        return value
    return value[:MAX_ATTRIBUTE_VALUE_LENGTH]


def sanitize_attributes(attributes: dict[str, str]) -> dict[str, str]:
    """Drop unknown keys, redact canaries, truncate values, and enforce the budget.

    Unknown keys are discarded. Values matching
    :data:`SECRET_CANARY_FRAGMENTS` are replaced with
    :data:`REDACTED_ATTRIBUTE_VALUE`. Remaining values longer than
    :data:`MAX_ATTRIBUTE_VALUE_LENGTH` are truncated. When more than
    :data:`MAX_ATTRIBUTE_COUNT` attributes remain after filtering, excess entries
    are dropped in insertion order so cardinality stays bounded.

    Returns:
        A new dict safe to attach to a span or metric data point.
    """
    sanitized: dict[str, str] = {}
    for key, value in attributes.items():
        if key not in ALLOWED_ATTRIBUTE_KEYS:
            continue
        if contains_secret_canary(value):
            sanitized[key] = REDACTED_ATTRIBUTE_VALUE
        else:
            sanitized[key] = truncate_attribute_value(value)
        if len(sanitized) >= MAX_ATTRIBUTE_COUNT:
            break
    return sanitized


def contains_secret_canary(value: str) -> bool:
    """Return whether ``value`` matches a documented secret-canary fragment.

    Returns:
        ``True`` when any fragment in :data:`SECRET_CANARY_FRAGMENTS` appears.
    """
    lowered = value.lower()
    return any(fragment.lower() in lowered for fragment in SECRET_CANARY_FRAGMENTS)
