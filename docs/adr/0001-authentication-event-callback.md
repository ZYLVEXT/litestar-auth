# ADR 0001: Authentication event callback is mandatory

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-core`, `authweave-workload`

## Context

Machine authentication decisions must produce durable, application-owned security
events for audit and operations. OpenTelemetry spans/metrics are sampled,
non-authoritative, and must never substitute for that delivery path.

Today `DirectMTLSProvider` and JWT providers accept an optional `event_callback`.
Optional delivery invites silent loss of authentication evidence when an integrator
forgets to wire the callback.

## Decision

When a provider is constructed with a configured authentication/security event
callback, invoking that callback is **mandatory** for every terminal authentication
outcome on the protected path. A raised or returned failure from the callback is
mapped to a typed `Unavailable` decision (fail closed).

Best-effort delivery is **not** a library mode. Applications that need absorb-and-
observe semantics must supply their own wrapper callback that catches, records, and
acknowledges success to AuthWeave.

Absence of a callback remains allowed only for explicitly non-audited local fixtures;
production Litestar adapters require a callback unless `allow_unaudited=True` is set.

Telemetry observers (`authweave-otel`) stay independent: their internal errors never
change the authentication result and never replace the mandatory callback.

## Consequences

- Library behavior: callback exceptions/`Unavailable` from delivery → authentication
  `Unavailable`; no ordered fallback to another provider.
- Application ownership: wrappers own retry, buffering, and routing of events.
- Test / vector obligations: success path with sync and async callbacks; callback
  failure → `Unavailable`; telemetry fault does not mask callback failure.
- Explicit non-goals: library-owned outbox, SIEM export, or best-effort default.

## Alternatives considered

- **Best-effort library swallow:** rejected — hides audit loss and violates fail-closed
  posture.
- **Always-required callback constructor arg today:** deferred as a coordinated
  breaking change across providers and tests; this ADR freezes the semantic rule first.

## Implementation

- Shared delivery helper: `authweave_workload.events.deliver_security_event` invokes the
  configured callback and raises the internal `EventDeliveryError` when the callback raises or
  returns `Unavailable`.
- Every workload provider (`DirectMTLSProvider`, `MTLSBoundJWTProvider`, `DPoPBoundJWTProvider`,
  `SPIFFEProvider`, `MTLSBoundIntrospectionProvider`, `DPoPBoundIntrospectionProvider`) wraps its
  `authenticate` and maps `EventDeliveryError` to a fail-closed `Unavailable` decision.
- Production narrowing lives in `WorkloadAuthExtension.validate()`, which rejects a provider
  configuration that omits `event_callback` unless `allow_unaudited=True` is set for a local
  fixture.

## Evidence

- Delivery helper: `authweave_workload.events.deliver_security_event`.
- Migration tests: `packages/authweave-workload/tests/test_direct_mtls_negative_matrix.py`
  (`test_direct_mtls_callback_exception_fails_closed`,
  `test_direct_mtls_callback_returning_unavailable_fails_closed`) and
  `packages/authweave-workload/tests/test_litestar_integration.py`
  (`test_workload_extension_requires_mandatory_event_callback_in_production`).
