# ADR 0002: Webhook signing keys are isolated per endpoint, owner, and environment

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-webhooks`

## Context

Consumers receive asymmetric webhooks. Sharing one Ed25519 signing key
across independent merchants or unrelated endpoints collapses blast radius and
breaks environment isolation (sandbox vs live).

## Decision

Each onboarding binding ties **exact endpoint + merchant/owner + environment** to
its own key document (at most three public keys for active/next/retiring). Independent
merchants must not share signing keys. Sandbox and live never share keys.

## Consequences

- Library behavior: verifiers require expected environment, owner, and endpoint; key documents
  carry the same three identity bindings.
- Application ownership: key ceremony, distribution URL bootstrap, and emergency
  rotation runbooks.
- Test / vector obligations: environment/endpoint mismatch fail closed; rotation
  overlap with ≤3 keys.
- Explicit non-goals: multi-tenant shared webhook secrets, HMAC `v1` as default.

## Alternatives considered

- **One platform-wide key:** rejected — compromise of one consumer endpoint invalidates all.
- **Per-merchant shared across endpoints:** rejected for endpoint-scoped replay and
  rotation blast radius.

## Evidence

- Standard Webhooks asymmetric `v1a` profile and endpoint-bound negative vectors.
