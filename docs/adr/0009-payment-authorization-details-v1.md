# ADR 0009: Payment authorization details profile v1

- **Status:** accepted
- **Date:** 2026-08-01
- **Package:** `authweave-workload`

## Context

RFC 9396 transports fine-grained authorization as an array of type-defined
JSON objects. Its generic fields do not define payment semantics, monetary
canonicalization, scope consistency, or authority narrowing. Accepting an
open object at the Resource Server would move those security decisions into
every route handler.

## Decision

1. Profile v1 uses the collision-resistant type identifier
   `https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1`.
2. Each entry has exactly `type`, `actions`, `locations`,
   `instructedAmount`, and optional `identifier`. Unknown fields are rejected.
3. Actions are limited to `initiate`, `status`, `cancel`, and `refund`.
   Locations are exact HTTPS URIs provisioned by the issuer profile.
4. `instructedAmount` contains an allowlisted three-letter currency and a
   positive canonical decimal string with exactly two fractional digits.
   Issuer policy supplies a maximum amount for every allowed currency.
5. Issuer policy maps coarse credential scopes to actions. Every action in an
   authorization detail must be covered by the verified scopes; details never
   widen scope authority.
6. A requested child detail is narrower only when one granted parent contains
   all its actions and locations, uses the same currency, and has an equal or
   greater amount ceiling.
7. JWT, plain introspection, and RFC 9701 signed introspection populate the
   existing bounded immutable `AuthenticationEvidence.authorization_details`
   field only after this profile validates successfully.
8. AuthWeave exposes interpretation helpers but does not approve a payment.
   Route handlers still own account state, beneficiary, fraud, idempotency,
   ledger, and transaction decisions.

## Consequences

- Mixed or unknown authorization-detail types fail closed for this issuer
  profile.
- The same parser protects JWT and introspection paths, avoiding schema drift.
- Adding currencies with other minor-unit exponents or new payment fields
  requires a new profile version and ADR.

## Alternatives considered

- **Arbitrary RFC 9396 objects:** rejected; RFC 9396 delegates semantics to the
  selected type.
- **Scopes only:** rejected; scopes cannot bind exact payment location and
  monetary ceiling.
- **Business authorization in the library:** rejected; verified OAuth authority
  is input to, not a replacement for, the payment domain decision.

## Evidence

- RFC 9396 Sections 2, 2.1, 2.2, 3.1, 9, and 12.
- Package tests cover malformed input, bounds, currencies, scope consistency,
  narrowing, JWT, plain/signed introspection, and authority-widening rejection.
