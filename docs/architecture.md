# Architecture

AuthWeave 8 keeps the same trust-boundary contract introduced for the six-distribution workspace:
opaque human sessions, separate workload profiles, and fail-closed provider coordination.

## Package topology

The dependency direction is intentionally one-way:

```text
authweave-core
├── litestar-auth
├── authweave-workload
│   └── authweave-workload[litestar] → litestar-auth Extension SDK v2
├── authweave-otel
├── authweave-webhooks
└── authweave-http-signatures
```

`authweave-core` contains principal, evidence, context, request, decision, replay,
observation, and coordinator contracts. It imports no framework, storage, or cryptographic
implementation. `litestar-auth` owns supported human authentication and the single Litestar
middleware. `authweave-workload` owns service application, service/workload/agent principal,
public X.509 credential lifecycle, and sender-constrained Resource Server integrations.
`authweave-otel` implements the optional observer seam. `authweave-webhooks` and
`authweave-http-signatures` are message-integrity packages, not authentication providers.

That import direction is checked by import-linter (`uv run lint-imports`, also part of
`just check`). `authweave-core` must not import Litestar, SQLAlchemy, Redis, PyJWT, or
cryptography. Persistence protocols in `litestar_auth.db` must not import SQLAlchemy; the
adapter is `litestar_auth.db.sqlalchemy`. The `authweave-workload` package root must not
import extra modules. Webhooks, HTTP signatures, and OTel must not import each other.

All distributions use one exact lockstep version, require Python
`>=3.12,<3.15`, and reject mixed workspace versions. Optional workload
implementations remain behind `sqlalchemy`, `mtls`, `jwt`, `dpop`, `spiffe`,
`introspection`, `token-exchange`, `redis`, and `litestar` extras; a base import does not load
them.

## Request vocabulary and routing

A `PrincipalRef` identifies the verified human, service, workload, or agent.
`AuthenticationEvidence` records the verified method and bounded properties.
`AuthenticationContext` separates subject, actor, delegation, and request
projection. It never contains a raw credential, access token, or private key.

Every route resolves exactly one provider profile before verification. Credential ownership is
`NOT_APPLICABLE`, `OWNED`, or `AMBIGUOUS`; ambiguity fails closed. Providers return `Authenticated`,
`NotApplicable`, `Invalid`, `Unavailable`, or `InvariantFailure`. Invalid, unavailable, and
invariant results are terminal and never trigger a fallback provider.

Authentication establishes identity and verified constraints. Tenant mapping,
RLS, resource ownership, and business authorization remain application-owned.

## Human and machine boundary

Human routes use opaque server-side database or Redis sessions in secure cookies. Challenge JWTs
and OAuth cookies are separate artifacts; see [credentials and tokens](credentials.md). Machine
routes use exactly one configured profile: direct mTLS, mTLS-bound JWT, DPoP-bound JWT, SPIFFE
X.509-SVID, or mTLS/DPoP-bound opaque-token introspection. Sender constraints and replay policy are
profile specific. Principal-kind guards are invariant checks, so similar attributes cannot make a
human credential satisfy a machine route or vice versa.

## Organization administration contracts

`litestar_auth.contrib.organization_admin.OrganizationAdmin` is the backend-neutral operations
service for organization, membership, and invitation workflows. It depends only on the public
`litestar_auth.db.BaseOrganizationStore` protocol; the SQLAlchemy adapter is one implementation,
not part of the service contract.

Invitation acceptance is deliberately one persistence operation. Every organization store must
implement `finalize_invitation_acceptance(...)` so consuming a pending invitation and creating its
membership either both succeed or both roll back. The service does not fall back to a split
`consume_invitation(...)` then `add_membership(...)` sequence because that can strand a consumed
invitation without a membership.

Applications that need the canonical flat-role representation import `normalize_role_name` or
`normalize_roles` from `litestar_auth.roles`. Both apply trim, Unicode NFKC normalization,
lowercase conversion, deduplication, and deterministic sorting where relevant.

```python
from litestar_auth.contrib.organization_admin import OrganizationAdmin
from litestar_auth.db import MembershipData
from litestar_auth.roles import normalize_roles

admin = OrganizationAdmin(store=organization_store)
membership_data = MembershipData(
    organization_id=organization_id,
    user_id=user_id,
    roles=normalize_roles(["Member"]),
)
membership = await organization_store.finalize_invitation_acceptance(
    invitation_id,
    consumed_at=accepted_at,
    membership_data=membership_data,
)
```

The store implementation owns the transaction or equivalent compare-and-set boundary behind that
method. `None` means the invitation was no longer pending and unexpired; validation failures raise
`ValueError`. Applications normally call `admin.accept_invitation(...)`, while custom
registration flows may use the public store operation after performing their own authenticated
token and invitee checks.

## Observation and message-integrity boundaries

`authweave-otel` implements `SecurityObserver`; observer failures never change authentication,
authorization, replay, or event-delivery decisions. Applications own the OpenTelemetry SDK,
exporters, sampling, and retention.

Standard Webhooks and payment HTTP Message Signatures verify bounded raw messages after the caller
trust boundary is selected. They do not establish a human/workload principal, replace business
idempotency, or own key custody and outbound network policy.

## ADR: external Authorization Server

AuthWeave is an OAuth relying party and Resource Server, not an Authorization Server. Human OAuth
uses Authorization Code with PKCE. mTLS-bound workload access tokens come from an explicitly trusted
external issuer and are verified against the documented RFC 9068/RFC 8705 profile; DPoP-bound access
tokens use the separate RFC 9449 profile.

`authweave-workload` also provides bounded Resource Server integrations for opaque-token
introspection, DPoP, SPIFFE identity, and certificate-bound access tokens. Its RFC 8693 token
exchange is a strict outbound client, not a Resource Server provider. The optional FAPI message-
signing client belongs to `litestar-auth` human OAuth. None of these integrations issues credentials
or implements an Authorization Server. Replay stores, issuer/key policy, outbound egress, and
application authorization hooks remain mandatory deployment configuration.

This decision keeps key issuance, federation, consent, and token-service
operations at a dedicated trust service while the packages remain focused on
authentication, certificate lifecycle, and verified request context.

## Removed profiles

AuthWeave deliberately has no deprecated aliases, request-authentication bearer strategy,
user-owned API key, proprietary HMAC request signing, ordered compatibility authenticator, or
`None`-based failure path. The [6.x → 7 migration guide](migration.md), [7.x → 8 migration
guide](migration-v8.md), and read-only removal audit are the only compatibility aids; runtime
adapters for removed profiles do not exist.
