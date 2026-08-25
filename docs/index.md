# AuthWeave 8

Six coordinated distributions separate verified identity contracts, human and workload
authentication, observability, and message-integrity tooling.

| Need | Distribution |
| --- | --- |
| Human registration, login, OAuth + PKCE, TOTP, roles, organizations, and opaque sessions in Litestar | `litestar-auth` |
| Framework-neutral authentication contracts and coordination | `authweave-core` |
| Workload lifecycle and sender-constrained Resource Server profiles | `authweave-workload` |
| Security telemetry facade | `authweave-otel` |
| Standard Webhooks signing and verification | `authweave-webhooks` |
| Payment HTTP Message Signatures | `authweave-http-signatures` |

Browser sessions and machine credentials stay on separate trust paths while sharing typed,
fail-closed AuthWeave decisions. All distributions require Python 3.12–3.14 and one exact
lockstep version.

## Start here

1. [Install](install.md) the distributions you need.
2. Follow the [quickstart](quickstart.md) for an opaque cookie session.
3. Read [credentials and tokens](credentials.md) before mixing sessions, challenge JWTs, and
   workload credentials.
4. Review [architecture](architecture.md) and [security posture](security.md).

## Security boundary

> Authentication establishes a verified principal and constraints. Your application still owns
> tenant mapping, row-level security, resource ownership, and business authorization.

AuthWeave intentionally does **not** provide unconstrained bearer login, user-owned API keys,
shared-secret machine or request-signing credentials, an OAuth Authorization Server or STS,
generic IAM, or production rollout automation. Token exchange is a strict client for an external
STS; it does not operate one.

New Litestar deployments should start on **8.0.1 or newer** (current lockstep includes the
documentation and import-boundary release). See [migrate 7.x → 8](migration-v8.md).

## Optional profiles

Merchant onboarding notes for webhooks, DPoP, HTTP Message Signatures, SPIFFE, and introspection
live under [Workload how-to](merchant/webhooks.md). Profile readiness is tracked on the
[roadmap](roadmap.md).
