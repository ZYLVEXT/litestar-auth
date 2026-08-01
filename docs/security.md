# Security posture

## Supported trust profiles

Human requests use opaque database or Redis sessions in secure cookies. Machine routes select
exactly one configured profile: direct TLS 1.3 mutual authentication, an mTLS-bound JWT, a
DPoP-bound JWT, SPIFFE X.509-SVID, or mTLS/DPoP-bound opaque-token introspection. Each sender-
constrained profile validates its exact certificate or DPoP binding. Credential ownership is
resolved before verification; duplicate or mixed presentations are rejected.

`Invalid`, `Unavailable`, and invariant failures are terminal. They never become anonymous and do
not start another provider. Route policy permits at most one provider profile, which prevents
authentication downgrade by construction.

## Human controls

- Argon2id is the supported password hashing baseline. Unsupported stored hashes fail closed and
  require reset.
- Access tokens are opaque, keyed-digest indexed, bounded, and server-side. Optional refresh tokens
  use the same storage posture.
- When refresh is enabled, rotation is atomic and reuse of a consumed refresh token revokes the
  active chain.
- Cookies are `Secure` and `HttpOnly` by default; unsafe requests require CSRF protection.
- TOTP pending material and provider OAuth tokens use explicit encrypted-at-rest policies.
- OAuth is relying-party Authorization Code + PKCE only. This project is not an Authorization
  Server.
- Account verification, reset, invitation, and TOTP enrollment artifacts are narrowly scoped,
  time-bounded, and replay protected. They are not general request authentication credentials.
- Plugin-managed verification and password-reset routes use an atomic replay store by default;
  multi-worker deployments must use a shared durable implementation such as Redis.
- Public authentication and TOTP endpoints use bounded rate-limit presets by default. Deployments
  with more than one worker must use shared rate-limit and account-state stores.

## Workload controls

- Certificate registration accepts public certificates only. Private-key or passphrase material
  is rejected before parsing and is never persisted or included in events. Registration accepts
  only the opaque metadata result produced by the X.509 validator.
- Client certificates require a modern key, safe signature hash, digital-signature key usage, and
  client-auth EKU. Trust anchors, validity, revocation freshness, TLS version, and termination
  boundary are explicit policy.
- Persistence atomically resolves application, principal, and credential state. Disabling any
  owner or revoking a credential terminates authentication.
- External JWT issuers have explicit HTTPS JWKS sources or static keys, bounded response/key/cache
  limits, no redirects, an asymmetric algorithm allowlist, and issuer/audience/type/time validation.
  mTLS-bound JWTs additionally require certificate binding; DPoP-bound JWTs require key binding.
- DPoP proofs bind method, effective external HTTPS target, access-token hash, key thumbprint, and a
  shared replay claim. SPIFFE accepts only validated X.509-SVID projections from an allowlisted
  boundary or the bounded Workload API snapshot lifecycle.
- Introspection clients use explicit endpoints, bounded responses/timeouts, no redirects, client
  authentication, and mandatory mTLS or DPoP confirmation. Outbound token exchange requires exact
  endpoint, audience/resource, requested-token, narrowing, and response limits; it never becomes an
  inbound authentication fallback.
- Subject, actor, and delegation chain are distinct. RFC 8693 actor claims are accepted only when
  issuer policy and an application authorization hook both allow them.
- Verified tenant or business authorization remains application-owned.
- Every lifecycle mutation requires an attributed, correlated event recorder. Production recorders
  write through the same database unit of work; audit delivery may use an application outbox after
  commit.
- Production workload providers require a terminal-outcome event callback. Callback failure returns
  `Unavailable`; optional OpenTelemetry observation never substitutes for durable event delivery.

## Message integrity and telemetry

- Standard Webhooks binds environment, owner, endpoint, public-key validity, timestamp, body size,
  signature count, and duplicate-delivery state before payload parsing. Sender egress uses an exact
  endpoint allowlist and remains application-network-policy owned.
- Payment HTTP Message Signatures verify RFC 9530 content digests, RFC 9421 signature policy,
  authenticated-principal key binding, and nonce replay. They do not replace authentication or
  business idempotency.
- `authweave-otel` allowlists and bounds attributes. SDK/exporter failure never changes an
  authentication, replay, authorization, or audit-delivery decision.

## Reference boundary

[`docker/reference/compose.yml`](https://github.com/ZYLVEXT/litestar-auth/blob/main/docker/reference/compose.yml)
demonstrates TLS 1.3 client
authentication and CRL enforcement at Envoy, a Unix-domain-socket hop, sanitized projected
headers consumed by the real Litestar middleware/provider pipeline, PostgreSQL persistence, Redis
human sessions, and a controlled JWKS service. The application derives revocation freshness from
the locally mounted CRL rather than trusting a request header. A TCP proxy-to-application hop
requires equivalent authenticated transport and an explicit allowlist.

Run `sh docker/reference/verify.sh`. Production deployment still requires an independent review of
the chosen proxy, CA/CRL distribution, external issuer, JWKS path, database policy, secret manager,
network boundaries, and durable event delivery.

## Explicit removals

Version 7 has no replayable login token, generic unconstrained Authorization header, user-owned
shared-secret credential, proprietary request-signing scheme, deprecated alias, or compatibility
adapter for those technologies. Migrate callers to opaque human sessions or registered X.509
workload credentials.
