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

## Credentials

Opaque browser sessions, challenge JWTs, OAuth cookies, and workload credentials are different
artifacts. Read [credentials and tokens](credentials.md) and [secrets and stores](secrets.md)
before configuring production.

New Litestar deployments should use **8.0.1 or newer**.

## Human controls

- Argon2id is the supported password hashing baseline. The default password policy accepts 15 to
  128 characters and imposes no composition rules. Unsupported stored hashes fail closed and
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

Bundled user-administration routes remain protected by the configured superuser role plus human
authentication by default. Applications with an equivalent reviewed authorization policy may set
`LitestarAuthConfig.users_admin_guards`, or `UsersControllerConfig.admin_guards` when mounting the
public controller factory directly. An explicitly empty sequence is rejected so customization
cannot accidentally publish the administrative inventory and mutation surface.

Organization administration has the same secure global-superuser controller default. A deployment
that exposes tenant administration may configure `OrganizationAdminAuthorizationPolicy` on the
public controller factory or `OrganizationAdminExtension`. Its global and path callbacks receive a
bounded operation name, and its role-delegation callback receives the target organization, target
reference, and normalized requested roles. A denial returns 403 before mutation; store-level
membership and last-privileged-member invariants still apply and cannot be replaced by callbacks.

Organization access normally requires stored membership. Deployments whose support or operations
staff must work inside an organization they do not belong to can set
`OrganizationConfig.elevated_membership_resolver`. It is consulted only after the store reports no
membership, so it can grant access to a non-member but can never widen what a member already holds,
and returning `None` — the default, since the field is unset — leaves the request without
organization context. Who qualifies, and under which organization roles, is authorization policy the
application owns; the library carries the answer and records that it was granted rather than stored.

Requests admitted this way are marked, and `current_organization_is_elevated(connection)` reports
it. Guards intentionally do not distinguish the two: an elevated principal holds exactly the
permissions of the organization roles the resolver returned, so least privilege is expressed by
returning a narrow role rather than by a parallel guard path. The distinction exists for
attribution — an operator acting inside someone else's organization is a different audit event from
a member acting in their own, and a request with no organization context reports `False`.

Application and contrib routes can compose `requires_recent_authentication()` with their normal
authorization guards. The application supplies a verifier over trusted server-side session or IdP
evidence and receives a bounded `RecentAuthenticationRequirement` containing the operation,
maximum age, and phishing-resistance requirement. Anonymous/non-human callers, a false decision,
and verifier exceptions all fail closed. The guard does not infer phishing resistance from TOTP or
an unverified OAuth claim.

The 15-character default follows the single-factor password minimum in
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#passwords). Applications
must also reject commonly used, expected, compromised, and deployment-specific passwords. The new
floor applies when a password is chosen or replaced; current-password proof remains non-empty and
bounded so accounts with a previously accepted credential can authenticate and rotate it.
Custom `msgspec` payloads use `litestar_auth.schemas.UserPasswordField` for a newly chosen password
and `CurrentPasswordField` for current-password proof.
`LitestarAuthConfig.password_validator_factory` is the deployment hook: return a synchronous
validator that raises `ValueError` for a blocked password, backed by an application-owned,
locally available, versioned corpus. Refresh that corpus out of band; do not add a remote lookup to
the authentication request path. The library intentionally ships neither a network dependency nor
a static list that would become stale.

Passwords and manually entered TOTP codes are not phishing-resistant. The native human stack makes
no NIST AAL2 or AAL3 claim. Until native WebAuthn support is explicitly added, deployments that
require phishing-resistant human authentication should require it at a reviewed external identity
provider and federate through the OAuth Authorization Code + PKCE integration. OAuth federation
does not establish an assurance level by itself; the deployment owns IdP policy and assurance
validation.

TOTP interoperability is deliberately narrow:

| Enrollment algorithm | Support | Authenticator requirement |
| --- | --- | --- |
| `SHA256` | Supported and default | Must honor `algorithm=SHA256` in the `otpauth://` URI. |
| `SHA512` | Supported | Must honor `algorithm=SHA512` in the `otpauth://` URI. |
| `SHA1` | Unsupported | Re-enroll with a supported algorithm; no downgrade is available. |

Authenticator clients that ignore the URI algorithm and silently generate SHA1 codes are
unsupported. Verify the chosen client during deployment; do not enable SHA1 for compatibility.

## Workload controls

- Certificate registration accepts public certificates only. Private-key or passphrase material
  is rejected before parsing and is never persisted or included in events. Registration accepts
  only the opaque metadata result produced by the X.509 validator.
- Client certificates require a modern key, safe signature hash, and client-auth EKU. When the
  RFC 5280-optional key-usage extension is present it must permit digital signatures. Trust anchors,
  validity, revocation freshness, TLS version, and termination boundary are explicit policy.
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

AuthWeave has no replayable login token, generic unconstrained Authorization header, user-owned
shared-secret credential, proprietary request-signing scheme, deprecated alias, or compatibility
adapter for those technologies. Migrate callers to opaque human sessions or registered X.509
workload credentials. See [migrate 6.x → 7](migration.md) and [migrate 7.x → 8](migration-v8.md).
