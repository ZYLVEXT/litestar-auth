# DPoP proxy-target and clock operations

DPoP binds every proof to the effective external HTTPS method and target URI. Pick
and document exactly one target profile per deployment. Never infer the target from
untrusted `Host`, `Forwarded`, or `X-Forwarded-*` input.

## Target profiles

### Direct public edge

- TLS terminates in the Litestar process or a co-located component with a fixed
  public origin.
- Construct `RequestView.target_uri` from the configured public origin plus the
  router-owned path. Strip query and fragment according to RFC 9449.
- Reject a path that is not present in the route table; do not accept an arbitrary
  absolute URI from request data.

### Controlled reverse proxy

- The edge proxy removes all inbound forwarding headers before adding its own.
- Map a deployment-owned listener/route identifier to an allowlisted public origin.
  The application consumes the identifier only from the authenticated internal hop.
- Construct the target from that mapping and the router-owned path. Do not concatenate
  client-visible forwarding values.
- Pin the proxy network or workload identity and test forged/duplicate forwarding
  headers at every release boundary.

### Service mesh or API gateway

- Bind the trusted gateway route ID and environment to one public origin in config.
- Authenticate the gateway-to-application hop. Treat mesh metadata without a verified
  workload identity as client input.
- Keep sandbox and live origin maps disjoint. A proof for one environment or route
  must not validate in another.

Dynamic tenant-controlled hosts are unsupported unless the application first maps a
validated tenant identifier to a pre-provisioned exact HTTPS origin. Wildcard suffix
checks and substring allowlists are not sufficient.

## Clock policy and incident operations

The default DPoP proof policy accepts an `iat` window of 60 seconds plus 30 seconds
of clock skew. The access-token issuer has its own explicit skew and maximum lifetime.

- Synchronize every AS, proxy, RS, and Redis host through the platform time service.
- Alert on absolute offset above 10 seconds and page before it approaches the
  configured skew. Record offset, source, and affected nodes without token values.
- Monitor `not_yet_valid` and `expired` reason-code rates by profile and environment,
  never by subject, token, proof `jti`, or JWK thumbprint.
- During drift, isolate or resynchronize the bad node first. Do not widen skew as the
  first response: a larger window increases proof pre-generation and replay exposure.
- If a temporary increase is approved, record owner, expiry, old/new values, affected
  routes, and rollback evidence. Restore the normal window after synchronization.
- Test past, future, and boundary `iat` values whenever changing proxy, VM, container,
  or time-service configuration.

## Readiness record

For each environment retain: target profile, public origin mapping, trusted hop
identity, forwarding-header stripping test, configured proof/issuer skew, observed
maximum drift, Redis durability policy, and the latest external-AS interoperability
run. Passing vectors alone is not FAPI certification.
