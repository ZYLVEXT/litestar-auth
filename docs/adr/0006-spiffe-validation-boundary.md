# ADR 0006: SPIFFE validation boundary

- **Status:** accepted
- **Date:** 2026-07-31
- **Packages:** `authweave-core`, `authweave-workload[spiffe]`

## Context

Machine mesh and headless workloads need SPIFFE X.509-SVID identity
without registering short-lived certificates by thumbprint. Two deployment
shapes exist: mesh-terminated TLS and in-process path validation. Mixing them
(proxy already verified + incomplete re-check) creates false confidence.

## Decision

1. **Exactly one validation boundary per deployment:**
   - **A. Trusted mesh termination** — Envoy/SPIRE gateway validates the chain
     against the SPIFFE bundle and projects `SpiffePeerEvidence` through an
     allowlisted local boundary factory. Clients cannot set or override that
     projection.
   - **B. Headless Python validation** — an adapter supplies bounded
     leaf+intermediates to `SpiffeX509SvidValidator` against a versioned bundle
     snapshot, then projects the same `SpiffePeerEvidence`. Raw certificate
     bytes never enter `RequestView`.
2. Identity after success is **only** the SPIFFE ID (URI SAN). No fingerprint
   registry for SVIDs.
3. `SPIFFEProvider` authenticates from projected peer evidence + explicit
   principal resolver (application/environment). Path segments grant no
   authority by themselves.
4. Bundle snapshots are versioned, atomically replaceable, and fail closed after
   configured staleness. Empty/missing bundles make the trust domain untrusted.
5. Workload API streaming goes through a maintained SPIFFE
   client library — not a bespoke gRPC protocol — and must still feed the same
   snapshot/validator seams.

## Consequences

- `authweave-core` gains `SpiffePeerEvidence` / `RequestView.spiffe_peer`.
- `authweave-workload[spiffe]` owns ID parsing, static bundles, X.509-SVID
  validator, and `SPIFFEProvider`.
- Both validation modes feed the same evidence contract; the SPIRE reference
  exercises Workload API delivery, bundle rotation, and outage handling.
- Federation trust-domain allowlists remain deployment-owned policy.

## Alternatives considered

- **Reuse `DirectMTLSProvider` thumbprint store:** rejected — conflicts with
  short-lived SVID rotation and SPIFFE identity model.
- **Always re-validate after mesh termination:** rejected — incomplete dual
  validation is worse than a single explicit boundary.

## Evidence

- SPIFFE X.509-SVID, Workload API, and trust-domain specifications.
