# AuthWeave optional-profile readiness

Public status for machine-authentication and message-integrity profiles in the AuthWeave 8
workspace. CI evidence establishes library readiness only, not certification of a deployment.

## Current readiness

| Profile | Current level | Remaining gate |
| --- | --- | --- |
| Standard Webhooks Ed25519 | Integration-ready | Independent review and production KMS drill |
| DPoP-bound JWT resource server | Integration-ready | Independent RFC 9449 interoperability and security review |
| Payment HTTP Message Signatures | Integration-ready | Independent RFC 9421/9530 review and production KMS drill |
| SPIFFE X.509-SVID | Integration-ready | Rotation/outage matrix, independent interoperability, production topology approval |
| Sender-constrained RFC 7662/9701 introspection | Integration-ready | Independent AS interoperability and security review |
| FAPI 2.0 Message Signing client | Integration-ready | Official conformance evidence and independent security review |
| Typed payment `authorization_details` | Integration-ready | Independent issuer interoperability and security review |
| RFC 8693 token exchange | Integration-ready | Independent STS interoperability and security review |

Unit tests and coverage establish library readiness only. Production readiness additionally needs
external review, deployment-owned keys and trust anchors, capacity/SLO evidence, incident drills,
and deployment approval.

## Verification entry points

- Base machine reference: `sh docker/reference/verify.sh`
- Observability: `sh docker/reference/observability/verify.sh`
- DPoP: `sh docker/reference/dpop/verify.sh`
- Sender-constrained introspection: `sh docker/reference/introspection/verify.sh`
- Sender-constrained token exchange: `sh docker/reference/token-exchange/verify.sh`
- FAPI Message Signing + typed payment authority: `sh docker/reference/fapi/verify.sh`
- HTTP signatures: `sh docker/reference/http-signatures/verify.sh`
- Standard Webhooks: `sh docker/reference/webhooks/verify.sh`
- SPIRE Workload API: `sh docker/reference/spiffe/verify.sh`

Architecture decisions are recorded under `docs/adr/`. AuthWeave remains a verification library;
it does not become an Authorization Server, STS, business authorization engine, audit store, or
telemetry backend.
