# DPoP interoperability reference (external test AS + Redis + live HTTP)

Smoke stack for `authweave-workload[dpop]`:

- language-neutral RFC 9449 / ADR 0003 vectors verified independently by
  AuthWeave/Python and dependency-free Node.js code
- a separately deployed test Authorization Server that validates a token-endpoint
  DPoP proof, publishes a network JWKS, and issues `token_type=DPoP` JWTs with `cnf.jkt`
- 32-way Redis proof-replay and nonce-consumption races, connection outage, and
  `noeviction` capacity failure
- four-worker live HTTP resource-server upstream using an application-owned
  `EXTERNAL_TARGET` (never client `Host` / `Forwarded`)
- valid proof acceptance plus fail-closed replay, `htu`, `htm`, `ath`, nonce, and
  `cnf.jkt` mismatch checks

The direct mTLS live harness is available at `sh docker/reference/verify.sh`.

```bash
sh docker/reference/dpop/verify.sh
```

See also `docs/merchant/dpop.md`.

The Authorization Server is deliberately named and scoped as a test fixture. It
is not a supported AuthWeave package or an OAuth Authorization Server product.
