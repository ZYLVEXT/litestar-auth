# Security policy

## Supported releases

Security fixes target the latest published release line. Code on `main` and entries under
`Unreleased` are pre-release until their packages are published. Older release lines may receive
critical fixes at the maintainer's discretion but are not guaranteed support.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ZYLVEXT/litestar-auth/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include:

- the affected package and version;
- the authentication profile and deployment boundary involved;
- a minimal reproducer or request sequence;
- the expected and observed security outcome;
- any known exploit conditions or mitigations.

Do not include production credentials, private keys, personal data, or third-party secrets. Use
synthetic material in reproductions.

The maintainer will acknowledge a complete report, validate impact, coordinate a fix and release,
and credit the reporter unless anonymity is requested. Timelines depend on severity and the need
to coordinate downstream users.

## Security model

The supported trust profiles, explicit non-goals, and deployment responsibilities are documented
in the [security posture](docs/security.md). Reports that depend on a documented non-goal are still
welcome when the boundary is unclear or can fail open.
