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
and credit the reporter unless anonymity is requested.

### Response targets

These are public response targets rather than a contractual service-level agreement:

- acknowledge a complete report within 3 business days;
- provide an initial severity assessment and next steps within 7 business days;
- target a fix or documented mitigation within 7 days for critical issues, 30 days for high,
  90 days for moderate, and the next planned release for low-severity issues;
- update the reporter at least weekly for critical/high issues and every two weeks otherwise.

Severity considers exploitability, authentication or authorization impact, affected trust
boundaries, confidentiality/integrity/availability impact, and the documented deployment model;
CVSS is supporting evidence, not the only input. Coordinated ecosystem fixes may require a longer
embargo, which will be agreed with the reporter rather than silently extending the timeline.

### Disclosure and safe harbor

Please allow time for a coordinated fix before public disclosure. When appropriate, the project
will publish a GitHub security advisory, request a CVE, identify affected and fixed versions, and
credit the reporter unless anonymity is requested.

Good-faith research that follows this policy is authorized. Test only systems and data you own or
have permission to use, avoid privacy violations and service disruption, and stop and report if
you encounter sensitive data. The project will not pursue legal action for accidental,
good-faith violations of this policy that are promptly reported and corrected.

## Security model

The supported trust profiles, explicit non-goals, and deployment responsibilities are documented
in the [security posture](docs/security.md). Reports that depend on a documented non-goal are still
welcome when the boundary is unclear or can fail open.
