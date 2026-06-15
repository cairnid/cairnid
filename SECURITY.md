# Security Policy

Cairn Identity is not yet a public beta or OpenID Certified provider. Treat this repository as an actively developed security project until the release gates in `docs/release-gates.md` are closed. The current formal threat model is maintained in `docs/threat-model.md`.

## Supported Versions

There are no supported production releases yet. Security fixes should target `main` until versioned releases exist.

## Scope

In scope for private security reporting:

- Authentication, authorization, OIDC/OAuth, session, CSRF, MFA, token, signing-key, audit, database, deployment, and admin UI vulnerabilities.
- Dependency vulnerabilities that affect the locked dependency graph.
- Documentation or configuration issues that would cause a reasonable production operator to expose secrets, weaken TLS, lose signing material, or bypass required controls.

Out of scope:

- Denial-of-service reports that require unrealistic local access or unbounded resource assumptions.
- Social engineering, phishing, or physical attacks against maintainers or operators.
- Scanner-only reports without a working impact explanation.
- Issues in unsupported future features that are explicitly tracked as not implemented.

## Reporting A Vulnerability

Do not create a public GitHub issue for a suspected vulnerability.

Send a private report to the repository owner or through GitHub private vulnerability reporting when enabled. Include:

- Affected component.
- Reproduction steps.
- Expected and actual behavior.
- Impact assessment.
- Suggested fix, if known.
- Whether secrets, tokens, signing keys, password material, MFA state, or audit data may be exposed.

## Triage Targets

Until public releases exist, these are best-effort targets rather than a contractual SLA:

| Severity | Examples | Initial response target | Fix target |
| --- | --- | --- | --- |
| Critical | Remote auth bypass, signing-key disclosure, token minting, cross-organization admin access | 2 business days | 7 days |
| High | Token replay, session theft path, privilege escalation, secret logging | 3 business days | 14 days |
| Medium | CSRF bypass on limited action, missing audit on sensitive action, rate-limit bypass | 5 business days | 30 days |
| Low | Hardening gap with limited exploitability, documentation ambiguity | 10 business days | Next planned release |

## Handling And Disclosure

Validated vulnerabilities should receive:

- A private fix branch.
- Regression tests where practical.
- A security advisory or release note when a public release exists.
- Release-gate updates if the issue changes the public release criteria.
- Threat model updates if the issue changes an asset, trust boundary, control, invariant, or residual risk.

Do not disclose a validated vulnerability publicly until a fix or mitigation is available, unless maintainers are unresponsive after a reasonable coordinated-disclosure period.
