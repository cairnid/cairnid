# Governance

Cairn Identity is a small open-source security project. Governance is intentionally lightweight until the project has a larger maintainer base.

## Maintainer Role

Maintainers are responsible for:

- Reviewing changes for correctness, security impact, and release-readiness claims.
- Keeping public documentation aligned with implemented behavior and current release gates.
- Triaging issues, pull requests, and private vulnerability reports.
- Protecting release tags, draft releases, and security-sensitive operational guidance.

Maintainer membership is listed in [MAINTAINERS.md](MAINTAINERS.md).

CODEOWNERS currently routes all paths to `@ibuuvai`. Move ownership to a `cairnid` organization team when the organization has a real maintainer team with the intended repository permissions.

## Review Expectations

Changes that affect authentication, authorization, OIDC/OAuth behavior, sessions, MFA, signing keys, organization isolation, audit records, deployment security, release artifacts, dependency policy, or evidence tooling require maintainer review before merge.

Security-sensitive changes should include tests or documented verification. Documentation must be updated when a change alters an operator-facing command, release gate, trust boundary, supported deployment path, or residual risk.

## Decision Process

Routine changes can be accepted by maintainer review once CI and relevant local checks pass.

For release gates, security posture, supported deployment paths, or public release artifacts, maintainers should prefer an explicit issue or pull-request discussion that records:

- The decision being made.
- Evidence used to make the decision.
- Follow-up work or blockers.

If maintainers disagree, defer the change until the risk, user impact, and release impact are written down and a maintainer decision is recorded in the pull request or issue.

## Security Handling

Suspected vulnerabilities must follow [SECURITY.md](SECURITY.md). Public issues and pull requests should not include exploit details, secrets, tokens, signing keys, or sensitive release evidence.

Maintainers should use private branches or GitHub security advisories for embargoed fixes where practical, then update tests, release notes, release gates, and the threat model as needed.

## Releases

Release candidates must not be recommended for production use until the gates in [docs/release-gates.md](docs/release-gates.md) are complete. Maintainers publish draft GitHub Releases only after checking the generated assets, checksums, manifest, SBOMs, attestations, changelog, and unresolved blockers.
